"""
IDOR Scanner — Broken Object Level Authorization (BOLA/IDOR)
"""
import requests
import time


class IDORScanner:
    def __init__(self, target, endpoints, waf_detected=None):
        self.target = target
        self.endpoints = endpoints
        self.waf_detected = waf_detected
        self.request_count = 0
        self.bypass_rate = 0
        self.session = requests.Session()
        self.session.timeout = 8

    def run(self):
        findings = []
        # Look for endpoints with numeric IDs
        id_endpoints = [e for e in self.endpoints
                       if any(seg.isdigit() for seg in e.get("url", "").split("/"))]

        for endpoint in id_endpoints[:5]:
            url = endpoint.get("url", "")
            # Try to access adjacent IDs
            base_url = url.rstrip("/")
            parts = base_url.split("/")

            for i, part in enumerate(parts):
                if part.isdigit():
                    for test_id in [str(int(part) - 1), str(int(part) + 1), "1", "0"]:
                        parts[i] = test_id
                        test_url = "/".join(parts)
                        try:
                            resp = self.session.get(test_url)
                            self.request_count += 1
                            if resp.status_code == 200 and len(resp.text) > 50:
                                findings.append({
                                    "type": "IDOR — Unauthorized Object Access",
                                    "severity": "high",
                                    "endpoint": test_url,
                                    "parameter": "path parameter (id)",
                                    "payload": f"Modified ID: {test_id}",
                                    "cvss": "8.1",
                                    "vector": "BOLA",
                                    "bypass_used": False,
                                    "bypass_technique": None,
                                    "remediation": (
                                        "Implement object-level authorization checks on every request. "
                                        "Use indirect object references. Verify ownership before serving data."
                                    ),
                                })
                                break
                        except Exception:
                            pass
                        time.sleep(0.05)

        return findings


"""
Header Scanner — Security misconfiguration via HTTP response headers
"""


class HeaderScanner:
    REQUIRED_HEADERS = {
        "Strict-Transport-Security": {
            "severity": "medium",
            "cvss": "5.3",
            "remediation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        },
        "X-Frame-Options": {
            "severity": "medium",
            "cvss": "4.3",
            "remediation": "Add: X-Frame-Options: DENY to prevent clickjacking.",
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "cvss": "5.1",
            "remediation": "Implement a strict Content-Security-Policy header.",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "cvss": "3.1",
            "remediation": "Add: X-Content-Type-Options: nosniff",
        },
        "Referrer-Policy": {
            "severity": "low",
            "cvss": "2.6",
            "remediation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        },
        "Permissions-Policy": {
            "severity": "low",
            "cvss": "2.1",
            "remediation": "Add Permissions-Policy to restrict browser features.",
        },
    }

    def __init__(self, target, endpoints, waf_detected=None):
        self.target = target
        self.endpoints = endpoints
        self.waf_detected = waf_detected
        self.request_count = 0
        self.bypass_rate = 0
        self.session = requests.Session()
        self.session.timeout = 8

    def run(self):
        findings = []
        try:
            resp = self.session.get(self.target)
            self.request_count += 1
            response_headers = {k.lower(): v for k, v in resp.headers.items()}

            for header, meta in self.REQUIRED_HEADERS.items():
                if header.lower() not in response_headers:
                    findings.append({
                        "type": f"Missing Security Header: {header}",
                        "severity": meta["severity"],
                        "endpoint": self.target,
                        "parameter": "HTTP Response Header",
                        "payload": "N/A",
                        "cvss": meta["cvss"],
                        "vector": "Misconfiguration",
                        "bypass_used": False,
                        "bypass_technique": None,
                        "remediation": meta["remediation"],
                    })

            # Check for server version disclosure
            server = resp.headers.get("Server", "")
            if any(c.isdigit() for c in server):
                findings.append({
                    "type": "Server Version Disclosure",
                    "severity": "low",
                    "endpoint": self.target,
                    "parameter": "Server header",
                    "payload": server,
                    "cvss": "2.0",
                    "vector": "Information Disclosure",
                    "bypass_used": False,
                    "bypass_technique": None,
                    "remediation": "Remove or genericize the Server response header.",
                })

        except Exception:
            pass

        return findings
