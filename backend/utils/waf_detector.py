"""
WAF Detector — Fingerprints WAF/IDS from response headers and behavior
"""

import requests


class WAFDetector:
    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
        "AWS WAF": ["awselb", "x-amzn-requestid", "x-amz-cf-id"],
        "Akamai": ["akamai", "x-akamai-transformed"],
        "Imperva / Incapsula": ["incap_ses", "visid_incap", "x-iinfo"],
        "F5 BIG-IP ASM": ["bigipserver", "x-cnection", "f5-"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
    }

    def __init__(self, target):
        self.target = target
        self.session = requests.Session()
        self.session.timeout = 8

    def detect(self):
        try:
            # Normal request
            resp = self.session.get(self.target)
            headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
            cookies_lower = {k.lower(): v.lower() for k, v in resp.cookies.items()}

            for waf_name, sigs in self.WAF_SIGNATURES.items():
                for sig in sigs:
                    if any(sig in h for h in headers_lower) or \
                       any(sig in c for c in cookies_lower) or \
                       sig in resp.text.lower():
                        return waf_name

            # Send a suspicious payload to trigger WAF
            probe = self.session.get(self.target, params={"q": "' OR 1=1--"})
            if probe.status_code in (403, 406, 429, 503):
                return "Unknown WAF (blocked probe)"

        except Exception:
            pass
        return None
