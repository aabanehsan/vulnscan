"""
Crawler — Discovers endpoints and parameters from a target
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time


class Crawler:
    def __init__(self, target, max_depth=2, max_pages=30):
        self.target = target.rstrip("/")
        self.base_domain = urlparse(target).netloc
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.visited = set()
        self.endpoints = []
        self.request_count = 0
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (VulnScan Security Tester)"
        })
        self.session.timeout = 8

    def crawl(self):
        self._crawl_url(self.target, depth=0)
        return self.endpoints

    def _crawl_url(self, url, depth):
        if depth > self.max_depth:
            return
        if len(self.visited) >= self.max_pages:
            return
        if url in self.visited:
            return

        self.visited.add(url)

        try:
            resp = self.session.get(url, allow_redirects=True)
            self.request_count += 1

            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())

            self.endpoints.append({
                "url": url.split("?")[0],
                "params": params,
                "method": "GET",
                "status": resp.status_code,
            })

            soup = BeautifulSoup(resp.text, "html.parser")

            # Collect form endpoints
            for form in soup.find_all("form"):
                action = form.get("action", "")
                method = form.get("method", "GET").upper()
                full_action = urljoin(url, action)
                if self._is_same_domain(full_action):
                    form_params = [i.get("name") for i in form.find_all("input") if i.get("name")]
                    self.endpoints.append({
                        "url": full_action,
                        "params": form_params,
                        "method": method,
                        "status": None,
                    })

            # Follow links
            for tag in soup.find_all("a", href=True):
                next_url = urljoin(url, tag["href"])
                if self._is_same_domain(next_url) and next_url not in self.visited:
                    time.sleep(0.1)
                    self._crawl_url(next_url, depth + 1)

        except Exception:
            pass

    def _is_same_domain(self, url):
        return urlparse(url).netloc == self.base_domain
