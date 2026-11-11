"""
Fake Website & Demo E-Commerce Threat Detector.

Identifies traffic to fake online shopping websites, demo stores, and web testing scenario sites:
  1. SauceDemo (saucedemo.com) - Fake online shopping website (Swag Labs)
  2. Automation Exercise (automationexercise.com) - Demo e-commerce store
  3. The Internet (the-internet.herokuapp.com) - Web security and test scenarios
  4. OpenCart Demo (demo.opencart.com / opencart.com) - Demo shopping platform
  5. Expand Testing (practice.expandtesting.com / expandtesting.com) - Web testing scenarios
  + Other notable demo shops (Demoblaze, OWASP Juice Shop, FakeStoreAPI)
"""

import socket
import threading
import time
import urllib.parse
from typing import Dict, Any, Optional, List


KNOWN_FAKE_SITES: List[Dict[str, Any]] = [
    {
        "id": "saucedemo",
        "name": "SauceDemo",
        "domains": [
            "saucedemo.com",
            "www.saucedemo.com",
            "sauce-demo.myshopify.com",
            "saucedemo.myshopify.com"
        ],
        "category": "Fake Online Shopping Website",
        "description": "Simulated e-commerce store (Swag Labs / Demo Store) with mock shopping cart, checkout, and test credentials.",
        "risk_level": "HIGH",
        "icon": "shopping-bag",
        "warning": "Fake online shopping website detected! You are visiting SauceDemo. Do not enter real credit cards, passwords, or personal data.",
        "default_ips": [
            "185.199.108.153", "185.199.109.153", "185.199.110.153", "185.199.111.153",
            "23.227.38.74", "23.227.38.65"
        ]
    },
    {
        "id": "automation_exercise",
        "name": "Automation Exercise",
        "domains": ["automationexercise.com", "www.automationexercise.com"],
        "category": "Demo E-Commerce Website",
        "description": "Demo shopping platform with simulated products, cart, and mock payment workflows.",
        "risk_level": "HIGH",
        "icon": "shopping-cart",
        "warning": "Demo e-commerce website detected! Simulated transactions and fake checkout forms.",
        "default_ips": ["104.21.82.30", "172.67.151.201"]
    },
    {
        "id": "the_internet",
        "name": "The Internet",
        "domains": ["the-internet.herokuapp.com"],
        "category": "Web Testing Scenarios Lab",
        "description": "Laboratory of web testing scenarios (authentication bypass, broken forms, file upload/download tests).",
        "risk_level": "HIGH",
        "icon": "globe",
        "warning": "Web test scenarios website detected! Contains vulnerable test scenarios and exploit sandboxes.",
        "default_ips": ["35.71.177.79", "166.117.94.78", "13.248.162.64", "99.83.176.110"]
    },
    {
        "id": "opencart_demo",
        "name": "OpenCart Demo",
        "domains": ["demo.opencart.com", "opencart.com"],
        "category": "Demo Shopping Website",
        "description": "OpenCart demonstration storefront running mock e-commerce shopping and test checkout workflows.",
        "risk_level": "HIGH",
        "icon": "store",
        "warning": "Demo shopping storefront detected! Simulated store running test catalog and mock payments.",
        "default_ips": ["172.66.139.120", "172.66.136.12"]
    },
    {
        "id": "expand_testing",
        "name": "Expand Testing",
        "domains": ["practice.expandtesting.com", "expandtesting.com"],
        "category": "Demo Websites & Web Testing Scenarios",
        "description": "Comprehensive suite of practice e-commerce, test login forms, and web testing scenarios.",
        "risk_level": "HIGH",
        "icon": "shield-alert",
        "warning": "Demo testing website collection detected! Simulated web forms and test authentication.",
        "default_ips": ["66.241.125.119"]
    },
    {
        "id": "demoblaze",
        "name": "Demoblaze",
        "domains": ["demoblaze.com", "www.demoblaze.com"],
        "category": "Demo Online Store",
        "description": "Mock electronics shopping portal with fake cart and simulated payments.",
        "risk_level": "HIGH",
        "icon": "shopping-cart",
        "warning": "Fake online shopping site detected! Simulated consumer electronics store.",
        "default_ips": []
    },
    {
        "id": "juice_shop",
        "name": "OWASP Juice Shop",
        "domains": ["juice-shop.herokuapp.com", "owasp-juice-shop.herokuapp.com"],
        "category": "Insecure Demo Store",
        "description": "Intentionally vulnerable web application simulating an e-commerce shop.",
        "risk_level": "HIGH",
        "icon": "alert-triangle",
        "warning": "Intentionally vulnerable demo shopping website detected!",
        "default_ips": []
    },
    {
        "id": "fakestoreapi",
        "name": "Fake Store API",
        "domains": ["fakestoreapi.com"],
        "category": "Mock E-Commerce API",
        "description": "Mock store data provider for testing e-commerce client applications.",
        "risk_level": "HIGH",
        "icon": "database",
        "warning": "Mock e-commerce API server detected!",
        "default_ips": []
    }
]


class FakeWebsiteDetector:
    """
    Real-time detector for fake online shopping websites, demo stores, and test labs.
    Maintains dynamic IP-to-Domain caches and performs forward & reverse DNS lookups.
    """

    def __init__(self):
        self.sites = KNOWN_FAKE_SITES
        self.ip_to_site: Dict[str, Dict[str, Any]] = {}
        self.domain_to_site: Dict[str, Dict[str, Any]] = {}
        self.reverse_dns_cache: Dict[str, Optional[str]] = {}
        self._lock = threading.Lock()

        # Seed with known default IPs and domains
        for site in self.sites:
            for domain in site["domains"]:
                self.domain_to_site[domain.lower()] = site
            for ip in site.get("default_ips", []):
                self.ip_to_site[ip] = site

        # Start background resolver to keep IP lists current
        self._resolve_thread = threading.Thread(target=self._resolve_domains_loop, daemon=True)
        self._resolve_thread.start()

    def _resolve_all(self):
        """Resolve all known site domains to current IP addresses."""
        for site in self.sites:
            for domain in site["domains"]:
                try:
                    ips = socket.gethostbyname_ex(domain)[2]
                    with self._lock:
                        for ip in ips:
                            # Prefer earlier / primary sites for shared CDN/GitHub Pages IPs
                            if ip not in self.ip_to_site:
                                self.ip_to_site[ip] = site
                except Exception:
                    pass

    def _resolve_domains_loop(self):
        """Periodically refresh IP mappings in background (every 10 minutes)."""
        self._resolve_all()
        while True:
            time.sleep(600)
            self._resolve_all()

    def get_reverse_dns(self, ip: str) -> Optional[str]:
        """Perform cached reverse DNS lookup for an IP."""
        if not ip or ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("172.16."):
            return None
        with self._lock:
            if ip in self.reverse_dns_cache:
                return self.reverse_dns_cache[ip]

        try:
            host = socket.gethostbyaddr(ip)[0].lower()
        except Exception:
            host = None

        with self._lock:
            self.reverse_dns_cache[ip] = host
        return host

    def check_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Check if a domain or hostname matches any known fake/demo site."""
        if not domain:
            return None
        d = domain.lower().strip()
        if d in self.domain_to_site:
            return self.domain_to_site[d]

        # Check domain suffix
        for registered_domain, site in self.domain_to_site.items():
            if d == registered_domain or d.endswith("." + registered_domain):
                return site

        # Check intelligent keyword patterns
        clean = d.replace("-", "").replace("_", "")
        if "saucedemo" in clean or "swaglabs" in clean or "saucedemo" in d or "sauce-demo" in d:
            return next(s for s in self.sites if s["id"] == "saucedemo")
        if "automationexercise" in clean or "automation-exercise" in d:
            return next(s for s in self.sites if s["id"] == "automation_exercise")
        if "theinternet" in clean or "internet.herokuapp" in d or "the-internet" in d:
            return next(s for s in self.sites if s["id"] == "the_internet")
        if "opencart" in clean:
            return next(s for s in self.sites if s["id"] == "opencart_demo")
        if "expandtesting" in clean:
            return next(s for s in self.sites if s["id"] == "expand_testing")
        if "demoblaze" in clean:
            return next(s for s in self.sites if s["id"] == "demoblaze")
        if "juiceshop" in clean or "juice-shop" in d:
            return next(s for s in self.sites if s["id"] == "juice_shop")
        if "fakestore" in clean or "fakeshop" in clean or "mockstore" in clean:
            return next(s for s in self.sites if s["id"] == "fakestoreapi")

        return None

    def check_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Check if a complete URL matches any known fake/demo site."""
        if not url:
            return None
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or url).lower().strip()
            site = self.check_domain(host)
            if not site:
                clean_url = url.lower().replace("-", "").replace("_", "")
                for s in self.sites:
                    site_id = s["id"].replace("_", "")
                    if site_id in clean_url:
                        site = s
                        break
            if site:
                return {
                    "is_fake": True,
                    "site_id": site["id"],
                    "site_name": site["name"],
                    "name": site["name"],
                    "category": site["category"],
                    "domain": host or site["domains"][0],
                    "description": site["description"],
                    "risk_level": site["risk_level"],
                    "warning": site["warning"],
                    "icon": site.get("icon", "shopping-bag"),
                    "matched_url": url
                }
        except Exception:
            pass
        return None

    def check_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Check if an IP matches any known fake/demo site."""
        if not ip:
            return None
        with self._lock:
            if ip in self.ip_to_site:
                return self.ip_to_site[ip]

        # Try reverse DNS lookup
        host = self.get_reverse_dns(ip)
        if host:
            matched = self.check_domain(host)
            if matched:
                with self._lock:
                    self.ip_to_site[ip] = matched
                return matched

        return None

    def register_ip_for_domain(self, ip: str, domain: str):
        """Map an IP to a domain discovered dynamically via DNS/SNI."""
        if not ip or not domain:
            return
        matched = self.check_domain(domain)
        if matched:
            with self._lock:
                self.ip_to_site[ip] = matched

    def inspect_flow(self, flow: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Inspect a flow dictionary and return fake website alert metadata if matched.
        """
        dst_ip = flow.get("destination_ip")
        src_ip = flow.get("source_ip")
        domain = flow.get("domain") or flow.get("host")
        url = flow.get("url")

        # 0. Full URL check if available
        matched_site = None
        matched_domain = domain

        if url:
            matched_site = self.check_url(url)
            if matched_site:
                matched_domain = domain or urllib.parse.urlparse(url).hostname

        # 1. Direct domain check (from SNI / DNS / HTTP Host)
        if not matched_site and domain:
            matched_site = self.check_domain(domain)

        # 2. Destination IP check
        if not matched_site and dst_ip:
            matched_site = self.check_ip(dst_ip)
            if matched_site:
                matched_domain = matched_site["domains"][0]

        # 3. Source IP check (for inbound responses from the fake site)
        if not matched_site and src_ip:
            matched_site = self.check_ip(src_ip)
            if matched_site:
                matched_domain = matched_site["domains"][0]

        if not matched_site:
            return None

        return {
            "is_fake": True,
            "site_id": matched_site["id"],
            "site_name": matched_site["name"],
            "category": matched_site["category"],
            "domain": matched_domain or matched_site["domains"][0],
            "description": matched_site["description"],
            "risk_level": matched_site["risk_level"],
            "warning": matched_site["warning"],
            "icon": matched_site.get("icon", "shopping-bag"),
            "matched_ip": dst_ip or src_ip or ""
        }


# Singleton instance
fake_website_detector = FakeWebsiteDetector()
