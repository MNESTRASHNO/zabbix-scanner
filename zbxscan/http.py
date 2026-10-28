"""HTTP probing client with sane defaults for security scanning."""
from __future__ import annotations

import requests
import urllib3
import warnings

warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

DEFAULT_UA = "zbxscan/0.1.0"


class HttpProbe:
    """Thin requests wrapper: timeouts, retries, no TLS verification, no redirects by default."""

    def __init__(self, timeout: float = 8.0, retries: int = 1, user_agent: str = DEFAULT_UA):
        self.timeout = timeout
        self.user_agent = user_agent
        self.session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(max_retries=retries)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.verify = False

    def request(self, method: str, url: str, allow_redirects: bool = False,
                delay: float = 0.0, **kw) -> requests.Response | None:
        import time
        if delay:
            time.sleep(delay)
        kw.setdefault("headers", {})["User-Agent"] = self.user_agent
        kw.setdefault("timeout", self.timeout)
        try:
            return self.session.request(method, url, allow_redirects=allow_redirects, **kw)
        except requests.RequestException:
            return None

    def get(self, url: str, **kw) -> requests.Response | None:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response | None:
        return self.request("POST", url, **kw)

    def close(self):
        self.session.close()
