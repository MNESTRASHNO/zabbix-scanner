"""Zabbix frontend fingerprinting.

Layers, in order of reliability:
  1. POST apiinfo.version (unauthenticated JSON-RPC) -> exact version.
  2. Login page HTML: <title>Zabbix <ver></title> / footer / generator meta.
  3. Branch guess from login-page HTML when apiinfo is unavailable: the Help
     link (zabbix.com/documentation/<M.m>/) is branch-exact; secondary markers
     (data-field-type attrs, html[theme], CSS custom props, csrf-token meta,
     autocomplete=new-password, /vendor/composer/installed.json) narrow the
     branch further (see _guess_branch_from_html). Sets version_approx=True
     and version='<branch>.0' — patch level stays unknown.
  4. Set-Cookie shape (zbx_session base64 JSON vs zbx_sessionid 32-hex) + headers.
Plus stack (component) signals: Server header, X-Powered-By, probe of known
endpoints (jsrpc.php, index_sso.php) — used for component CVE conditions.

Universality rules (brand-independent — no customer/instance-specific words):
  - A frontend is recognized by vendor-level markers only: "zabbix" anywhere in
    the page (author meta "Zabbix SIA" included) or a zbx_session cookie, so
    custom-branded instances (custom <title>, themes) still match.
  - The origin that actually serves the app wins: redirects (http->https,
    cross-host, /zabbix subpath) are followed and the FINAL URL is recorded
    (scheme/host/port/base). Every later probe reuses the resolved origin
    (see Fingerprint.origin / web_url / api_url).
  - If no scheme is given explicitly, both https and http are tried
    (port hints decide the order; explicit scheme pins it).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

from .http import HttpProbe
from .versioning import ZabbixVersion, parse_version

_TITLE_RE = re.compile(r"Zabbix\s+[vV]?(\d+\.\d+(?:\.\d+)?)")
_FOOTER_RE = re.compile(r"Zabbix\s+[vV]?(\d+\.\d+(?:\.\d+)?)")
_META_GEN_RE = re.compile(r'name=["\']generator["\']\s+content=["\']([^"\']+)', re.I)
_DOC_LINK_RE = re.compile(r"zabbix\.com/documentation/(\d+\.\d+)/")


def normalize_target(target: str) -> tuple[str, int, str | None]:
    """'host[:port]' or 'scheme://host[:port]' -> (host, port, scheme).

    scheme is None when not given explicitly; the caller then tries both
    https and http (order chosen from the port hint)."""
    scheme = None
    rest = target.strip()
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            scheme = None  # non-http(s) schemes are not probed; validated upstream
    if ":" in rest:
        host, _, port = rest.rpartition(":")
        if port.isdigit():
            return host.strip("/"), int(port), scheme
    return rest.strip("/"), (443 if scheme == "https" else 80), scheme


def base_url(host: str, port: int, scheme: str | None = None) -> str:
    """Origin URL; an explicit scheme wins, else the port-443 heuristic."""
    scheme = scheme or ("https" if port == 443 else "http")
    return f"{scheme}://{host}:{port}"


@dataclass
class Fingerprint:
    target: str
    host: str
    port: int
    scheme: str | None = None        # resolved scheme of the serving origin
    base: str | None = None          # resolved frontend base ('' or '/zabbix')
    version: str | None = None
    version_parsed: ZabbixVersion | None = None
    version_source: str | None = None   # 'api' | 'html' | 'html-branch-guess'
    version_approx: bool = False        # True when only the branch is known
    web: bool = False
    api: bool = False
    server_header: str | None = None
    x_powered_by: str | None = None
    cookies: list[str] = field(default_factory=list)
    sso_present: bool | None = None  # /index_sso.php exists (SAML condition)
    sso_enabled: bool | None = None  # SAML SSO actually enabled (index_sso.php does NOT bounce to login)
    agent_port_open: bool | None = None  # 10050/tcp reachable on host (agent2 modules)
    server_port_open: bool | None = None  # 10051/tcp reachable on host (trapper modules)
    jsrpc_present: bool | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def branch(self) -> str | None:
        return self.version_parsed.branch if self.version_parsed else None

    def origin(self) -> str:
        """scheme://host:port of the origin actually serving the frontend."""
        return base_url(self.host, self.port, self.scheme)

    def web_url(self, path: str = "") -> str:
        """Frontend URL: origin + base path + optional path."""
        return f"{self.origin()}{self.base or ''}{path}"

    def api_url(self) -> str:
        return self.web_url("/api_jsonrpc.php")


def _looks_like_zabbix(resp: requests.Response) -> bool:
    """Vendor-level markers only — survives full customer re-branding
    (custom <title>/themes/logos). Never matches on customer-specific words."""
    html = (resp.text or "").lower()
    if "zabbix" in html:
        return True
    headers = resp.headers or {}
    return "zbx_session" in (headers.get("Set-Cookie") or "")


def _cookie_names(set_cookie: str) -> list[str]:
    """Cookie names from a raw Set-Cookie header, without attribute noise
    ('secure'/'HttpOnly'/Expires fragments)."""
    names: list[str] = []
    for part in (set_cookie or "").split(","):
        kv = part.split(";")[0].strip()
        if "=" not in kv:
            continue
        name = kv.split("=", 1)[0].strip()
        if name and " " not in name and name.lower() not in ("expires",) \
                and name not in names:
            names.append(name)
    return names


def _adopt_final_url(fp: Fingerprint, final_url: str | None) -> None:
    """Record the origin that actually served the response (the redirect
    target, if any): scheme, host, port and the frontend base path.

    The base is derived from the final DIRECTORY: '/zabbix/index.php' ->
    '/zabbix', '/zabbix.php' or '/' -> '' (a redirect to a top-level .php
    entrypoint must not become a base)."""
    if not final_url:
        return
    try:
        u = urlparse(final_url)
    except ValueError:
        return
    if u.scheme:
        fp.scheme = u.scheme
    if u.hostname:
        fp.host = u.hostname
    if u.port:
        fp.port = u.port
    elif u.scheme in ("https", "http"):
        # no explicit port in the final URL -> the origin IS the scheme default
        fp.port = 443 if u.scheme == "https" else 80
    path = u.path or "/"
    last = path.rsplit("/", 1)[-1]
    if "." in last:  # a file (e.g. index.php / zabbix.php) -> its directory
        path = path.rsplit("/", 1)[0]
    path = path.rstrip("/")
    fp.base = path


def _api_urls(host: str, port: int, base: str, scheme: str | None) -> list[str]:
    """Candidate api_jsonrpc.php URLs: explicit scheme first, else both."""
    schemes = (scheme,) if scheme else ("https", "http")
    seen: set[str] = set()
    urls: list[str] = []
    for s in schemes:
        u = f"{s}://{host}:{port}{base or ''}/api_jsonrpc.php"
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


def _probe_api_version(probe: HttpProbe, urls: list[str]) -> str | None:
    """apiinfo.version is public (no auth) in every version 2.x - 7.x.

    POST follows redirects: a 301 http->https (or cross-host) must not kill
    the probe — requests re-sends the POST body on 301/302."""
    for url in urls:
        for params in ({}, []):
            body = {"jsonrpc": "2.0", "method": "apiinfo.version", "params": params, "id": 1}
            try:
                resp = probe.post(url, json=body, allow_redirects=True)
            except Exception:
                continue
            if resp is None:
                continue
            if resp.status_code == 200:
                try:
                    data = resp.json()
                except ValueError:
                    data = None
                if data and isinstance(data.get("result"), str):
                    return data["result"]
    return None


def _extract_version(html: str) -> str | None:
    for m in (_META_GEN_RE.search(html), _TITLE_RE.search(html), _FOOTER_RE.search(html)):
        if m:
            return m.group(1)
    return None


def _guess_branch_from_html(html: str, probe: HttpProbe | None = None,
                            composer_url: str | None = None) -> tuple[str | None, str | None]:
    """Approximate the Zabbix branch from login-page HTML when apiinfo is
    unavailable (disabled/blocked/WAF'ed).

    Signal matrix, derived from real stacks 4.0.46/5.0.44/6.0.42/7.0.19/
    7.2.11/7.4.3 (docker zabbix-web-nginx-pgsql) and confirmed on 3 prod
    frontends with custom titles:

      | signal                                | 4.0 | 5.0 | 6.0 | 7.0 | 7.2 | 7.4 |
      |---------------------------------------|-----|-----|-----|-----|-----|-----|
      | Help link zabbix.com/documentation/X.Y|  +  |  +  |  +  |  +  |  +  |  +  |
      | data-field-type="..." form attrs      |  -  |  -  |  -  |  -  |  -  |  +  |
      | html[theme=...] color-scheme attrs    |  -  |  -  |  -  |  +  |  +  |  +  |
      | inline CSS custom props --severity-*  |  -  |  -  |  +  |  +  |  +  |  +  |
      | <meta name=csrf-token> (empty value)  |  +  |  +  | val |  -  |  -  |  -  |
      | autocomplete="new-password"           |  +  |  +  |  -  |  -  |  -  |  -  |
      | GET /vendor/composer/installed.json   | 200 | 404 | 404 | 404 | 404 | 404 |

    Returns (branch | None, evidence | None). Branch None means the signals
    only narrow the range — the caller must NOT pretend an exact branch."""
    m = _DOC_LINK_RE.search(html or "")
    if m:
        return m.group(1), "Help link zabbix.com/documentation/%s/ (branch-exact)" % m.group(1)
    if 'data-field-type=' in html:
        return "7.4", "data-field-type form attrs (7.4+)"
    if re.search(r'<html\b[^>]*\btheme="', html):
        return None, "html[theme] attrs present -> branch 7.0-7.2 (ambiguous, no exact guess)"
    if "--severity-color" in html:
        return "6.0", "inline CSS custom properties --severity-* (6.0+)"
    if 'name="csrf-token"' in html:
        if 'autocomplete="new-password"' in html:
            if probe is not None and composer_url:
                try:
                    r = probe.get(composer_url)
                    if r is not None and r.status_code == 200:
                        return "4.0", "csrf-token meta + new-password + composer/installed.json 200 (4.0)"
                except Exception:
                    pass
            return "5.0", "csrf-token meta + autocomplete=new-password (<=5.0)"
        return "6.0", "csrf-token meta without new-password (6.x)"
    return None, None


def tcp_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """One-shot TCP connect probe (agent 10050 / trapper 10051 reachability)."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def fingerprint(target: str, probe: HttpProbe | None = None, timeout: float = 8.0) -> Fingerprint:
    host, port, scheme = normalize_target(target)
    fp = Fingerprint(target, host, port, scheme=scheme)
    own_probe = probe is None
    p = probe or HttpProbe(timeout=timeout)
    page_html = ""
    try:
        schemes = (scheme,) if scheme else \
            (("https", "http") if port == 443 else ("http", "https"))
        # 1) locate the frontend; follow redirects, then adopt the FINAL origin
        #    (scheme/host/port/base) so every later probe hits the real app
        for s in schemes:
            for base in ("", "/zabbix"):
                root = p.get(f"{s}://{host}:{port}{base}", allow_redirects=True)
                if root is None:
                    continue
                headers = root.headers or {}
                if fp.server_header is None:
                    fp.server_header = headers.get("Server")
                if fp.x_powered_by is None:
                    fp.x_powered_by = headers.get("X-Powered-By")
                if root.status_code == 200 and _looks_like_zabbix(root):
                    fp.web = True
                    _adopt_final_url(fp, root.url)
                    fp.cookies = _cookie_names(headers.get("Set-Cookie", "") or "")
                    if fp.cookies:
                        fp.notes.append(f"cookies: {fp.cookies}")
                    fp.version = _extract_version(root.text or "")
                    if fp.version:
                        fp.version_source = "html"
                        fp.notes.append(f"version from login-page HTML: {fp.version}")
                    page_html = root.text or ""
                    via = f" via {s}://{host}:{port}{base}" \
                        if (fp.scheme, fp.host, fp.port, fp.base) != (s, host, port, base) else ""
                    fp.notes.append(f"frontend at `{fp.base or '/'}`, status {root.status_code}{via}")
                    break
            if fp.web:
                break
        # 2) exact version via API (authoritative; HTML rarely carries it on
        #    modern/rebranded frontends)
        if fp.web:
            v = _probe_api_version(p, _api_urls(fp.host, fp.port, fp.base or "", fp.scheme))
            if v:
                fp.api = True
                fp.version = v
                fp.version_source = "api"
                fp.notes.append(f"apiinfo.version -> {v}")
            elif not fp.version and page_html:
                # apiinfo unavailable (disabled/blocked) -> approximate the
                # branch from the login-page HTML; patch level stays unknown
                branch, evidence = _guess_branch_from_html(
                    page_html, probe=p,
                    composer_url=fp.web_url("/vendor/composer/installed.json"))
                if evidence:
                    fp.notes.append(f"branch guess: {evidence}")
                if branch:
                    fp.version = f"{branch}.0"
                    fp.version_approx = True
                    fp.version_source = "html-branch-guess"
                    fp.notes.append(
                        f"version approximated from HTML: branch {branch} "
                        "(apiinfo unavailable; patch level unknown)")
        else:
            # no page marker — apiinfo.version is itself the Zabbix marker;
            # probe both bases, both schemes
            for base in ("", "/zabbix"):
                v = _probe_api_version(p, _api_urls(host, port, base, scheme))
                if v:
                    fp.version = v
                    fp.version_source = "api"
                    fp.api = True
                    fp.web = True
                    fp.base = base or ""
                    fp.notes.append(f"apiinfo.version -> {v}")
                    break
        if fp.version:
            fp.version_parsed = parse_version(fp.version)
            if fp.version_parsed is None:
                fp.notes.append(f"version `{fp.version}` not parseable")
        if fp.base is not None and fp.version_parsed is not None:
            # condition probes (only meaningful once the frontend is confirmed)
            r = p.get(fp.web_url("/index_sso.php"), allow_redirects=True)
            if r is not None:
                fp.sso_present = r.status_code in (200, 301, 302, 500) and r.status_code != 404
                # SAML enabled? stock frontends bounce /index_sso.php straight back
                # to the login form (302 -> index.php); with SAML on it goes to the
                # IdP (external Location) or renders a SAMLRequest page.
                loc = ""
                if r.history:
                    loc = r.history[0].headers.get("Location", "") or ""
                elif r.url:
                    loc = str(r.url)
                if r.status_code == 302 or r.history:
                    fp.sso_enabled = "index.php" not in loc
                fp.notes.append(f"index_sso.php -> {r.status_code}"
                                + (f" (sso {'enabled' if fp.sso_enabled else 'disabled'})"
                                   if fp.sso_enabled is not None else ""))
            r = p.get(fp.web_url("/jsrpc.php"))
            if r is not None:
                fp.jsrpc_present = r.status_code in (200, 302, 500) and r.status_code != 404
            # service ports on the same host the modules target
            fp.agent_port_open = tcp_open(host, 10050, timeout=min(2.0, timeout))
            fp.server_port_open = tcp_open(host, 10051, timeout=min(2.0, timeout))
        if not fp.web and not fp.api:
            fp.notes.append("no Zabbix frontend detected")
        return fp
    finally:
        if own_probe:
            p.close()
