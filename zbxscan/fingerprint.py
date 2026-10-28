"""Zabbix frontend fingerprinting.

Layers, in order of reliability:
  1. POST apiinfo.version (unauthenticated JSON-RPC) -> exact version.
  2. Login page HTML: <title>Zabbix <ver></title> / footer / generator meta.
  3. Set-Cookie shape (zbx_session base64 JSON vs zbx_sessionid 32-hex) + headers.
Plus stack (component) signals: Server header, X-Powered-By, probe of known
endpoints (jsrpc.php, index_sso.php) — used for component CVE conditions.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

import requests

from .http import HttpProbe
from .versioning import ZabbixVersion, parse_version

_TITLE_RE = re.compile(r"Zabbix\s+[vV]?(\d+\.\d+(?:\.\d+)?)")
_FOOTER_RE = re.compile(r"Zabbix\s+[vV]?(\d+\.\d+(?:\.\d+)?)")
_META_GEN_RE = re.compile(r'name=["\']generator["\']\s+content=["\']([^"\']+)', re.I)


def normalize_target(target: str) -> tuple[str, int]:
    """'host[:port]' (optionally with scheme) -> (host, port). Default port 80."""
    scheme = None
    rest = target
    if "://" in rest:
        scheme, rest = rest.split("://", 1)
    if ":" in rest:
        host, _, port = rest.rpartition(":")
        if port.isdigit():
            return host.strip("/"), int(port)
    return rest.strip("/"), (443 if scheme == "https" else 80)


def base_url(host: str, port: int) -> str:
    return f"https://{host}:{port}" if port == 443 else f"http://{host}:{port}"


@dataclass
class Fingerprint:
    target: str
    host: str
    port: int
    base: str | None = None          # resolved frontend base ('' or '/zabbix')
    version: str | None = None
    version_parsed: ZabbixVersion | None = None
    web: bool = False
    api: bool = False
    server_header: str | None = None
    x_powered_by: str | None = None
    cookies: list[str] = field(default_factory=list)
    sso_present: bool | None = None  # /index_sso.php exists (SAML condition)
    jsrpc_present: bool | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def branch(self) -> str | None:
        return self.version_parsed.branch if self.version_parsed else None


def _probe_api_version(probe: HttpProbe, base: str) -> str | None:
    """apiinfo.version is public (no auth) in every version 2.x - 7.x."""
    url = base + "/api_jsonrpc.php"
    for params in ({}, []):
        body = {"jsonrpc": "2.0", "method": "apiinfo.version", "params": params, "id": 1}
        try:
            resp = probe.post(url, json=body)
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


def fingerprint(target: str, probe: HttpProbe | None = None, timeout: float = 8.0) -> Fingerprint:
    host, port = normalize_target(target)
    fp = Fingerprint(target, host, port)
    own_probe = probe is None
    p = probe or HttpProbe(timeout=timeout)
    try:
        for base in ("", "/zabbix"):
            url = base_url(host, port) + (base or "")
            root = p.get(url, allow_redirects=True)
            if root is None:
                continue
            headers = root.headers or {}
            if fp.server_header is None:
                fp.server_header = headers.get("Server")
            if fp.x_powered_by is None:
                fp.x_powered_by = headers.get("X-Powered-By")
            if root.status_code == 200:
                html = root.text or ""
                if "zabbix" in html.lower():
                    fp.web = True
                    fp.base = base or ""
                    cks = root.headers.get("Set-Cookie", "") or ""
                    if cks:
                        fp.cookies = [c.split("=")[0] for c in cks.split(";")]
                    if fp.cookies:
                        fp.notes.append(f"cookies: {fp.cookies}")
                    fp.version = _extract_version(html)
                    fp.notes.append(f"frontend at `{base or '/'}`, status {root.status_code}")
                    break
        if fp.base is None:
            # still probe API on both bases even if no page marker
            for base in ("", "/zabbix"):
                v = _probe_api_version(p, base_url(host, port) + (base or ""))
                if v:
                    fp.version = v
                    fp.api = True
                    fp.base = base or ""
                    fp.web = True
                    fp.notes.append(f"apiinfo.version -> {v}")
                    break
        else:
            v = _probe_api_version(p, base_url(host, port) + fp.base)
            if v:
                fp.api = True
                fp.version = v
                fp.notes.append(f"apiinfo.version -> {v}")
        if fp.version:
            fp.version_parsed = parse_version(fp.version)
            if fp.version_parsed is None:
                fp.notes.append(f"version `{fp.version}` not parseable")
        if fp.base is not None and fp.version_parsed is not None:
            # condition probes (only meaningful once the frontend is confirmed)
            b = base_url(host, port) + fp.base
            r = p.get(b + "/index_sso.php", allow_redirects=True)
            if r is not None:
                fp.sso_present = r.status_code in (200, 301, 302, 500) and r.status_code != 404
                fp.notes.append(f"index_sso.php -> {r.status_code}")
            r = p.get(b + "/jsrpc.php")
            if r is not None:
                fp.jsrpc_present = r.status_code in (200, 302, 500) and r.status_code != 404
        if not fp.web and not fp.api:
            fp.notes.append("no Zabbix frontend detected")
        return fp
    finally:
        if own_probe:
            p.close()
