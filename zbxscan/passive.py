"""Passive scan: fingerprint -> DB lookup -> condition checks -> default creds.

Pipeline per target:
  fingerprint()                       exact version + stack signals
  records_for_version()              CVE + advisory hits
  exploit.condition(id, fp)          prerequisite probes (pass/fail/unknown)
  components_for_branch()            stack (PHP/Apache/DB) CVE candidates
  check_default_creds()              user.login attempts with timeouts/delays
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import db
from .exploits import condition
from .fingerprint import Fingerprint, fingerprint as do_fingerprint
from .http import HttpProbe
from .versioning import compare, is_fixed, parse_version

#: login param name switched at 5.4 ("user" -> "username"); research/credentials_notes.md
LOGIN_USER_PARAM_MIN = "5.4"

#: default attempts (avoids the 5-strikes->30s lockout); the rest need --all-creds
DEFAULT_CRED_IDS = (
    ("frontend", "Admin", "zabbix"),
    ("frontend", "guest", ""),
)


@dataclass
class CredResult:
    username: str
    password: str
    category: str
    ok: bool
    detail: str = ""
    token: str | None = None


@dataclass
class VulnHit:
    record: dict
    condition_status: str = "unknown"
    condition_detail: str = "no exploit module"
    patched: bool = False


@dataclass
class TargetReport:
    target: str
    fp: Fingerprint
    hits: list[VulnHit] = field(default_factory=list)
    components: list[dict] = field(default_factory=list)
    creds: list[CredResult] = field(default_factory=list)
    auth_context: dict | None = None
    creds_reevaluated: bool = False
    notes: list[str] = field(default_factory=list)


def _rpc(probe, fp, method, params, auth=None):
    url = f"http{'s' if fp.port == 443 else ''}://{fp.host}:{fp.port}{fp.base}/api_jsonrpc.php"
    body = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    if auth is not None:
        body["auth"] = auth
    resp = probe.post(url, json=body)
    if resp is None:
        return {"error": {"code": -1, "message": "no response"}}
    try:
        return resp.json()
    except ValueError:
        return {"error": {"code": -1, "message": f"bad json http={resp.status_code}"}}


def auth_context(fp: Fingerprint, probe: HttpProbe, user: str, password: str,
                 token: str | None = None) -> dict:
    """Authenticated context: exact identity, role rules, and the primitives each
    exploit family needs (scripts, editable hosts, dashboards, reports,
    media types, actions, web-service port).

    Pass `token` to reuse an existing session (avoids a second user.login, which
    can trip the 5-failed-logins -> 30s lockout right after creds probing)."""
    ctx: dict = {"login": None}
    if token is None:
        v = fp.version_parsed
        key = "user"
        if v is not None and compare(v, parse_version("5.4.0")) >= 0:
            key = "username"
        lg = _rpc(probe, fp, "user.login", {key: user, "password": password})
        if "result" not in lg or not isinstance(lg.get("result"), str):
            ctx["login_error"] = lg
            return ctx
        auth = lg["result"]
    else:
        auth = token
    ctx["token"] = auth
    me = _rpc(probe, fp, "user.get",
              {"output": ["userid", "username", "roleid"],
               "filter": {"username": user},
               "selectUsrgrps": ["usrgrpid", "name"]}, auth=auth)
    me0 = (me.get("result") or [{}])[0] if me.get("result") else {}
    role_o = {}
    rid = me0.get("roleid")
    if rid:
        role = _rpc(probe, fp, "role.get",
                    {"roleids": [rid],
                     "output": ["roleid", "name", "type", "rules"]}, auth=auth)
        role_o = (role.get("result") or [{}])[0] if role.get("result") else {}
    ctx["me"] = {"userid": me0.get("userid"), "username": me0.get("username"),
                 "role": role_o.get("name"),
                 "role_type": role_o.get("type"),
                 "groups": [g.get("name") for g in me0.get("usrgrps") or []]}
    rules = role_o.get("rules") or {}
    ctx["rules"] = rules
    superadmin = str(role_o.get("type")) == "3"
    # behavioral permission probes (rules not exposed via API in 7.0.0):
    # success of each resource call = granted read; editable hosts = write
    sc = _rpc(probe, fp, "script.get", {"output": ["scriptid", "name", "execute_on", "host_access"]},
              auth=auth)
    ctx["scripts"] = sc.get("result") or []
    ctx["scripts_ok"] = "error" not in sc
    ctx["ping_script"] = any("ping" in (s.get("name") or "").lower() for s in ctx["scripts"])
    hs = _rpc(probe, fp, "host.get", {"output": ["hostid"], "editable": True, "limit": 5}, auth=auth)
    hs_list = hs.get("result") or []
    ctx["editable_hosts_count"] = len(hs_list)
    ctx["hosts_ok"] = "error" not in hs
    db2 = _rpc(probe, fp, "dashboard.get", {"output": ["dashboardid"], "limit": 5}, auth=auth)
    ctx["dashboards_count"] = len(db2.get("result") or [])
    rep = _rpc(probe, fp, "report.get", {"output": ["reportid"], "limit": 5}, auth=auth)
    ctx["reports_count"] = len(rep.get("result") or [])
    mt = _rpc(probe, fp, "mediatype.get", {"output": ["mediatypeid"], "limit": 5}, auth=auth)
    ctx["mediatypes_count"] = len(mt.get("result") or [])
    ctx["mediatypes_ok"] = "error" not in mt
    act = _rpc(probe, fp, "action.get", {"output": ["actionid"], "limit": 5}, auth=auth)
    ctx["actions_count"] = len(act.get("result") or [])
    ctx["actions_ok"] = "error" not in act
    ctx["can_script_edit"] = superadmin or bool(ctx["scripts"])
    ctx["can_script_execute"] = superadmin or bool(ctx["scripts"])
    ctx["can_item_create"] = superadmin or ctx["editable_hosts_count"] > 0
    ctx["can_host_write"] = superadmin or ctx["editable_hosts_count"] > 0
    ctx["can_media_admin"] = superadmin or ctx["mediatypes_ok"]
    ctx["is_superadmin"] = superadmin
    # web service port probe (backend of reports; visual for 46768/32725)
    try:
        import socket as _s
        s = _s.create_connection((fp.host, 10053), timeout=2)
        s.close()
        ctx["ws_10053_open"] = True
    except OSError:
        ctx["ws_10053_open"] = False
    # auth-method fingerprint (supplementary info, not a vuln):
    # markers on the login page + post-login behaviour (2FA/TOTP prompt)
    ctx["auth_methods"] = _probe_auth_methods(fp, probe)
    return ctx


def _probe_auth_methods(fp: Fingerprint, probe: HttpProbe) -> dict:
    """Collect evidence about SSO/LDAP/2FA from the login page and a web login
    attempt (2FA prompt detection). Best-effort, no false guarantees."""
    import re as _re
    out = {"saml_sso_present": fp.sso_present}
    base = f"http{'s' if fp.port == 443 else ''}://{fp.host}:{fp.port}{fp.base}"
    r = probe.get(base + "/index.php", allow_redirects=True)
    html = (r.text or "") if r is not None else ""
    low = html.lower()
    out["ldap_link"] = ("ldap" in low) or bool(_re.search(r"ldap", low))
    out["sso_button"] = any(k in low for k in ("sso", "single sign-on", "idp", "saml"))
    out["totp_prompt_on_login_page"] = any(k in low for k in
                                          ("authenticator", "verification code", "one-time password", "totp"))
    markers = {"google_authenticator": "authenticator", "verification_code": "verification code",
               "one_time_password": "one-time password", "totp": "totp"}
    found = [n for n, k in markers.items() if k in low]
    out["login_page_markers"] = found
    if fp.api and fp.base is not None:
        # web form login (with -creds) can reveal a 2FA gate after credentials
        if getattr(probe, "_zbx_creds", None):
            u, p = probe._zbx_creds
            r2 = probe.post(base + "/index.php", data={"name": u, "password": p,
                                                       "autologin": "0", "enter": "Sign in"},
                            allow_redirects=True)
            h2 = (r2.text or "") if r2 is not None else ""
            l2 = h2.lower()
            out["post_login_2fa_prompt"] = any(k in l2 for k in
                                               ("authenticator", "verification code", "two-factor"))
            out["signed_in_no_2fa"] = "sign out" in l2
    return out


#: exploit-family verdict based on authenticated context
def _verdict(record: dict, ctx: dict) -> tuple[str, str] | None:
    rid = record["id"]
    me = ctx.get("me") or {}
    superadmin = str(me.get("role_type")) == "3"
    def need(cond: bool, what: str):
        return ("pass", f"creds: {what} OK") if cond else ("fail", f"creds: {what} NOT granted")
    fam = {
        "CVE-2023-29450": lambda: need(ctx.get("can_item_create") or ctx.get("can_host_write")
                                        or superadmin, "host/item write"),
        "CVE-2024-22116": lambda: need((ctx.get("can_script_execute") and
                                        (ctx.get("can_host_write") or superadmin)) or superadmin,
                                       "script execute + host write"),
        "CVE-2025-27232": lambda: need(superadmin or ctx.get("can_media_admin"),
                                       "media-types admin (Super admin)"),
        "CVE-2024-36465": lambda: ("pass", "creds: any API user suffices"),
        "CVE-2024-42327": lambda: ("pass", "creds: any API user suffices"),
        "CVE-2024-36467": lambda: ("pass", "creds: any API user suffices"),
        "CVE-2024-22120": lambda: ("pass" if (ctx.get("can_script_execute")
                                              or superadmin) else "fail",
                                   "creds: script execute rights"),
        "CVE-2021-46088": lambda: need(ctx.get("can_script_edit") or superadmin,
                                       "script create/execute (admin role)"),
        "CVE-2022-46768": lambda: need(ctx.get("ws_10053_open"), "web-service 10053 reachable"),
        "CVE-2022-23134": lambda: ("pass", "creds: setup.php vector is unauth"),
        "CVE-2016-10134": lambda: ("pass", "creds: jsrpc.php vector is unauth"),
    }
    fn = fam.get(rid)
    if fn:
        return fn()
    if record.get("type") == "xss":
        return ("unknown",
                "XSS: chain to RCE — deliver victim's zbx_session (stored XSS / "
                "URL-widget via CVE-2023-32725), inject the cookie → victim session → "
                "script RCE (module CVE-2021-46088). Active exploitation needs a browser/victim.")
    return None


def _login_payload(version_str: str | None, username: str, password: str) -> dict:
    """user.login params: {"user": ..} until 5.2, {"username": ..} from 5.4."""
    v = parse_version(version_str) if version_str else None
    key = "user"
    if v is not None and compare(v, parse_version(LOGIN_USER_PARAM_MIN)) >= 0:
        key = "username"
    return {"jsonrpc": "2.0", "method": "user.login",
            "params": {key: username, "password": password}, "id": 2}


def check_default_creds(fp: Fingerprint, probe: HttpProbe,
                        all_creds: bool = False, delay: float = 0.7) -> list[CredResult]:
    if not fp.api or fp.base is None:
        return []
    url = f"http{'s' if fp.port == 443 else ''}://{fp.host}:{fp.port}{fp.base}/api_jsonrpc.php"
    creds = db.credentials()
    results: list[CredResult] = []
    seen: set[tuple[str, str]] = set()
    if not all_creds:
        candidates = [(cat, u, p) for (cat, u, p) in DEFAULT_CRED_IDS]
    else:
        candidates = [(c["category"], c["username"], c["password"]) for c in creds]
    for cat, uname, pw in candidates:
        pair = (uname, pw)
        if pair in seen:
            continue
        seen.add(pair)
        body = _login_payload(fp.version, uname, pw)
        resp = probe.post(url, json=body, delay=delay)
        if resp is None:
            results.append(CredResult(uname, pw, cat, False,
                                      "no response (timeout/conn)"))
            continue
        if resp.status_code == 200:
            try:
                data = resp.json()
            except ValueError:
                data = None
            if isinstance(data, dict) and isinstance(data.get("result"), str):
                results.append(CredResult(uname, pw, cat, True,
                                          f"token {data['result'][:12]}…",
                                          token=data["result"]))
                # stop at the first working pair in default mode: keeps on
                # brute-forcing only trips the 5-failed-logins -> 30s lockout
                # of the very account we just found (and we want its token).
                if not all_creds:
                    break
                continue
        results.append(CredResult(uname, pw, cat, False,
                                  f"http {resp.status_code}"))
    return results


def scan_target(target: str, probe: HttpProbe | None = None, timeout: float = 8.0,
                all_creds: bool = False, user: str | None = None,
                password: str | None = None) -> TargetReport:
    fp = do_fingerprint(target, probe=probe, timeout=timeout)
    own = probe is None
    p = probe or HttpProbe(timeout=timeout)
    report = TargetReport(target, fp)
    try:
        if fp.version_parsed:
            for r in db.records_for_version(fp.version, kinds=("cve", "advisory")):
                st, det = condition(r["id"], fp)
                # appliance/java-only advisories do not apply to a php/nginx web stack
                txt = ((r.get("summary") or "") + " " + (r.get("component") or "")).lower()
                if "logback" in txt or "appliance" in txt or ("java" in txt and "javascript" not in txt):
                    st, det = "fail", f"stack gate: {r['id']} applies to java/appliance components, not to this php stack"
                report.hits.append(VulnHit(
                    record=r,
                    condition_status=st,
                    condition_detail=det,
                    patched=is_fixed(fp.version_parsed, r.get("fixed_versions")),
                ))
            report.components = db.components_for_branch(fp.version_parsed.branch)
        # authenticated passive: refine hits with the account's actual rights
        if user is not None and password is not None and fp.api:
            p_session = probe if probe is not None else p
            p_session._zbx_creds = (user, password)  # consumed by auth-method probe
            report.auth_context = auth_context(fp, p_session, user, password)
            ctx = report.auth_context
            for h in report.hits:
                vd = _verdict(h.record, ctx) if ctx.get("token") else ("fail", "creds: login failed")
                if vd is not None:
                    h.condition_status, h.condition_detail = vd
        report.creds = check_default_creds(fp, p, all_creds=all_creds)
        # default creds found and no explicit creds given -> re-evaluate the
        # auth-gated conditions with the working account (as if creds were typed)
        if user is None and password is None:
            ok = next((c for c in report.creds if c.ok), None)
            if ok is not None and ok.token and fp.api:
                p_session = probe if probe is not None else p
                p_session._zbx_creds = (ok.username, ok.password)
                report.auth_context = auth_context(fp, p_session, ok.username, ok.password,
                                                   token=ok.token)
                ctx = report.auth_context
                if ctx.get("token"):
                    for h in report.hits:
                        vd = _verdict(h.record, ctx)
                        if vd is not None:
                            h.condition_status, h.condition_detail = vd
                    report.creds_reevaluated = True
        return report
    finally:
        if own:
            p.close()
