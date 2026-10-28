#!/usr/bin/env python3
"""Testlab: spin up a Zabbix stack (server + DB + web) for a given version,
run the scanner against it, then tear everything down.

Usage:
  python3 scripts/testlab.py --patch 5.4.8            # full cycle: up -> scan -> down
  python3 scripts/testlab.py --patch 5.4.8 --scan-only # target already up
  python3 scripts/testlab.py --patch 5.4.8 --keep      # leave running after scan
  python3 scripts/testlab.py --down                    # tear down current lab

Docker access goes through `sg docker` (user added to docker group mid-session).
DB flavor: pgsql (matches versions.json stacks "verify" triples).
"""
from __future__ import annotations

import argparse
import json
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSIONS = json.loads((ROOT / "db" / "versions.json").read_text())
RESULTS = ROOT / "results"

FLAVOR = "pgsql"
WEB_TYPE = "nginx"
NET = "zbx-testlab"

DOCKER = "docker"


def dcmd(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["sg", "docker", "-c", shlex.join([DOCKER, *args])]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        print(f"[docker {' '.join(args)}] rc={p.returncode}\n{p.stdout}\n{p.stderr}", file=sys.stderr)
        raise SystemExit(1)
    return p


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def branch_of(ver: str) -> str:
    return ".".join(ver.split(".")[:2])


def images_for(ver: str) -> tuple[str, str, str]:
    """(server, web, db) image strings for a patch version."""
    br = branch_of(ver)
    vtags = VERSIONS.get("docker", {}).get(ver) or []
    def pick(prefix: str) -> str:
        candidates = [f"zabbix/{prefix}:{ver}-alpine", f"zabbix/{prefix}:alpine-{ver}"]
        for want in candidates:
            if any(t == want for t in vtags):
                return want
        raise SystemExit(f"no docker tag for {ver}: tried {candidates}; available: {vtags[:4]}")
    server = pick(f"zabbix-server-{FLAVOR}")
    web = pick(f"zabbix-web-{WEB_TYPE}-{FLAVOR}")
    stack = VERSIONS.get("stacks", {}).get(br, {}).get("verify") or []
    if stack:
        db = stack[1]
    else:
        db = {"3.0": "postgres:9.6", "4.0": "postgres:11", "5.0": "postgres:12",
              "5.4": "postgres:13", "6.0": "postgres:13-alpine",
              "6.4": "postgres:15-alpine", "7.0": "postgres:16-alpine",
              "7.2": "postgres:16-alpine", "7.4": "postgres:16-alpine"}.get(br, "postgres:16-alpine")
    return server, web, db


def envs(ver: str, server_name: str, db_name: str) -> tuple[list[str], list[str], list[str]]:
    """env lists for (db, server, web) containers."""
    db_env = ["POSTGRES_USER=zabbix", "POSTGRES_PASSWORD=zabbix", "POSTGRES_DB=zabbix"]
    server_env = [
        f"DB_SERVER_HOST={db_name}", "DB_SERVER_PORT=5432",
        "POSTGRES_USER=zabbix", "POSTGRES_PASSWORD=zabbix", "POSTGRES_DB=zabbix",
        "ZBX_STARTPOLLERS=2", "ZBX_STARTPOLLERSUNREACHABLE=1", "ZBX_STARTPINGERS=0",
        "ZBX_STARTTRAPPERS=1", "ZBX_STARTPROXYPOLLERS=0",
    ]
    web_env = [
        f"ZBX_SERVER_HOST={server_name}", "ZBX_SERVER_PORT=10051",
        f"DB_SERVER_HOST={db_name}", "DB_SERVER_PORT=5432",
        "POSTGRES_USER=zabbix", "POSTGRES_PASSWORD=zabbix", "POSTGRES_DB=zabbix",
        "PHP_TZ=UTC",
    ]
    return db_env, server_env, web_env


def container_names(ver: str) -> dict:
    safe = ver.replace(".", "_")
    return {"db": f"zlab_{safe}_db", "server": f"zlab_{safe}_server", "web": f"zlab_{safe}_web"}


def up(ver: str) -> tuple[str, int]:
    names = container_names(ver)
    server_img, web_img, db_img = images_for(ver)
    insp = dcmd("network", "inspect", NET, check=False)
    if insp.returncode != 0 or not insp.stdout.strip():
        dcmd("network", "create", NET)
    db_env, server_env, web_env = envs(ver, names["server"], names["db"])

    dcmd("rm", "-f", names["db"], names["server"], names["web"], check=False)
    dcmd("run", "-d", "--name", names["db"], "--network", NET, *[f"-e{e}" for e in db_env], db_img)
    dcmd("run", "-d", "--name", names["server"], "--network", NET,
         *[f"-e{e}" for e in server_env],
         "-p", f"127.0.0.1::10051", server_img)
    web_port = free_port()
    insp = dcmd("image", "inspect", web_img, "--format", "{{json .Config.ExposedPorts}}", check=False)
    internal_web = "8080" if '"8080/tcp"' in insp.stdout else "80"
    dcmd("run", "-d", "--name", names["web"], "--network", NET,
         *[f"-e{e}" for e in web_env],
         "-p", f"127.0.0.1:{web_port}:{internal_web}", web_img)
    print(f"[testlab] {ver}: db={db_img} server={server_img} web={web_img} -> http://127.0.0.1:{web_port}")
    return names["server"], web_port


def wait_ready(web_port: int, name: str, timeout: int = 240) -> bool:
    import requests  # noqa
    import urllib3
    urllib3.disable_warnings()
    body = {"jsonrpc": "2.0", "method": "apiinfo.version", "params": [], "id": 1}
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.post(f"http://127.0.0.1:{web_port}/api_jsonrpc.php",
                              json=body, timeout=3, verify=False)
            if r.status_code == 200 and isinstance(r.json().get("result"), str):
                return True
        except Exception:
            pass
        time.sleep(3)
    p = dcmd("logs", name, check=False)
    print("[testlab] frontend not ready — web container logs:\n", p.stdout[-2000:], file=sys.stderr)
    return False


def scan(web_port: int, ver: str) -> int:
    RESULTS.mkdir(exist_ok=True)
    out_path = RESULTS / f"passive_{ver}.txt"
    cmd = [sys.executable, "-m", "zbxscan.cli", "-m", "passive", "-t", f"127.0.0.1:{web_port}", "--timeout", "8"]
    p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    out_path.write_text(p.stdout + "\n--- stderr ---\n" + p.stderr)
    print(p.stdout)
    if p.returncode != 0:
        print("scan rc=", p.returncode, p.stderr, file=sys.stderr)
    return p.returncode


def down(ver: str | None = None):
    names = container_names(ver) if ver else {}
    targets = list(names.values()) if ver else []
    if not ver:
        p = dcmd("ps", "-aq", "--filter", f"network={NET}", check=False)
        targets = p.stdout.split()
    if targets:
        dcmd("rm", "-f", *targets, check=False)
    dcmd("network", "rm", NET, check=False)
    print("[testlab] down")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patch", help="Zabbix patch version, e.g. 5.4.8")
    ap.add_argument("--scan-only", action="store_true")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--down", action="store_true")
    args = ap.parse_args()
    if args.down:
        down(args.patch)
        return 0
    if not args.patch:
        ap.error("--patch required")
    if args.scan_only:
        _, port = scan_target_port()
    else:
        _, port = up(args.patch)
        if not wait_ready(port, container_names(args.patch)["web"]):
            print("[testlab] FAILED to become ready", file=sys.stderr)
            down(args.patch)
            return 1
    rc = scan(port, args.patch)
    if not args.keep and not args.scan_only:
        down(args.patch)
    return rc


if __name__ == "__main__":
    sys.exit(main())
