#!/usr/bin/env python3
"""Full passive-matrix sweep: for every release branch pick a docker-available
patch, spin up the stack, run the passive scanner, tear down.

Writes results/matrix_passive.csv and a summary line per branch.
Usage: python3 scripts/sweep_passive.py [--patch 5.4.8]  (default: latest patch per branch)
"""
from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import testlab  # noqa: E402
from zbxscan.fingerprint import fingerprint  # noqa: E402
from zbxscan.passive import scan_target  # noqa: E402

RESULTS = ROOT / "results"
CSV = RESULTS / "matrix_passive.csv"


def latest_patch_with_image(branch: str) -> str | None:
    v = testlab.VERSIONS
    d = v.get("docker", {})
    patches = v.get("patches", {}).get(branch) or []
    for ver in reversed(patches):
        if d.get(ver):
            return ver
    return None


def run_one(ver: str) -> dict:
    row = {"version": ver, "fingerprint_ok": False, "api": False, "web": False,
           "hits": 0, "hits_pass": 0, "creds_ok": False, "error": ""}
    try:
        _, port = testlab.up(ver)
        ready = testlab.wait_ready(port, testlab.container_names(ver)["web"], timeout=240)
        if not ready:
            row["error"] = "frontend not ready"
            return row
        rep = scan_target(f"127.0.0.1:{port}", timeout=8.0)
        fp = rep.fp
        row.update(fingerprint_ok=fp.version is not None,
                   api=fp.api, web=fp.web,
                   hits=len(rep.hits),
                   hits_pass=sum(1 for h in rep.hits if h.condition_status == "pass"),
                   creds_ok=any(c.ok for c in rep.creds))
        if fp.version:
            row["version_found"] = fp.version
        out = RESULTS / f"passive_{ver}.txt"
        with open(out, "w", encoding="utf-8") as f:
            f.write(f"== {ver} ==\nversion={fp.version} api={fp.api} web={fp.web}\n")
            for h in sorted(rep.hits, key=lambda x: x.record["id"]):
                f.write(f"{h.record['id']} {h.condition_status} "
                        f"fixed={h.patched} poc={(h.record.get('public_poc') or {}).get('exists')}\n")
    except Exception as e:  # noqa: BLE001
        row["error"] = f"{type(e).__name__}: {e}"
    finally:
        testlab.down(ver)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--patch", help="single specific patch to sweep")
    args = ap.parse_args()
    RESULTS.mkdir(exist_ok=True)

    rows: list[dict] = []
    if args.patch:
        branch = testlab.branch_of(args.patch)
        branches = [branch]
        ver_of = {branch: args.patch}
    else:
        branches = [b["branch"] for b in testlab.VERSIONS["branches"]]
        ver_of = {b: None for b in branches}

    for branch in branches:
        ver = ver_of[branch]
        if ver is None:
            ver = latest_patch_with_image(branch)
        if ver is None:
            print(f"[sweep] {branch}: no docker image for any patch — skip")
            continue
        print(f"[sweep] {branch} -> {ver} ...", flush=True)
        row = run_one(ver)
        row["branch"] = branch
        rows.append(row)
        print(f"[sweep] {ver}: fp={row['fingerprint_ok']} api={row['api']} "
              f"hits={row['hits']} pass={row['hits_pass']} creds={row['creds_ok']} "
              f"{row['error']}", flush=True)

    with open(CSV, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["branch", "version", "version_found",
                                          "fingerprint_ok", "api", "web", "hits",
                                          "hits_pass", "creds_ok", "error"])
        w.writeheader()
        w.writerows(rows)
    print("\n[sweep] done -> results/matrix_passive.csv")


if __name__ == "__main__":
    main()
