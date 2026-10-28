"""Access to the consolidated DB (db/)."""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from .versioning import compare, matches_any, parse_version

_BRANCH_TOKEN_RE = re.compile(r"\d+\.\d+")


def _entry_covers_branch(entry: dict, branch: str) -> bool:
    """Match lenient applies_to_zabbix entries like "5.0", "5.0/6.0",
    "4.0/5.0 (bionic)", "5.0+", "3.0-5.0". "-" / "+" annotate version ranges."""
    v = entry.get("branch")
    if not v:
        return False
    if v == "—":
        return False
    v = v.strip()
    tokens = _BRANCH_TOKEN_RE.findall(v)
    if not tokens:
        return False
    bv = parse_version(branch)
    if bv is None:
        return False
    if v.endswith("+") or "+" in v:
        return any(compare(bv, parse_version(t)) >= 0 for t in tokens)
    if "-" in v:
        lo, _, hi = v.partition("-")
        lot, hit = _BRANCH_TOKEN_RE.search(lo), _BRANCH_TOKEN_RE.search(hi)
        if lot and hit:
            return compare(bv, parse_version(lot.group(0))) >= 0 and \
                   compare(bv, parse_version(hit.group(0))) <= 0
        return False
    return branch in v  # exact branch token membership ("5.0/6.0" contains "5.4"? no)



DB_DIR = Path(__file__).resolve().parent.parent / "db"


@lru_cache(maxsize=None)
def _load(name: str) -> dict:
    with open(DB_DIR / name, encoding="utf-8") as f:
        return json.load(f)


def vulns() -> list[dict]:
    return _load("vulns.json")["vulnerabilities"]


def credentials() -> list[dict]:
    return _load("credentials.json")


def pocs() -> list[dict]:
    return _load("pocs.json")


def versions() -> dict:
    return _load("versions.json")


def record(id_: str) -> dict | None:
    for r in vulns():
        if r["id"] == id_:
            return r
    return None


def records_for_version(version_str: str, kinds=("cve", "advisory")) -> list[dict]:
    """Vulnerability records whose affected range covers the given version."""
    v = parse_version(version_str)
    if v is None:
        return []
    out = []
    for r in vulns():
        if r["kind"] not in kinds:
            continue
        if matches_any(v, r.get("affected_versions")):
            out.append(r)
    return out


def components_for_branch(branch: str) -> list[dict]:
    """Component (stack) records applicable to a Zabbix branch."""
    out = []
    for r in vulns():
        if r["kind"] != "component":
            continue
        if any(_entry_covers_branch(a, branch) for a in r.get("applies_to_zabbix") or []):
            out.append(r)
    return out
