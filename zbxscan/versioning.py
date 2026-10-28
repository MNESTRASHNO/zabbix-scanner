"""Zabbix version parsing, comparison and range matching.

Zabbix version strings seen in the wild / in the DB:
  "3.0.4", "5.4.0rc2", "6.0.0alpha1", "7.0.0beta2", "2.2.14rc1".

Pre-release phases are ordered: alpha < beta < rc < release.
A bare two-part range bound like "4.4" means the whole branch (any patch).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_PHASE_RANK = {"alpha": 1, "beta": 2, "rc": 3, "": 4}

# matches: 5.4 / 3.0.4 / 5.4.0rc2 / 6.0.0alpha1 / 6.0.0a1 / 6.0.0b2
_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?(?:(a|b|alpha|beta|rc)(\d*))?$", re.I)


@dataclass(frozen=True)
class ZabbixVersion:
    raw: str
    major: int
    minor: int
    patch: int
    phase: str  # alpha | beta | rc | ""
    phase_num: int  # 0 for release

    @property
    def branch(self) -> str:
        return f"{self.major}.{self.minor}"

    def as_tuple(self):
        return (self.major, self.minor, self.patch, _PHASE_RANK[self.phase], self.phase_num)

    def __str__(self) -> str:
        return self.raw


def parse_version(s: str) -> ZabbixVersion | None:
    """Parse a Zabbix version string; None for "unknown" or garbage."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    if s == "unknown" or not s:
        return None
    m = _RE.match(s)
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2))
    patch = int(m.group(3) or 0)
    ph_raw = (m.group(4) or "").lower()
    ph_num = int(m.group(5) or 0)
    if ph_raw == "a":
        ph = "alpha"
    elif ph_raw == "b":
        ph = "beta"
    else:
        ph = ph_raw
    if ph and ph_num == 0:
        ph_num = 1
    return ZabbixVersion(s, major, minor, patch, ph, ph_num)


def compare(a: ZabbixVersion, b: ZabbixVersion) -> int:
    ta, tb = a.as_tuple(), b.as_tuple()
    return (ta > tb) - (ta < tb)


def _exclusive(entry: dict) -> bool:
    notes = str(entry.get("notes") or "")
    return "эксклюзивный" in notes or "exclusive" in notes.lower()


class VersionRange:
    """One entry of a record's affected_versions: {branch, min, max, notes}."""

    def __init__(self, entry: dict):
        self.entry = entry
        self.branch = str(entry.get("branch") or "")
        lo = entry.get("min")
        hi = entry.get("max")
        self.min = parse_version(lo) if lo not in (None, "unknown", "") else None
        self.max = parse_version(hi) if hi not in (None, "unknown", "") else None
        # two-part max ("4.4") = whole branch inclusive of every patch
        if self.max is not None and self.max.raw.count(".") < 2:
            self.max = ZabbixVersion(
                self.max.raw, self.max.major, self.max.minor, 99999,
                self.max.phase, self.max.phase_num)
        self.inclusive = not _exclusive(entry)

    def matches(self, v: ZabbixVersion) -> bool:
        if not self.branch or v.branch != self.branch:
            return False
        if self.min and compare(v, self.min) < 0:
            return False
        if self.max:
            c = compare(v, self.max)
            if c > 0 or (c == 0 and not self.inclusive):
                return False
        return True

    def __repr__(self) -> str:
        return f"<Range {self.branch} {self.min}..{self.max} {'incl' if self.inclusive else 'excl'}>"


def matches_any(v: ZabbixVersion, entries: list | None) -> bool:
    """True if version falls into any affected_versions entry."""
    for e in entries or []:
        if VersionRange(e).matches(v):
            return True
    return False


def is_fixed(v: ZabbixVersion, fixed_versions: list | None) -> bool:
    """True if the version is >= the newest fix version of its OWN branch.

    Fix lists are per-branch (e.g. ['4.0.37', '5.0.19', '5.4.9']); a 5.4.x
    build is only patched once it reaches the 5.4 fix, not 4.0.37 or 5.0.19.
    """
    best: ZabbixVersion | None = None
    for f in fixed_versions or []:
        fv = parse_version(f)
        if fv is not None and fv.branch == v.branch:
            if best is None or compare(fv, best) > 0:
                best = fv
    return best is not None and compare(v, best) >= 0
