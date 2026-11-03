#!/usr/bin/env python3
"""Persistent lab: bring up stacks for given versions and keep them running.
Writes port map to /tmp/opencode/lab_ports.json (merges with existing)."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import testlab  # noqa: E402

OUT = Path("/tmp/opencode/lab_ports.json")
VERSIONS = sys.argv[1:] or ["5.0.44", "7.4.3"]

ports = OUT.read_text() and json.loads(OUT.read_text()) if OUT.exists() else {}
ready = {k: v for k, v in ports.items() if isinstance(v, bool)}
for ver in VERSIONS:
    try:
        _, port = testlab.up(ver)
        ports[ver] = port
    except SystemExit as e:
        print(f"[lab] skip {ver}: {e}", flush=True)
        continue
for ver in list(VERSIONS):
    port = ports.get(ver)
    if port is None:
        continue
    ok = testlab.wait_ready(port, testlab.container_names(ver)["web"], timeout=420)
    ready[ver] = ok
    print(f"[lab] {ver} port={port} ready={ok}", flush=True)

OUT.write_text(json.dumps(ports, indent=1))
Path("/tmp/opencode/lab_ready.json").write_text(json.dumps(ready, indent=1))
print("[lab] DONE", flush=True)
