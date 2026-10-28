# Креды Zabbix (2016–2026): исследовательский конспект

Файл данных: `credentials.json` (9 записей, все комбинации `(target, username, password, source)` уникальны).
Все пары — только по проверенным источникам; что не подтверждено — отдельным разделом внизу.

---

## 1. Официальные дефолты (category=default)

| target | username | password | Ветки | Источник |
|---|---|---|---|---|
| frontend (веб-логин) | `Admin` | `zabbix` | **all** (1.8 → 8.0; проверено 1.8, 2.0, 2.2, 2.4, 3.0, 4.0, 5.0, 6.0, 7.0, 7.2, 7.4, 8.0) | Quickstart «Login and configuring user»: `https://www.zabbix.com/documentation/current/en/manual/quickstart/login` (аналогично `/3.0`, `/4.0`, `/5.0`, `/6.0`, `/7.2`; в 7.0 URL переехал: `.../7.0/en/manual/quickstart/basic_config/login`) |
| api (user.login) | `Admin` | `zabbix` | all | `https://www.zabbix.com/documentation/7.2/en/manual/api/reference/user/login` (примеры auth в `.../7.0/en/manual/api`, раздел Authentication) |
| docker-compose (env) | `zabbix` | `zabbix` | 5.0–7.4 | `https://github.com/zabbix/zabbix-docker` → `env_vars/.env_db_pgsql`, `env_vars/.env_db_mysql` (ветки 6.0, 7.0, 7.4) + `https://www.zabbix.com/documentation/5.0/en/manual/installation/containers` |
| database (MySQL/PostgreSQL) | `zabbix` | `zabbix` (docker) / задаётся админом (bare-metal) | all | `https://www.zabbix.com/documentation/5.0/en/manual/installation/containers` |
| api (токены) | — | — | 6.0+ | **Дефолтных API-токенов нет** (информационная запись) — `https://www.zabbix.com/documentation/7.0/en/manual/api`, раздел Authentication |

Ключевые цитаты:

- Frontend: «Enter the user name **Admin** with password **zabbix** to log in as a Zabbix superuser» — текст идентичен во всех ветках.
- Docker env (офиц. документация контейнеров 5.0): «MYSQL_USER … By default, value is 'zabbix'», «MYSQL_PASSWORD … By default, value is 'zabbix'»; то же для `POSTGRES_USER`/`POSTGRES_PASSWORD`; `DB_SERVER_HOST` по умолчанию `mysql-server`/`postgres-server`; БД `zabbix`. В zabbix-docker эти же дефолты в `env_vars/` (в compose подключаются как secrets/env_file; дефолты закомментированы как `# MYSQL_PASSWORD=zabbix` и т.д.).
- BM (bare-metal) установка: документация требует создать пользователя БД `zabbix` с паролем **по выбору администратора** — фиксированного дефолтного пароля БД для сборок из пакетов/исходников нет.

---

## 2. per-version

| target | username | password | Ветки | Примечание / источник |
|---|---|---|---|---|
| frontend | `guest` | (пусто) | включён по умолчанию: 2.x, 3.0, 4.0 < 4.0.15 | «As a guest, you may access monitoring pages in Zabbix **without being logged in**» (3.0). Пароль не задан. Прав по умолчанию нет. |
| frontend | `guest` | (пусто) | отключён по умолчанию: с 4.0.15 | 4.0: «Starting with Zabbix 4.0.15, the 'guest' user is **disabled by default**. To re-enable it, add it to the Guests user group». |
| frontend | `guest` | (пусто) | 5.0–7.2 (отключён) | 5.0: «disabled by default»; 6.0: «before Zabbix 6.0.28, automatic guest login was possible»; 7.0+: «To enable the user, remove the predefined **Disabled** group». |
| api | — | — | ≤5.2 | парам. логина **`user`**; 5.4+: **`username`** (в 6.0 `user` deprecated, с 7.0 удалён) — таблица Parameters `.../manual/api/reference/user/login` по веткам 3.0/4.0/4.4/5.0/5.2/5.4/6.0/7.0/7.2. |

Аномалий по **самому паролю Admin/zabbix** в 3.0–7.2 НЕТ — дефолт не менялся ни разу (в т.ч. в 1.8: документация уже «Admin with password zabbix»).

---

## 3. popular (wordlist-ы / сканеры / блоги)

| target | username | password | Источник |
|---|---|---|---|
| frontend | `Admin` | `zabbix` | ProjectDiscovery nuclei-templates `http/default-logins/zabbix/zabbix-default-login.yaml` (POST name/password на `/index.php`, `/zabbix/index.php`; матчер 302 → `zabbix.php?action=dashboard.view`) |
| frontend | `Admin` | `zabbix` | SecLists `Passwords/Default-Credentials/default-passwords.csv` — строка `zabbix,Admin,zabbix` (единственная zabbix-пара во всём SecLists; в default-passwords.txt только пароль-строка `zabbix`) |
| frontend | `guest` | (пусто) | Metasploit `modules/auxiliary/scanner/http/zabbix_login.rb` — «Zabbix Server Brute Force Utility»: тестирует `Admin:zabbix` и guest-режим («This Zabbix instance has Guest mode enabled») |
| frontend | `Admin` | `zabbix` | Блог AccessChecker `https://www.accesschecker.net/en/software/zabbix` (заявляет «case-sensitive», ссылается на офиц. документацию) |

Все популярные источники повторяют ту же пару `Admin`/`zabbix` — других подтверждённых пар в wordlist-ах для Zabbix не найдено.

---

## 4. user.login — формат запроса по веткам

Эндпоинт: `POST http(s)://<host>/zabbix/api_jsonrpc.php` (JSON-RPC 2.0).

| Ветка | Параметр имени пользователя | Запрос |
|---|---|---|
| ≤ 5.2 (3.0, 4.0, 4.4, 5.0, 5.2) | `user` | `{"jsonrpc":"2.0","method":"user.login","params":{"user":"Admin","password":"zabbix"},"id":1}` |
| 5.4, 6.0 | `username` (в 6.0 `user` ещё принимается, deprecated) | `{"jsonrpc":"2.0","method":"user.login","params":{"username":"Admin","password":"zabbix"},"id":1}` |
| 7.0, 7.2, 7.4 (current), 8.0 | `username` (только) | то же; опционально `"userData":true` → в ответе объект пользователя вместо sessionid |

Ответ: `{"jsonrpc":"2.0","result":"<sessionid>","id":1}` (24 символа, hex). Метод вызывается **без** поля `auth`.

⚠️ **Исправление к ТЗ**: в задании сказано «7.0+ требует передавать `user` вместо `username`» — по факту **наоборот**: `user` использовался ДО 5.2, а с **5.4** обязателен `username` (7.0+ `user` уже не документируется). Проверено по таблицам Parameters документации каждой ветки.

Авторизация API в 6.0+ также возможна API-токеном: поле `auth` в JSON-RPC или заголовок `Authorization: Bearer <token>`; токен создаётся пользователем вручную (Users > API tokens / метод `token.create`) — **дефолтных токенов не существует** (см. раздел Authentication `.../7.0/en/manual/api`).

---

## 5. Что НЕ подтверждено (исключено из credentials.json)

| Пара / факт | Статус |
|---|---|
| `admin/admin` (старые 1.8/2.0) | ❌ Не подтверждено: уже в 1.8 документация даёт `Admin`/`zabbix`. Легенда из ранних версий (<1.8), вне окна 2016–2026. |
| `admin/zabbix` (нижний регистр) | ⚠️ Источника-пары не найдено. Работает только при отключённой опции «Case sensitive login» (существует с ~4.0, **включена по умолчанию**: «Unmark the checkbox to disable case-sensitive login … enabled by default» — `.../manual/web_interface/frontend_sections/administration/authentication`, ветки 4.0/5.0/6.0). В 3.x настройка не задокументирована. |
| `zabbix`/`zabbix` как веб-логин фронтенда | ❌ Не подтверждено: это креды БД/docker, а не UI. В wordlist-ах такой zabbix-пары для фронтенда нет. |
| `guest`/`guest` | ❌ Не подтверждено ни одним источником. |
| `cirt.net/passwords` → zabbix | ⚠️ Недоступно: cirt.net отдаёт Cloudflare-блокировку (и из web.archive.org не получить). В коллекции SecLists `cirt-net_collection.txt` записей zabbix нет. |
| root-пароль Zabbix appliance (OVA) | ⚠️ Не подтверждено из офиц. документации (страницы `manual/quickstart/appliance` явных кредов не содержат). Не включено. |
| guest-логин через API | ⚠️ Не подтверждено: guest без прав создан для неаутентифицированного веб-доступа; сценарий `user.login("guest","")` документацией не описан. |

---

## 6. Источники (сводно)

Официальные (default/per-version):
- `https://www.zabbix.com/documentation/{3.0|4.0|5.0|6.0|7.0|7.2|current}/en/manual/quickstart/login` (+ `7.0/en/manual/quickstart/basic_config/login`)
- `https://www.zabbix.com/documentation/{2.0|3.0|4.4|5.0|5.2|5.4|6.0|7.0|7.2}/en/manual/api/reference/user/login`
- `https://www.zabbix.com/documentation/7.0/en/manual/api` (Authentication; token)
- `https://www.zabbix.com/documentation/{3.0|4.0|5.0|6.0|7.0|7.2}/en/manual/config/users_and_usergroups/user` (guest)
- `https://www.zabbix.com/documentation/{5.0|current}/en/manual/installation/containers` (docker env)
- `https://www.zabbix.com/documentation/{4.0|5.0|6.0}/en/manual/web_interface/frontend_sections/administration/authentication` (case-sensitive login)

Wordlist-ы/сканеры (popular):
- `https://github.com/danielmiessler/SecLists` → `Passwords/Default-Credentials/default-passwords.csv`, `cirt-net_collection.txt`
- `https://github.com/projectdiscovery/nuclei-templates` → `http/default-logins/zabbix/zabbix-default-login.yaml`
- `https://github.com/rapid7/metasploit-framework` → `modules/auxiliary/scanner/http/zabbix_login.rb`
- `https://www.accesschecker.net/en/software/zabbix`

Repo docker: `https://github.com/zabbix/zabbix-docker` (ветки 6.0, 7.0, 7.4; `env_vars/.env_db_{mysql,pgsql}`).