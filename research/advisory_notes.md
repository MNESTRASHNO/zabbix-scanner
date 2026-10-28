# Zabbix Security Advisories (non-CVE): ZBX-* / GHSA-* / ZBA-* — конспект исследования

Период: 2016–2026 (по дате создания тикета/публикации адвайзери). Владелец набора: non-CVE id (GHSA-*, ZBX-*, плюс два официальных ZBA-адвайзери без собственного CVE). CVE-записи — в другом наборе (CveResearch).

## Источники
1. **Официальный портал адвайзери Zabbix** — https://www.zabbix.com/security_advisories и RSS https://assets.zabbix.com/files/zabbix_security_advisories.rss (103 записи: ZBV-*/ZBA-*). Данные по affected/fixed версиям получены из typesense-коллекции `zabbix_web_security_advisories` (эндпоинт https://www.zabbix.com/saas/search), которая питает страницу адвайзери.
2. **Трекер Zabbix (Jira)** — https://support.zabbix.com, REST API `/rest/api/2/search`: проект ZBX, jql `labels = security` (96 тикетов), плюс тематические поиски (logback, CVE-2021-42550, GHSA и др.). Подробности (описания, PoC, fix-версии, комментарии) — по `/rest/api/2/issue/{key}`.
3. **GitHub Advisory Database** — https://github.com/advisories (GHSA-коды). Reviewed-записи (php-saml, xmlseclibs) получены через GitHub REST API; полный список unreviewed-записей (CVE-import) — grep по локальному клону github/advisory-database (advisories/unreviewed/).
4. **Блоги вендора** — blog.zabbix.com (теперь zabbix.com/blog): «Zabbix security advisories regarding CVE-2022-23131 and CVE-2022-23134» (Feb 2022), «Monitoring Zabbix Security Advisories» (Oct 2024) — подтверждают процесс публикации адвайзери; спец.-постов по non-CVE фиксам (SAML/API/reports) не найдено, все такие изменения идут через тикеты ZBX.

## Таблица записей (id | type | уязвимый диапазон | фикс | auth | импакт)

| id | type | диапазон | фикс | auth | импакт |
|---|---|---|---|---|---|
| GHSA-23gg-m473-8fr9 | auth-bypass | — | — | user | См. CVE-2024-36466 (NVD/GHSA): A bug in the code allows an attacker to sign a forged zbx_session cookie, which |
| GHSA-2835-94vr-22j6 | other | — | — | user | См. CVE-2026-59783 (NVD/GHSA): The Zabbix Server/Proxy has a vulnerability where binary items can crash the Se |
| GHSA-2fgh-jwqp-hr3r | other | — | — | unknown | См. CVE-2008-1353 (NVD/GHSA): zabbix_agentd in ZABBIX 1.4.4 allows remote attackers to cause a denial of servi |
| GHSA-2h5x-h7x4-hm9h | other | — | — | user | См. CVE-2026-23920 (NVD/GHSA): Host and event action script input is validated with a regex (set by the admini |
| GHSA-2j4h-qfp4-82q7 | sql-injection | — | — | unknown | См. CVE-2013-5743 (NVD/GHSA): Multiple SQL injection vulnerabilities in Zabbix 1.8.x before 1.8.18rc1, 2.0.x b |
| GHSA-2r84-x97c-3ch4 | xss | — | — | user | См. CVE-2022-23133 (NVD/GHSA): An authenticated user can create a hosts group from the configuration with XSS  |
| GHSA-34w2-qwhq-wprv | other | — | — | user | См. CVE-2023-32723 (NVD/GHSA): Request to LDAP is sent before user permissions are checked. |
| GHSA-37pv-569q-qx93 | information-disclosure | — | — | admin | См. CVE-2026-23935 (NVD/GHSA): A Zabbix administrator is able to read out of bounds memory by utilizing a flaw |
| GHSA-399r-wgcm-v67f | command-injection | — | — | none | См. CVE-2016-4338 (NVD/GHSA): The mysql user parameter configuration script (userparameter_mysql.conf) in the  |
| GHSA-39vx-jv7h-w8ch | other | — | — | unknown | См. CVE-2011-3263 (NVD/GHSA): zabbix_agentd in Zabbix before 1.8.6 and 1.9.x before 1.9.4 allows context-depen |
| GHSA-3g95-xf53-275x | xss | — | — | none | См. CVE-2022-40626 (NVD/GHSA): An unauthenticated user can create a link with reflected Javascript code inside |
| GHSA-3m8p-v336-pmqp | other | — | — | user | См. CVE-2024-42328 (NVD/GHSA): When the webdriver for the Browser object downloads data from a HTTP server, th |
| GHSA-3mh6-r7m6-r42x | csrf | — | — | none | См. CVE-2021-27927 (NVD/GHSA): In Zabbix before 4.0.28rc1, 5.x before 5.0.8rc1, 5.1.x and 5.2.x before 5.2.4rc |
| GHSA-3p5c-5fm7-qp72 | command-injection | — | — | user | См. CVE-2026-59787 (NVD/GHSA): The Perl SNMP trap receiver script shipped with Zabbix does not properly neutra |
| GHSA-3p6x-mw8p-qjh9 | xss | — | — | user | См. CVE-2022-24918 (NVD/GHSA): An authenticated user can create a link with reflected Javascript code inside i |
| GHSA-3q27-8g46-2vwm | other | — | — | user | См. CVE-2024-36461 (NVD/GHSA): Within Zabbix, users have the ability to directly modify memory pointers in the |
| GHSA-3r46-m7qj-9cf6 | xss | — | — | user | См. CVE-2023-29452 (NVD/GHSA): Currently, geomap configuration (Administration -> General -> Geographical maps |
| GHSA-3wch-5xm2-547f | rce | — | — | user | См. CVE-2024-22116 (NVD/GHSA): An administrator with restricted permissions can exploit the script execution f |
| GHSA-44qv-5wxp-8xqv | xss | — | — | user | См. CVE-2022-35229 (NVD/GHSA): An authenticated user can create a link with reflected Javascript code inside i |
| GHSA-4g73-3mxf-j47w | saml-sso-bypass | — | — | none | См. CVE-2022-23131 (NVD/GHSA): In the case of instances where the SAML SSO authentication is enabled (non-defa |
| GHSA-4mp5-p9jh-3rv5 | other | — | — | none | См. CVE-2026-23923 (NVD/GHSA): An unauthenticated attacker can exploit the Frontend 'validate' action to blind |
| GHSA-53rv-m76f-83xc | file-read | — | — | unknown | См. CVE-2011-3265 (NVD/GHSA): popup.php in Zabbix before 1.8.7 allows remote attackers to read the contents of |
| GHSA-5cpx-pcr7-g2xj | xss | — | — | unknown | См. CVE-2011-2904 (NVD/GHSA): Cross-site scripting (XSS) vulnerability in acknow.php in Zabbix before 1.8.6 al |
| GHSA-5j5m-c26m-fvc8 | auth-bypass | — | — | none | См. CVE-2026-23933 (NVD/GHSA): In Zabbix 7.4 the cryptographic key used for signing Frontend sessions has been |
| GHSA-5j69-6hhj-5x7f | information-disclosure | — | — | none | См. CVE-2013-7484 (NVD/GHSA): Zabbix before 5.0 represents passwords in the users table with unsalted MD5. |
| GHSA-5j8p-438x-rgg5 | saml-sso-bypass | 6.0.x < 6.0.44; 7.0.x < 7.0.23; 7.4.x < 7.4.7 | 6.0.45/7.0.24/7.4.8/8.0.0beta1 | none | Подделка SAML-ответа и обход SSO-аутентификации (получение доступа под произвольным пользователем), если атаку |
| GHSA-5q7w-vc8g-r5vx | other | — | — | admin | См. CVE-2023-29451 (NVD/GHSA): Specially crafted string can cause a buffer overrun in the JSON parser library  |
| GHSA-5xxv-j4hw-gp2p | file-read | — | — | none | См. CVE-2014-3005 (NVD/GHSA): XML external entity (XXE) vulnerability in Zabbix 1.8.x before 1.8.21rc1, 2.0.x  |
| GHSA-625f-58w6-wj9f | rce | — | — | admin | См. CVE-2024-22120 (NVD/GHSA): Zabbix server can perform command execution for configured scripts. After comma |
| GHSA-6cpc-423v-fx46 | other | — | — | user | См. CVE-2024-42329 (NVD/GHSA): The webdriver for the Browser object expects an error object to be initialized  |
| GHSA-6f4g-hm4f-cqp3 | xss | — | — | user | См. CVE-2022-35230 (NVD/GHSA): An authenticated user can create a link with reflected Javascript code inside i |
| GHSA-6f9x-gc6q-v2cg | xss | — | — | unknown | См. CVE-2010-2790 (NVD/GHSA): Multiple cross-site scripting (XSS) vulnerabilities in the formatQuery function  |
| GHSA-728r-qj99-48p2 | other | — | — | user | См. CVE-2025-49643 (NVD/GHSA): An authenticated Zabbix user (including Guest) is able to cause disproportionat |
| GHSA-734c-5898-qrph | privilege-escalation | — | — | none | См. CVE-2026-59781 (NVD/GHSA): When Zabbix Agent was installed on Windows into a custom installation directory |
| GHSA-7374-hfgm-rm8v | rce | — | — | none | См. CVE-2023-29453 (NVD/GHSA): Templates do not properly consider backticks (`) as Javascript string delimiter |
| GHSA-7734-ppwx-cfgh | information-disclosure | — | — | unknown | См. CVE-2011-3264 (NVD/GHSA): Zabbix before 1.8.6 allows remote attackers to obtain sensitive information via  |
| GHSA-79cm-2gxq-7x9r | xss | — | — | none | См. CVE-2020-15803 (NVD/GHSA): Zabbix before 3.0.32rc1, 4.x before 4.0.22rc1, 4.1.x through 4.4.x before 4.4.1 |
| GHSA-7q7m-r84j-6pm2 | other | — | — | none | См. CVE-2023-29449 (NVD/GHSA): JavaScript preprocessing, webhooks and global scripts can cause uncontrolled CP |
| GHSA-7rx9-h3cp-pvq7 | other | — | — | user | См. CVE-2023-29458 (NVD/GHSA): Duktape is an 3rd-party embeddable JavaScript engine, with a focus on portabili |
| GHSA-7w94-mp6m-pfq8 | information-disclosure | — | — | user | См. CVE-2024-36460 (NVD/GHSA): The front-end audit log allows viewing of unprotected plaintext passwords, wher |
| GHSA-87fp-835h-vrgc | xss | — | — | user | См. CVE-2022-24917 (NVD/GHSA): An authenticated user can create a link with reflected Javascript code inside i |
| GHSA-88jj-c4p9-959j | other | — | — | none | См. CVE-2026-23930 (NVD/GHSA): An unauthenticated user is able to cause disproportionate CPU load on the Front |
| GHSA-8h32-vcmm-pcx8 | rce | — | — | admin | См. CVE-2023-32727 (NVD/GHSA): An attacker who has the privilege to configure Zabbix items can use function ic |
| GHSA-8jg5-4gwh-7gh9 | other | — | — | unknown | См. CVE-2009-4500 (NVD/GHSA): The process_trap function in trapper/trapper.c in Zabbix Server before 1.6.6 all |
| GHSA-8jhf-8qjr-8c39 | other | — | — | unknown | См. CVE-2014-1685 (NVD/GHSA): The Frontend in Zabbix before 1.8.20rc2, 2.0.x before 2.0.11rc2, and 2.2.x befor |
| GHSA-8m2h-w74v-v385 | information-disclosure | — | — | user | См. CVE-2025-27238 (NVD/GHSA): Due to a bug in Zabbix API, the hostprototype.get method lists all host prototy |
| GHSA-8rh3-5c87-wh48 | information-disclosure | — | — | none | См. CVE-2019-15132 (NVD/GHSA): Zabbix through 4.4.0alpha1 allows User Enumeration. With login requests, it is  |
| GHSA-8vxw-wxwq-hg38 | other | — | — | user | См. CVE-2024-36463 (NVD/GHSA): The implementation of atob in "Zabbix JS" allows to create a string with arbitr |
| GHSA-8w6w-prh9-wr2j | information-disclosure | — | — | none | См. CVE-2024-36469 (NVD/GHSA): Execution time for an unsuccessful login differs when using a non-existing user |
| GHSA-8w8h-m7f2-m6c4 | other | — | — | none | См. CVE-2024-45700 (NVD/GHSA): Zabbix server is vulnerable to a DoS vulnerability due to uncontrolled resource |
| GHSA-8w8q-863g-6gx9 | other | — | — | user | См. CVE-2024-22119 (NVD/GHSA): The cause of vulnerability is improper validation of form input field “Name” on |
| GHSA-922w-vh7f-4cxh | other | — | — | user | См. CVE-2024-42326 (NVD/GHSA): There was discovered a use after free bug in browser.c in the es_browser_get_va |
| GHSA-98m4-j87f-4xfc | rce | — | — | unknown | См. CVE-2006-6692 (NVD/GHSA): Multiple format string vulnerabilities in zabbix before 20061006 allow attackers |
| GHSA-9947-j3mv-mffj | sql-injection | — | — | unknown | См. CVE-2011-4674 (NVD/GHSA): SQL injection vulnerability in popup.php in Zabbix 1.8.3 and 1.8.4, and possibly |
| GHSA-9g97-3vch-5xc2 | sql-injection | — | — | user | См. CVE-2024-36465 (NVD/GHSA): A low privilege (regular) Zabbix user with API access can use SQL injection vul |
| GHSA-9gfh-wppm-mm59 | xss | — | — | user | См. CVE-2023-32721 (NVD/GHSA): A stored XSS has been found in the Zabbix web application in the Maps element i |
| GHSA-9gr5-72qc-m8xc | information-disclosure | — | — | user | См. CVE-2026-23931 (NVD/GHSA): The frontend validatate.api.exists action can be exploited by authenticated use |
| GHSA-9mqw-qc3x-x476 | information-disclosure | — | — | user | См. CVE-2026-23937 (NVD/GHSA): The Zabbix API host.get action can be exploited by authenticated users to extra |
| GHSA-c26q-v9gv-jx6m | rce | — | — | none | См. CVE-2023-32728 (NVD/GHSA): The Zabbix Agent 2 item key smart.disk.get does not sanitize its parameters bef |
| GHSA-c3fc-hggh-m873 | other | — | — | unknown | См. CVE-2007-0640 (NVD/GHSA): Buffer overflow in ZABBIX before 1.1.5 has unknown impact and attack vectors rel |
| GHSA-c47p-v2q9-c4rg | information-disclosure | — | — | unknown | См. CVE-2013-5572 (NVD/GHSA): Zabbix 2.0.5 allows remote authenticated users to discover the LDAP bind passwor |
| GHSA-c4cc-x928-vjw9 | saml-sso-bypass | 6.0.x < 6.0.44; 7.0.x < 7.0.23; 7.4.x < 7.4.7 | 6.0.45/7.0.24/7.4.8/8.0.0beta1 | none | Обход проверки подписи/дайджеста XML (SAML Assertion), потенциально подделка SAML-ответа и обход SSO-аутентифи |
| GHSA-c945-v35p-v696 | information-disclosure | — | — | admin | См. CVE-2025-27231 (NVD/GHSA): The LDAP 'Bind password' value cannot be read after saving, but a Super Admin a |
| GHSA-cf7c-p4p5-gq5x | xss | — | — | user | См. CVE-2022-24919 (NVD/GHSA): An authenticated user can create a link with reflected Javascript code inside i |
| GHSA-cv5w-5v87-ffvf | rce | — | — | unknown | См. CVE-2020-11800 (NVD/GHSA): Zabbix Server 2.2.x and 3.0.x before 3.0.31, and 3.2 allows remote attackers to |
| GHSA-cv64-6j2c-f8cg | other | — | — | user | См. CVE-2026-23925 (NVD/GHSA): An authenticated Zabbix user (User role) with template/host write permissions i |
| GHSA-f832-gjrw-m8w5 | xss | — | — | unknown | См. CVE-2011-4615 (NVD/GHSA): Multiple cross-site scripting (XSS) vulnerabilities in Zabbix before 1.8.10 allo |
| GHSA-fc6r-7w85-4vgg | information-disclosure | — | — | user | См. CVE-2025-49641 (NVD/GHSA): A regular Zabbix user with no permission to the Monitoring -> Problems view is  |
| GHSA-fqr7-2x83-wf2r | other | — | — | none | См. CVE-2023-32726 (NVD/GHSA): The vulnerability is caused by improper check for check if RDLENGTH does not ov |
| GHSA-fvmr-q9wm-2vfr | rce | — | — | unknown | См. CVE-2013-6824 (NVD/GHSA): Zabbix before 1.8.19rc1, 2.0 before 2.0.10rc1, and 2.2 before 2.2.1rc1 allows re |
| GHSA-g47w-cvcq-qh23 | other | — | — | none | См. CVE-2023-32722 (NVD/GHSA): The zabbix/src/libs/zbxjson module is vulnerable to a buffer overflow when pars |
| GHSA-g5ff-j87h-3cwg | rce | — | — | unknown | См. CVE-2021-46088 (NVD/GHSA): Zabbix 4.0 LTS, 4.2, 4.4, and 5.0 LTS is vulnerable to Remote Code Execution (R |
| GHSA-g6qx-w624-hvrq | sql-injection | — | — | unknown | См. CVE-2010-1277 (NVD/GHSA): SQL injection vulnerability in the user.authenticate method in the API in Zabbix |
| GHSA-g86q-v527-5vcc | other | — | — | unknown | См. CVE-2012-6086 (NVD/GHSA): libs/zbxmedia/eztexting.c in Zabbix 1.8.x before 1.8.18rc1, 2.0.x before 2.0.8rc |
| GHSA-gm93-3f63-r64c | privilege-escalation | — | — | user | См. CVE-2025-49642 (NVD/GHSA): Library loading on AIX Zabbix Agent builds can be hijacked by local users with  |
| GHSA-gx59-7g62-6xhg | other | — | — | user | См. CVE-2024-42327 (NVD/GHSA): A non-admin user account on the Zabbix frontend with the default User role, or  |
| GHSA-gxx4-vhw8-8h73 | information-disclosure | — | — | none | См. CVE-2017-2826 (NVD/GHSA): An information disclosure vulnerability exists in the iConfig proxy request of Z |
| GHSA-h34r-wgpp-r3p4 | information-disclosure | — | — | user | См. CVE-2025-27236 (NVD/GHSA): A regular Zabbix user can search other users in their user group via Zabbix API |
| GHSA-h55g-ww3m-9hq9 | information-disclosure | — | — | admin | См. CVE-2026-23919 (NVD/GHSA): For performance reasons Zabbix Server/Proxy reuses JavaScript (Duktape) context |
| GHSA-h96q-8w2r-523f | other | — | — | none | См. CVE-2017-2825 (NVD/GHSA): In the trapper functionality of Zabbix Server 2.4.x, specifically crafted trappe |
| GHSA-hfrc-jq43-4m6c | file-read | — | — | user | См. CVE-2023-29450 (NVD/GHSA): JavaScript pre-processing can be used by the attacker to gain access to the fil |
| GHSA-hg5p-m73j-gf56 | file-read | — | — | unknown | См. CVE-2013-3738 (NVD/GHSA): A File Inclusion vulnerability exists in Zabbix 2.0.6 due to inadequate sanitiza |
| GHSA-hh74-wwvh-3g5f | rce | — | — | admin | См. CVE-2025-27233 (NVD/GHSA): Zabbix Agent 2 smartctl plugin does not properly sanitize smart.disk.get parame |
| GHSA-hh7f-cch9-52mr | other | — | — | none | См. CVE-2022-43515 (NVD/GHSA): Zabbix Frontend provides a feature that allows admins to maintain the installat |
| GHSA-hvm5-hr24-54m2 | other | — | — | unknown | См. CVE-2014-1682 (NVD/GHSA): The API in Zabbix before 1.8.20rc1, 2.0.x before 2.0.11rc1, and 2.2.x before 2.2 |
| GHSA-j24v-fg24-6mqq | sql-injection | — | — | user | См. CVE-2026-23921 (NVD/GHSA): A low privilege Zabbix user with API access can exploit a blind SQL injection v |
| GHSA-j62j-v7xw-jfcc | sql-injection | — | — | unknown | См. CVE-2010-5049 (NVD/GHSA): SQL injection vulnerability in events.php in Zabbix 1.8.1 and earlier allows rem |
| GHSA-j6fc-pvcg-2p4f | xss | — | — | user | См. CVE-2023-29454 (NVD/GHSA): Stored or persistent cross-site scripting (XSS) is a type of XSS where the atta |
| GHSA-j6gv-xg9q-8h4p | other | — | — | user | См. CVE-2026-23934 (NVD/GHSA): An authenticated user is able to cause disproportionate CPU load on the Fronten |
| GHSA-jfgr-r9xc-vhc8 | rce | — | — | unknown | См. CVE-2009-4498 (NVD/GHSA): The node_process_command function in Zabbix Server before 1.8 allows remote atta |
| GHSA-jm5w-96w4-8pcq | information-disclosure | — | — | admin | См. CVE-2024-42333 (NVD/GHSA): The researcher is showing that it is possible to leak a small amount of Zabbix  |
| GHSA-jmxh-h64m-45qp | other | — | — | none | См. CVE-2026-59786 (NVD/GHSA): Zabbix Server and Proxy accept the active agent heartbeat message regardless of |
| GHSA-m34r-jrv8-mwmv | command-injection | — | — | admin | См. CVE-2024-22122 (NVD/GHSA): Zabbix allows to configure SMS notifications. AT command injection occurs on "Z |
| GHSA-m4jh-qvf3-23v6 | other | — | — | unknown | См. CVE-2009-4501 (NVD/GHSA): The zbx_get_next_field function in libs/zbxcommon/str.c in Zabbix Server before  |
| GHSA-mmh3-p6qg-xhw2 | privilege-escalation | — | — | user | См. CVE-2024-22121 (NVD/GHSA): A non-admin user can change or remove important features within the Zabbix Agen |
| GHSA-mv97-qj5h-25f3 | other | — | — | none | См. CVE-2022-23134 (NVD/GHSA): After the initial setup process, some steps of setup.php file are reachable not |
| GHSA-p859-wc97-3523 | information-disclosure | — | — | user | См. CVE-2024-22114 (NVD/GHSA): User with no permission to any of the Hosts can access and view host count & ot |
| GHSA-pgwc-wgrf-gmj5 | other | — | — | admin | См. CVE-2024-36468 (NVD/GHSA): The reported vulnerability is a stack buffer overflow in the zbx_snmp_cache_han |
| GHSA-phjj-9p2g-26h9 | auth-bypass | — | — | none | См. CVE-2024-42332 (NVD/GHSA): The researcher is showing that due to the way the SNMP trap log is parsed, an a |
| GHSA-pphq-xpjc-vgqx | information-disclosure | — | — | user | См. CVE-2024-42325 (NVD/GHSA): Zabbix API user.get returns all users that share common group with the calling  |
| GHSA-pr2j-9fvv-cqvq | information-disclosure | — | — | user | См. CVE-2026-59785 (NVD/GHSA): Host search in Frontend allows filtering by fields that are not displayed, incl |
| GHSA-prmg-f2m8-74q7 | other | — | — | admin | См. CVE-2026-23938 (NVD/GHSA): An authenticated administrator is able to crash Zabbix server or proxy by creat |
| GHSA-pvp6-r25h-5wh3 | other | — | — | admin | См. CVE-2025-27240 (NVD/GHSA): A Zabbix adminitrator can inject arbitrary SQL during the autoremoval of hosts  |
| GHSA-q33m-pmcq-844x | sql-injection | — | — | none | См. CVE-2016-10134 (NVD/GHSA): SQL injection vulnerability in Zabbix before 2.2.14 and 3.0 before 3.0.4 allows |
| GHSA-q44w-9xjg-492g | file-read | — | — | admin | См. CVE-2025-27232 (NVD/GHSA): An authenticated Zabbix Super Admin can exploit the oauth.authorize action to r |
| GHSA-q4wv-f3rp-mjgr | other | — | — | admin | См. CVE-2024-42330 (NVD/GHSA): The HttpRequest object allows to get the HTTP headers from the server's respons |
| GHSA-q598-p9hw-59vj | other | — | — | admin | См. CVE-2023-29456 (NVD/GHSA): URL validation scheme receives input from a user and then parses it to identify |
| GHSA-q7cw-45fg-vx6f | other | — | — | none | См. CVE-2016-10742 (NVD/GHSA): Zabbix before 2.2.21rc1, 3.x before 3.0.13rc1, 3.1.x and 3.2.x before 3.2.10rc1 |
| GHSA-q7g5-2mg7-m2r3 | other | — | — | none | См. CVE-2024-36462 (NVD/GHSA): Uncontrolled resource consumption refers to a software vulnerability where a at |
| GHSA-q964-q8gh-7pcw | other | — | — | admin | См. CVE-2026-59788 (NVD/GHSA): The email media type OAuth form passes the Authorization endpoint value to wind |
| GHSA-qjqp-r6hf-xpqh | xss | — | — | admin | См. CVE-2026-23928 (NVD/GHSA): The Item history widget (in Zabbix 7.0+) or the Plain text widget (in Zabbix 6. |
| GHSA-qqcg-7f79-v65c | privilege-escalation | — | — | none | См. CVE-2022-23132 (NVD/GHSA): During Zabbix installation from RPM, DAC_OVERRIDE SELinux capability is in use  |
| GHSA-qvwc-px27-9hw9 | xss | — | — | user | См. CVE-2023-29455 (NVD/GHSA): Reflected XSS attacks, also known as non-persistent attacks, occur when a malic |
| GHSA-qxrq-fp7f-qqh5 | file-read | — | — | admin | См. CVE-2024-22123 (NVD/GHSA): Setting SMS media allows to set GSM modem file. Later this file is used as Linu |
| GHSA-r6r7-6w4q-hr3r | xss | — | — | unknown | См. CVE-2011-5027 (NVD/GHSA): Cross-site scripting (XSS) vulnerability in ZABBIX before 1.8.10 allows remote a |
| GHSA-r6x3-vwpm-5vwg | privilege-escalation | — | — | user | См. CVE-2025-27237 (NVD/GHSA): In Zabbix Agent and Agent 2 on Windows, the OpenSSL configuration file is loade |
| GHSA-r7ff-gv9g-75w3 | file-read | — | — | none | См. CVE-2022-46768 (NVD/GHSA): Arbitrary file read vulnerability exists in Zabbix Web Service Report Generatio |
| GHSA-r8x9-p5v6-vx46 | command-injection | — | — | admin | См. CVE-2026-23927 (NVD/GHSA): A user able to connect to Agent 2 can inject an Oracle TNS connection string vi |
| GHSA-rgf9-28hg-x4c8 | privilege-escalation | — | — | none | См. CVE-2022-22704 (NVD/GHSA): The zabbix-agent2 package before 5.4.9-r1 for Alpine Linux sometimes allows pri |
| GHSA-rj72-j8c2-fwx3 | other | — | — | admin | См. CVE-2024-36464 (NVD/GHSA): When exporting media types, the password is exported in the YAML in plain text. |
| GHSA-rq9v-pgww-544v | sql-injection | — | — | unknown | См. CVE-2014-9450 (NVD/GHSA): Multiple SQL injection vulnerabilities in chart_bar.php in the frontend in Zabbi |
| GHSA-rw3m-rqw9-p6rw | other | — | — | unknown | См. CVE-2007-6210 (NVD/GHSA): zabbix_agentd 1.1.4 in ZABBIX before 1.4.3 runs "UserParameter" scripts with gid |
| GHSA-v49g-5qr7-mhrh | rce | — | — | unknown | См. CVE-2006-6693 (NVD/GHSA): Multiple buffer overflows in zabbix before 20061006 allow attackers to cause a d |
| GHSA-v4vr-xhx7-pmfv | xss | — | — | user | См. CVE-2023-29457 (NVD/GHSA): Reflected XSS attacks, occur when a malicious script is reflected off a web app |
| GHSA-v6qg-5p9x-9hh9 | rce | — | — | unknown | См. CVE-2009-4502 (NVD/GHSA): The NET_TCP_LISTEN function in net.c in Zabbix Agent before 1.6.7, when running  |
| GHSA-v7c2-5wfc-rfff | other | — | — | admin | См. CVE-2026-23926 (NVD/GHSA): An authenticated (non-super) administrator can create a maintenance period with |
| GHSA-vm66-478p-4mqw | other | — | — | none | См. CVE-2026-1199 (NVD/GHSA): Zabbix API and Frontend login lockout mechanism has a flaw where several unsucce |
| GHSA-vmrp-q2j9-gmqr | other | — | — | admin | См. CVE-2024-22117 (NVD/GHSA): When a URL is added to the map element, it is recorded in the database with seq |
| GHSA-vq34-c5hg-7r26 | other | — | — | unknown | См. CVE-2013-1364 (NVD/GHSA): The user.login function in Zabbix before 1.8.16 and 2.x before 2.0.5rc1 allows r |
| GHSA-vv83-2f3m-pvxg | xss | — | — | user | См. CVE-2022-24349 (NVD/GHSA): An authenticated user can create a link with reflected XSS payload for actionsâ |
| GHSA-w279-xxqj-4mmw | rce | — | — | unknown | См. CVE-2013-3628 (NVD/GHSA): Zabbix 2.0.9 has an Arbitrary Command Execution Vulnerability |
| GHSA-w5wv-98xr-mhmx | other | — | — | user | См. CVE-2023-32724 (NVD/GHSA): Memory pointer is in a property of the Ducktape object. This leads to multiple  |
| GHSA-w8xh-986v-xwgh | sql-injection | — | — | unknown | См. CVE-2012-3435 (NVD/GHSA): SQL injection vulnerability in frontends/php/popup_bitem.php in Zabbix 1.8.15rc1 |
| GHSA-wcgg-mr8m-q73v | rce | — | — | none | См. CVE-2017-2824 (NVD/GHSA): An exploitable code execution vulnerability exists in the trapper command functi |
| GHSA-wg6x-hw9j-7vg6 | saml-sso-bypass | — | — | admin | См. CVE-2026-59782 (NVD/GHSA): The JavaScript preprocessing (Duktape) engine on Zabbix server has a vulnerabil |
| GHSA-wpfh-pv35-c3gc | other | — | — | none | См. CVE-2022-43516 (NVD/GHSA): A Firewall Rule which allows all incoming TCP connections to all programs from  |
| GHSA-wx93-p8qg-2gp4 | information-disclosure | — | — | admin | См. CVE-2026-23922 (NVD/GHSA): The email media OAuth field 'Client secret' cannot be read after saving, but a  |
| GHSA-x27p-fpr7-4wpm | xss | — | — | user | См. CVE-2026-23929 (NVD/GHSA): Prototype pollution vulnerability in searchParamsToObject() is leading to a per |
| GHSA-x47p-6vx5-8v99 | rce | — | — | admin | См. CVE-2025-27234 (NVD/GHSA): Zabbix Agent 2 smartctl plugin does not properly sanitize smart.disk.get parame |
| GHSA-x4g7-vjj9-57q3 | information-disclosure | — | — | none | См. CVE-2019-17382 (NVD/GHSA): An issue was discovered in zabbix.php?action=dashboard.view&dashboardid=1 in Za |
| GHSA-xc8w-x6qp-w4p7 | xss | — | — | user | См. CVE-2024-45699 (NVD/GHSA): The endpoint /zabbix.php?action=export.valuemaps suffers from a Cross-Site Scri |
| GHSA-xfvx-fm25-g3v4 | rce | — | — | admin | См. CVE-2026-23924 (NVD/GHSA): Zabbix Agent 2 Docker plugin does not properly sanitize the 'docker.container_i |
| GHSA-xhfh-28gq-v6jp | sql-injection | — | — | unknown | См. CVE-2009-4499 (NVD/GHSA): SQL injection vulnerability in the get_history_lastid function in the nodewatche |
| GHSA-xq5v-w2v7-hg7j | other | — | — | user | См. CVE-2024-42331 (NVD/GHSA): In the src/libs/zbxembed/browser.c file, the es_browser_ctor method retrieves a |
| GHSA-xwvj-c6cj-6xgw | privilege-escalation | — | — | none | См. CVE-2024-36467 (NVD/GHSA): An authenticated user with API access (e.g.: user with default User role), more |
| ZBA-2022-10-1 | other | 6.0.x < 6.0.8 | 6.0.9 (Solaris-сборки)/все пакеты ≥ 2022-11-01 | none | Переполнение буфера при обработке X.509 (X.509 Email Address 4-byte buffer overflow) — DoS, потенциально RCE;  |
| ZBX-10272 | other | 2.2.x < 2.2.21; 3.0.x < 3.0.13; 3.2.x < 3.2.10; 3.4.x < 3.4.4 | 2.2.21/3.0.13/3.2.10/3.4.4 | none | Фишинг: пользователь по ссылке на легитимный Zabbix попадает на внешний вредоносный сайт. |
| ZBX-10318 | csrf | 3.0.x < 3.0.2 | 3.0.2 | user | Модификация конфигурации экранов (вплоть до порчи данных мониторинга) у авторизованного пользователя без его в |
| ZBX-10319 | other | 2.2.x < 2.2.12; 2.4.x < 2.4.8; 3.0.x < 3.0.1 | 2.2.12/2.4.8/3.0.1 | user | Отказ в обслуживании веб-сервера фронтенда (высокая нагрузка CPU) при отправке специально сформированного запр |
| ZBX-10404 | information-disclosure | 3.0.x < 3.0.27; 4.0.x < 4.0.7; 4.2.x < 4.2.1 | 3.0.27/4.0.7/4.2.1/4.4.0alpha1 | admin | Раскрытие секрета (пароль SMTP/медиа) в HTML-коде страницы; риск при подглядывании за экраном, кэшах, логах пр |
| ZBX-10660 | privilege-escalation | 2.0.x < 5.0 | — | user | Каждый LDAP-пользователь получает права администратора — серьёзное ослабление модели прав при подключении внеш |
| ZBX-10741 | command-injection | 2.0.x < 2.0.18; 2.2.x < 2.2.13; 3.0.x < 3.0.3 | 2.0.18/2.2.13/3.0.3 | none | Исполнение произвольных команд ОС от имени процесса агента через ключ mysql.size[] при передаче параметров (то |
| ZBX-11483 | rce | 2.0.x < 2.0.20; 2.2.x < 2.2.16; 3.0.x < 3.0.6; 3.2.x < 3.2.2 | 2.0.20/2.2.16/3.0.6/3.2.2/3.4.0alpha1 | admin | Удалённое выполнение команд на сервере при наличии привилегий Admin. |
| ZBX-12768 | xss | 2.2.x < 2.2.20; 3.0.x < 3.0.11; 3.2.x < 3.2.8; 3.4.x < 3.4.2 | 2.2.20/3.0.11/3.2.8/3.4.2 | user | Выполнение произвольного JS в сессии жертвы (кража сессии, действия от имени администратора) при переходе на з |
| ZBX-12769 | xss | 2.2.x < 2.2.20; 3.0.x < 3.0.11; 3.2.x < 3.2.8; 3.4.x < 3.4.2 | 2.2.20/3.0.11/3.2.8/3.4.2 | user | Исполнение произвольного JS в сессии авторизованного пользователя (кража cookie, действия от его имени). |
| ZBX-13260 | information-disclosure | 3.0.x < 3.0.14; 3.2.x < 3.2.11; 3.4.x < 3.4.5 | 3.0.14/3.2.11/3.4.5 | none | Раскрытие конфиденциальной информации хостов (IP и пр.), доступной через глобальные скрипты; без авторизации. |
| ZBX-13261 | xss | 2.2.x < 2.2.21; 3.0.x < 3.0.14; 3.2.x < 3.2.11; 3.4.x < 3.4.5 | 2.2.21/3.0.14/3.2.11/3.4.5 | user | Исполнение произвольного JS в сессии пользователя при переходе по сформированной ссылке. |
| ZBX-13345 | csrf | 3.0.x < 3.0.15; 3.4.x < 3.4.7 | 3.0.15/3.4.7/4.0.0alpha3 | user | Выполнение привилегированных действий (создание пользователя и пр.) от имени жертвы без её ведома — фактически |
| ZBX-14336 | xss | 3.0.x < 3.0.17; 3.4.x < 3.4.9 | 3.0.17/3.4.9/4.0.0alpha6 | user | Хранимый XSS: исполнение JS в сессиях всех пользователей, открывающих IT-сервисы; плюс несанкционированное соз |
| ZBX-14337 | xss | 3.4.x < 3.4.9 | 3.4.9/4.0.0alpha6 | user | Исполнение JS при открытии дашборда с заражённым виджетом у всех пользователей. |
| ZBX-14975 | other | 3.4.x < 7.4 | — | user | Минимальный: пароли могут сохраняться менеджером паролей браузера на общих машинах. |
| ZBX-15708 | information-disclosure | 4.0.x < 4.0.7; 4.2.x < 4.2.1 | 4.0.7/4.2.1/4.4.0alpha1 | user | Хранение пароля пользователя в открытом виде в БД (поле passwd медиатипа) — раскрытие секрета при просмотре БД |
| ZBX-15870 | information-disclosure | 3.0.x < 3.0.27; 4.0.x < 4.0.7; 4.2.x < 4.2.1 | 3.0.27/4.0.7/4.2.1/4.4.0alpha1 | none | Раскрытие точной версии Zabbix неавторизованным — упрощает подбор эксплойтов по версии. |
| ZBX-16019 | command-injection | 3.0.x < 3.0.27; 4.0.x < 4.0.7; 4.2.x < 4.2.1 | 3.0.27/4.0.7/4.2.1/4.4.0alpha1 | admin | Исполнение произвольных команд ОС на сервере Zabbix при выполнении глобального скрипта (например, ping). |
| ZBX-16103 | other | 4.0.x < 4.0.11; 4.2.x < 4.2.5 | 4.0.11/4.2.5/4.4.0alpha1 | user | Защита от отказа в обслуживании сервера Zabbix через переполнение стека PCRE при препроцессинге. |
| ZBX-16750 | other | 3.0.x < 3.0.29; 4.0.x < 4.0.14; 4.2.x < 4.2.8; 4.4.x < 4.4.1 | 3.0.29/4.0.14/4.2.8/4.4.1/5.0.0alpha1 | none | Ослабление аутентификации компонентов: подключение недоверенного пира (например, поддельного агента/прокси) пр |
| ZBX-16765 | auth-bypass | 3.0.x < 5.2 | — | none | Неавторизованный доступ к данным/страницам, видимым guest-пользователю (system information, проблемы и т.п.).  |
| ZBX-16792 | information-disclosure | 5.0.x < 5.0 | — | none | Раскрытие паролей БД в логах контейнеров (риск при агрегации/хранении логов). |
| ZBX-17101 | xss | 3.0.x < 3.0.29; 4.0.x < 4.0.16; 4.4.x < 4.4.4 | 3.0.29/4.0.16/4.4.4/5.0.0alpha1 | user | Хранимый XSS в ключевых страницах мониторинга (проблемы, карты): исполнение JS в сессиях пользователей. |
| ZBX-17600 | rce | 3.0.x < 3.0.30; 3.2 (все); 2.2 >= 2.2.19 | 3.0.31 | none | Удалённое выполнение кода на Zabbix Server при доступе к trapper-порту. |
| ZBX-17742 | information-disclosure | 5.0.x < 6.4 | — | local | Утечка секретов (пароли БД, токены), используемых мониторингом, через логи агента на высокой детализации отлад |
| ZBX-17997 | information-disclosure | 5.0.x < 5.0.3; 5.2.x < 5.2.0alpha1 | 5.0.3/5.2.0alpha1 | user | Раскрытие паролей медиатипов (SMTP и др.) в журнале аудита и БД — при утечке логов/БД секреты в открытом виде. |
| ZBX-18057 | xss | 3.0.x < 3.0.32; 4.0.x < 4.0.22; 4.4.x < 4.4.10; 5.0.x < 5.0.2 | 3.0.32/4.0.22/4.4.10/5.0.2/5.2.0alpha1 | admin | Сторонняя страница в iframe без sandbox — риск XSS-вектора и фишинга в контексте Zabbix. |
| ZBX-18134 | information-disclosure | 5.0.x < 5.4 | 5.4.0alpha1 | admin | Раскрытие PSK-ключа администраторам, не имеющим права видеть его в Administration — снижение доверия TLS-PSK. |
| ZBX-18224 | privilege-escalation | 5.0.x < 5.2 | 5.4.0 | local | Локальное повышение привилегий до SYSTEM через подмену конфигурации OpenSSL/DLL (persistence, полный контроль  |
| ZBX-18884 | other | 4.0.x < 4.0.28; 5.0.x < 5.0.8; 5.2.x < 5.2.4 | 4.0.28/5.0.8/5.2.4/5.4.0alpha1 | user | Краш процесса сервера (DoS) / потенциально небезопасное переполнение стека при обработке длинного доменного им |
| ZBX-18942 | csrf | 4.0.x < 4.0.28; 5.0.x < 5.0.8; 5.2.x < 5.2.4 | 4.0.28/5.0.8/5.2.4/5.4.0alpha1 | none | CSRF: переконфигурация параметров аутентификации (например, отключение проверки/подмена настроек) в сессии адм |
| ZBX-19149 | rce | 4.0.x < 4.0.30; 5.0.x < 5.0.10; 5.2.x < 5.2.6 | 4.0.30/5.0.10/5.2.6/5.4.0beta1 | n/a | Потенциальное RCE при включённых сетевых компонентах logback (сериализация); стандартная конфигурация Zabbix и |
| ZBX-19150 | csrf | 4.0.x < 4.0.30; 5.0.x < 5.0.10; 5.2.x < 5.2.6 | 4.0.30/5.0.10/5.2.6/5.4.0beta2 | none | Устранение CSRF-векторов по всему фронтенду. |
| ZBX-19300 | xss | 4.0.x < 4.0.32; 5.0.x < 5.0.13; 5.2.x < 5.2.7; 5.4.x < 5.4.1 | 4.0.32/5.0.13/5.2.7/5.4.1/6.0.0alpha1 | user | Закрытие XSS-векторов самой jQuery во всех страницах фронтенда; до фикса уязвимые jQuery-функции могли быть ис |
| ZBX-20349 | other | — | — | none | Отсутствует (Java Gateway не использует log4j); запись для полноты картины по Log4Shell-инциденту 2021. |
| ZBX-20383 | rce | 2.0.x < 2.X; 3.0.x < 3.X; 4.0 4.0.0..4.0.36; 5.0.x < 5.0.18; 5.4 5.4.0..5.4.8; 6.0 6.0.0alpha1..6.0.0beta1 | 4.0.37/5.0.19/5.4.9/6.0.0beta2 | local | Загрузка и исполнение произвольного Java-кода с LDAP/HTTP при старте/перечитывании конфигурации Java Gateway — |
| ZBX-21376 | other | 6.0.x < 7.4 | — | user | Продление сессий после отзыва учётной записи во внешнем IdP (до 30 дней) — риск при увольнениях/отзыве прав. |
| ZBX-22589 | other | 4.4 4.4.4..4.4.*; 5.0.x < 5.0.31; 5.2 5.2.0alpha1..5.2.*; 5.4 5.4.0alpha1..5.4.*; 6.0 6.0.0alpha1..6.0.13; 6.2.x < 6.2.8; 6.4.x < 6.4.0rc1 | 5.0.32/6.0.14/6.2.8/6.4.0rc1/7.0.0alpha1 | user | Контролируемое расходование памяти/лога — потенциальный DoS со стороны пользователя с правами на конфигурацию. |
| ZBX-22718 | other | 6.0.x < 6.0.17; 6.4.x < 6.4.2 | 6.0.17/6.4.2/7.0.0alpha1 | user | Exhaustion памяти сервера — DoS. |
| ZBX-22719 | other | 6.0.x < 6.0.17; 6.4.x < 6.4.2 | 6.0.17/6.4.2/7.0.0alpha1 | admin | Зависание обработки элемента — локальный DoS (блокировка потока обработки данных). |
| ZBX-22720 | xss | 6.0.x < 6.0.17; 6.4.x < 6.4.2 | 6.0.18/6.4.2/7.0.0alpha1 | admin | Внедрение HTML (потенциальный XSS) в страницы геокарт администратором; устранено рендерингом как текст. |
| ZBX-22727 | other | 6.0.x < 6.0.18; 6.4.x < 6.4.2 | 6.0.18/6.4.2/7.0.0alpha1 | user | Краш процесса — отказ в обслуживании. |
| ZBX-24939 | other | 6.0.x < 7.4 | — | none | Операционное ослабление PKI (практики отключения проверки subject или использования общих сертификатов); не яв |
| ZBX-27819 | saml-sso-bypass | 6.0.x < 6.0.44; 7.0.x < 7.0.23; 7.4.x < 7.4.7 | 6.0.45/7.0.24/7.4.8/8.0.0beta1 | none | Обход SAML SSO (подделка аутентификации) при эксплуатации GHSA-5j8p-438x-rgg5. |

## Заметки и неоднозначности
- **id-пространство**: записи с id вида ZBX-* — тикеты трекера support.zabbix.com с меткой security; GHSA-* — GitHub Security Advisories (reviewed и unreviewed); два официальных адвайзери без собственного CVE получили id ZBA-2021-12-4 (оформлен как ZBX-20383, т.к. это его тикет) и ZBA-2022-10-1 (тикета ZBX с меткой security нет — отслеживался во внутреннем трекере ZBXSEC-128; это единственное отклонение от паттерна id GHSA-*/ZBX-*, сделано умышленно, чтобы не потерять реальный адвайзери).
- **CVE-связки**: у части ZBX-тикетов в названии есть CVE (ZBX-11483=CVE-2016-9140, ZBX-17600=CVE-2020-11800, ZBX-18057=CVE-2020-15803, ZBX-19149=CVE-2017-5929, ZBX-18942/ZBX-19150=CVE-2021-27927, ZBX-22589=CVE-2023-29449, ZBX-22720=CVE-2023-29452, ZBX-10741=CVE-2016-4338 — указан в комментарии). Они оставлены в этом наборе как ZBX-записи (id-домен ZBX-* не пересекается с CVE-доменом), детали CVE — в наборе CveResearch. GHSA с CVE-партнёром: id=GHSA-*, CVE указан в summary/notes (см. GHSA-c4cc-x928-vjw9→CVE-2025-66578; GHSA-5j8p-438x-rgg5 связан с CVE-2025-66475 через xmlseclibs).
- **affected_versions**: для большинства ZBX-тикетов точный уязвимый диапазон вендор не публикует — указан верхний порог по fix-версии ветки (максимум ЭКСКЛЮЗИВНЫЙ: уязвимы все версии ветки строго младше фикса; min='unknown'). Исключения с реальными диапазонами: ZBX-20383 (ZBA-2021-12-4, logback), ZBX-22589 (CVE-2023-29449), ZBX-17600 (CVE-2020-11800), ZBA-2022-10-1.
- **fixed_versions**: берутся из тикета (fixVersions + комментарии) и официального адвайзери; rc1-версии нормализованы до релизов (например 5.0.46rc1 → 5.0.46); где фикс шёл только в develop-ветку (например, ZBX-18134 → 5.4.0alpha1) — указана альфа.
- **Не подтверждено / без фикса**: ZBX-10660, ZBX-16765, ZBX-20349 (won't fix — поведение/не-уязвимость), ZBX-14975, ZBX-17742, ZBX-21376, ZBX-24939 (открыты/подтверждены или закрыты без фикса); для ZBX-16792 (docker-логи) версия фикса в тикете не указана; ZBX-22718/22719/22727 имеют скрытые описания («Hidden due to security reasons») — детали и принадлежность к CVE не подтверждены; ZBX-18224 исправлен только в 5.4 (для 3.0–5.2 лишь документация).
- **Исключено как не-уязвимости** (тикеты с меткой security, но документационные/процессные): ZBX-14549 (установочные инструкции https), ZBX-13372 (документация прав БД), ZBX-8464 (документация active proxies), ZBX-21514 (информация о ключах репозитория). Также исключены «not affected»-адвайзери ZBA-2022-03-1 (zlib), ZBA-2022-04-1 (Spring4Shell), ZBA-2022-07-1 (OpenSSL c_rehash) — информационные, в записи не превращены, упоминаются здесь.
- **Тикеты до 2016 года** (например, XSS/CSRF 2012–2015: ZBX-7091, ZBX-7479, ZBX-7693 и др.) из набора исключены по временному окну исследования (2016–2026).
- **GHSA (все записи)**: в наборе 143 записи GHSA (id GHSA-*) — это ВСЕ записи GitHub Advisory Database по Zabbix: 2 reviewed (php-saml GHSA-5j8p-438x-rgg5, xmlseclibs GHSA-c4cc-x928-vjw9) и 141 unreviewed (импорты CVE/NVD в GHSA-базу, включая бэкфилл 2022). Полный перечень получен grep-ом по локальному клону github/advisory-database (148 файлов упоминают zabbix; исключены 5 сторонних: Logstash GHSA-8qhq-rq4j-8prj, Grafana-Zabbix плагин GHSA-g4rr-88fc-26fj, Grafana-интеграция GHSA-97c5-jw9r-3fwj, MESILAT-плагин для Confluence GHSA-2c98-gcr8-fwj8, Nagios-визард GHSA-qp8f-9474-hr27). Каждая unreviewed-запись — связка GHSA↔CVE: уязвимые версии/фиксы указаны в CVE-записи (NVD) и официальном адвайзери Zabbix; severity — из GHSA (CVSS v3/v4, посчитан из вектора). Записи с CVE за 2006–2015 годы (Zabbix 1.x/2.0, EOL) включены для полноты, но в сканере актуальны только для очень старых инсталляций.
- **Проверка JSON**: research/advisory_records.json прогнан через `python3 -m json.tool` перед сдачей; дубликатов id нет (проверено скриптом). Итог: 190 записей (47 ZBX/ZBA/GHSA-reviewed-детальных + 143 GHSA-связки).
