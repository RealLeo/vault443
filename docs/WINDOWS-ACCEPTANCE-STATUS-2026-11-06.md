# Windows: консолидированный статус приёмки 6–7 ноября 2026

> **Стенд удалён по запросу пользователя 7 ноября 2026 после приёмки.**
> VM Windows 10, Windows 11 и вспомогательная Linux VM сняты с регистрации
> вместе с дисками и всеми снимками. Каталог `/var/www/projects/windows`,
> ISO, SDK, временные данные и отдельно перенесённый ISO-кэш Windows 11 удалены.
> Освобождено 158,23 ГиБ. Установщик R9, исходники и все отчёты сохранены в
> [готовом комплекте](../dist/windows/validated-2026-11-07-r9/); 11 файлов
> повторно проверены по SHA-256 после очистки.
> [Акт очистки](../dist/windows/environment-cleanup-20261107T151713Z.json).
> Указанные ниже OFF-снимки и пути VM описывают историческое состояние приёмки;
> восстановить их теперь нельзя. Для новых VM-проверок стенд нужно создать заново.

Приёмка согласованной Windows матрицы завершена **7 ноября 2026, 14:54:32 UTC
(17:54:32 МСК)**. Все три VM выключены. Текущий локальный R9 установщик готов
к передаче; приложение не подписано Authenticode, релиз не опубликован.
[Итоговый отчёт](WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md),
[all-VM OFF receipt](../dist/windows/vm-final-state-r9.json).

Последний Win11 offlink case11 PASS 14:48:48.035, exact Windows/Linux cleanup
подтверждён; post-main4 IPv4/IPv6 HTTP/DNS PASS.
[Native](../dist/windows/native-win11-r9/offlink-proof/20261107T144748340Z/result.json),
[post-main](../dist/windows/native-win11-r9/offlink-proof/r9-offlink-post-main.json).
[Packet proof](../dist/windows/native-win11-r9/r9-offlink-packet-analysis.json)
SHA `6e483874d22cae62d03195867329cea4fda536e7a036e049e6ca1b99b6322a82`:
unbound и ambiguity0, certain bound114out/37in; первый OUT 14:48:29.025096
на 7.60с позже latest binding CALL start. Observed clock envelope
[-0.4259517,+1.2179286]с, стабильный UTC не заявлен. Capture: 2461 persisted/
2474 received: 13 tail queued вне completed window, 0 kernel drops; это отражено
в ограничениях proof. Linux NAT token596cc535… cleanup=true, counter1/42.

Win11 final-state: OS 25H2/build 26200.6584, UEFI/SecureBoot1/TPMv2_0, noSDK,
ordinary GUI 8852/session1, LocalSystem 3448/Auto. Четыре main и шесть work профилей
сохранены, все VPN off/guardfalse, нет foreign fixture/offlink route/overlap IP.
[Final state](../dist/windows/native-win11-r9/final-state-after-offlink.json),
[GUI](../dist/windows/native-win11-r9/ordinary-gui-after-offlink.png).
Штатный guest shutdown /s /t0, без hardkill; OFF snapshot
`235e530f-fce4-4567-80c3-127e4d5a3a76`:
[receipt](../dist/windows/native-win11-r9/off-snapshot-final.json).
Win10 OFF snapshot `d4de2a10-95b9-4d9d-8444-49d4694bb32a`, Linux fixture OFF;
оба точных NFT test journals и owned tables отсутствовали перед выключением.
Предыдущие Win11 f4cac и R8failure checkpoints сохранены отдельно.

## Текущий R9

[Installer](../dist/windows/candidate-2026-11-07-r9/Vault443-1.3.4-windows-x64-setup.exe),208 435 592 байта,
SHA `f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d`;
manifest `3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a`;
source `9eb63b1cac9b7d1e8afba7fca8134058c2f855b6e5777679905ae76930ef8e9d`.
[Native build](../dist/windows/native-build-r9/result.json) gui/package PASS 13:15–13:17.
[Offline verification](../dist/windows/native-build-r9/offline-verification.json)
подтверждает полное совпадение 1765 payload records, 113 PE/8 production EXE и 295 runtime-source
файлов с R8. Изменён только ISS
`d14b22327f8d1971062dd176f9567f34c960c78b18b9d14a4f4f0913f2fc5138`;
SDK/QtCore/Go не пересобирались. Business/component proofs R8 связаны с точными
runtime hashes и сохраняют свои ограничения. Это не свежая полная R9/Win10
серия и не PASS старого R8 installer lifecycle.

## Новые installer проверки Win11 R9

| Проверка | Результат | Отчёт |
| --- | --- | --- |
| Первая установка без SDK |14 PASS 13:26:57; exact R9 source/manifest/runtime, профили сохранены, GUI запускается обычным пользователем. |[Install](../dist/windows/native-win11-r9/installer-proof/r9-entry/20261107T132617967Z/20261107T132619686Z-install.json), [GUI](../dist/windows/native-win11-r9/ordinary-gui-first-install.png) |
| Безопасный отказ при заблокированном UI |11 PASS 13:31:22. Приостановлен только UI thread, finally Resume; намеренный Restart Manager graceful shutdown failure, без Kill/force. Те же SCM, все 15 profile IDs и 1768 имён app files сохранены. |[Safe abort](../dist/windows/native-win11-r9/installer-proof/r9-gui-close-abort/20261107T133050879Z/result.json) |
| Обычное удаление с открытым GUI и reinstall |14 PASS 13:32:48. Исходный GUI 4300/creation 13:27:59 подтверждён удерживаемым handle и закрыт самим uninstaller. Child uninstall14: 0 файлов приложения/routes/DNS/WFP, включая owned containers; точные IDs сохранены. Foreign NRPT пережил uninstall/reinstall, затем exact QA cleanup. |[Lifecycle](../dist/windows/native-win11-r9/installer-proof/r9-lifecycle/20261107T133207708Z/result.json), [uninstall14](../dist/windows/native-win11-r9/installer-proof/r9-lifecycle/20261107T133207708Z/uninstall/20261107T133215697Z-uninstall.json), [reinstall14](../dist/windows/native-win11-r9/installer-proof/r9-lifecycle/20261107T133207708Z/install/20261107T133225924Z-install.json), [GUI после](../dist/windows/native-win11-r9/ordinary-gui-after-reinstall.png) |

Win11 R9 штатно выключена 13:36:15, final checkpoint
`f4cac319-69b6-4f3f-ab58-8836b1c103c3`:
[final state](../dist/windows/native-win11-r9/final-state.json).
R9 builder сохранён OFF как `096ddfd6-f49e-4f72-8761-ce200e31dcef`.
Win10 завершила R9/noSDK проверки и выключена: checkpoint d4de2a10,
[OFF receipt](../dist/windows/native-win10-r9/off-snapshot.json). Исходная e4cc ветка
сохранена. Win11 offlink и exact cleanup завершены; current OFF snapshot 235e530f.
Прежний R9 LC checkpoint f4cac сохранён.

## Свежие проверки Windows 10 R9

| Проверка | Подтверждённый результат | Отчёт |
| --- | --- | --- |
| Upgrade и core | Upgrade 14 PASS 13:40:28, без SDK. Fresh core complete/PASS 14:02:16.704: main 139, physical DNS6 UDP/TCP positives, recovery 23 и VLESS+три work с реальным IPv4/IPv6/DNS. |[Upgrade](../dist/windows/native-win10-r9/core-proof/r9-entry/20261107T134006631Z/20261107T134007041Z-upgrade.json), [core](../dist/windows/native-win10-r9/core-proof/r9-core/result.json), [main 139](../dist/windows/native-win10-r9/core-proof/main/20261107T140015595Z-all-vless.json) |
| Шесть engine-family faults | Все шесть новых случаев по 15 PASS, final restore PASS 14:11:20. Xray VLESS/Trojan/SS, настоящий Outline helper, WG multi и AWG. Exact OpenVPN 15 — отдельный ранее завершённый Win10 R8 proof при идентичном runtime, без повторного нового claim. |[Matrix](../dist/windows/native-win10-r9/engine-proof/engine-matrix/20261107T140438342Z-result.json) |
| Реальная смена IP/DNS | Physical IPv4/IPv6 .2→.3 и DNS4→DNS6: changed 22 PASS 14:12:26; exact finally restore PASS 14:16:02.745, restored 22 PASS 14:16:45.992. |[Master](../dist/windows/native-win10-r9/network-ui-proof/r8-network-change-change-20261107T141602745Z.json), [changed 22](../dist/windows/native-win10-r9/network-ui-proof/network-change/20261107T141226140Z-changed.json), [restored 22](../dist/windows/native-win10-r9/network-ui-proof/network-change/20261107T141646015Z-restored.json) |
| Native picker и продуктовый UAC | Existing private OVPN→Already added→Cancel без commit. Boot On→Off→On через настоящий vault443-access UAC; final On PASS с теми же IDs, SCM 1932/creation 13:40:22.769415 и trafficSession 1794060527651907500-11. |[Picker](../dist/windows/native-win10-r9/native-file-picker.png), [preview](../dist/windows/native-win10-r9/native-file-preview-existing.png), [UI result](../dist/windows/native-win10-r9/network-ui-proof/r9-ui-result.json), [final On](../dist/windows/native-win10-r9/product-uac-boot-final-on.png) |

Win10 R9 tail: partial baseline 29/blocked 29/recovered 29 PASS;
[host report](../dist/windows/native-win10-r9/partial/r8-partial-host-20261107T141859Z.json)
complete 14:23:44.649, exact token-owned DROP cleanup=true/errors 0: 20 пакетов/3520 байт.
Удаление DROP выполнено 14:23:08.944, затем завершилась recovered проверка.
External dual11 PASS 14:24:53.103, IPv6-only11 PASS 14:25:56.098; exact Windows
service/adapter/binding cleanup прошёл, afterstop2 PASS 14:27:30 включает main22
с автоматическим VLESS resume без RequestConnect.
[Dual](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142451867Z-dual.json),
[v6only](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142553329Z-v6only.json),
[afterstop](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142712351Z-afterstop.json).
Overlap baseline/run14/rulesRestored PASS, owned secondary IP точно удалён,
recovered6 PASS 14:31:03.706:
[run](../dist/windows/native-win10-r9/tail-proof/r8-overlap/20261107T142858318Z-run.json),
[recovered](../dist/windows/native-win10-r9/tail-proof/r8-overlap/20261107T143020673Z-recovered.json).

Новый offlink external test на Win10 **функционально11 PASS 14:32:58.545**:
точный endpoint 93.184.215.14:1194, свой physical host route metric444,
тот же fixture SCM до/после binding. Unbound window 14:32:16.798–14:32:37.900,
bound window 14:32:37.965–14:32:53.103. Windows service/adapter/binding/route
очищены, Linux token967bd… DNAT точно удалён 14:33:45.739; счётчик1packet/42bytes
подтверждает попадание нового flow, а не полный объём трафика.
[Proof archive](../dist/windows/native-win10-r9/offlink-export.zip),
[ownership/cleanup](../dist/windows/native-win10-r9/offlink-owner.json),
[QA provenance](../dist/windows/native-win10-r9/controllers/r9-external-offlink-provenance.json).
Win10 R9 inbound PASS: baseline 8/8, после guard arm LAN 4 positive/offlink 4 negative,
pre-existing offlink TCP4/6 без reply payload. [Analysis](../dist/windows/native-win10-r9/inbound/r9-inbound-analysis.json)
acceptancePassed=true; четыре QA firewall rules/binding точно удалены 14:38:24.979:
[cleanup](../dist/windows/native-win10-r9/installer-proof/inbound-cleanup-20261107T143824990Z.json).

Win10 R9 hung-GUI safe-abort11 PASS 14:39:48.574; live-GUI lifecycle14 PASS
14:41:18.131, включая child uninstall14/reinstall14, закрытие исходного GUI 388
самим uninstaller, сохранение точных SID/profile IDs и чужого NRPT, затем exact
QA cleanup. [Safe abort](../dist/windows/native-win10-r9/installer-proof/r9-gui-close-abort/20261107T143920716Z/result.json),
[lifecycle](../dist/windows/native-win10-r9/installer-proof/r9-lifecycle/20261107T144046093Z/result.json).
Ordinary GUI 6544/session1 после reinstall:
[PNG](../dist/windows/native-win10-r9/ordinary-gui-after-reinstall.png).
[Final state](../dist/windows/native-win10-r9/final-state.json): OS 19045/noSDK,
LocalSystem 7112/Auto, четыре own main и пять work сохранены, все VPN off,
guardfalse, нет offlink route/external service/adapter/overlap IP.

Post-offlink main22 PASS 14:34:10.749:
[verify](../dist/windows/native-win10-r9/clock-final-main-proof/20261107T143353875Z-verify-vless.json).
Capture 5507/N0 controlled stop 14:35:14.496, 14185 frames/no kernel drops.
[Main packet proof](../dist/windows/native-win10-r9/r9-win10-packet-analysis.json)
SCOPED_ZERO_COUNTS_CLOCK_INTERVAL_CHANGE_QUALIFIED,
SHA `d1f3bb3ec99dfc4df5f816ea43e287b68f372ab7e2d6eb739534f45de698d4b2`.
[Offlink packet proof](../dist/windows/native-win10-r9/r9-offlink-packet-analysis.json)
SCOPED_UNBOUND_DENY_BOUND_ALLOW_CONFIRMED__CLOCK_VARIATION_QUALIFIED,
SHA `ff1d92e4f141a151201badfe59d2733a5cec8b26a004ad752dfe5b8b47a65a23`:
unbound0 включая expanded edges; certain bound113out/23in, первый OUT
14:32:47.704861 более 8.25с после latest possible binding.
Clock variation учтена консервативным union [-0.6450152,+1.4826]с и точными
DNS ID/ports causal calibration. Стабильный UTC не заявлен; первоначальный
неуспешный clock-interval анализ сохранён.
[Provenance/limits](../dist/windows/native-win10-r9/packet-proof-provenance.json).

Win10 штатно выключена через guest shutdown.exe; OFF checkpoint `d4de2a10-95b9-4d9d-8444-49d4694bb32a` подтверждён 14:45:07 [receipt](../dist/windows/native-win10-r9/off-snapshot.json).
Win11 offlink native/packet/cleanup и финальное выключение завершены; новых незакрытых native пунктов нет.

## R8 component evidence и сохранённый installer failure

Установщик [R8](../dist/windows/candidate-2026-11-07-r8/) содержит 208 434 238 байт,
SHA-256 `12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e`.
Манифест `bc6692d6939e0798de19465963e24de765eb84938b33866e4e295ea5bba65f19`,
исходники `957c7399aef10e067e593b66120a5cf9a67476ee446b19734e3bd7848e2d35c2`,
daemon `4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50`.
[Нативная упаковка](../dist/windows/native-build-r8/result.json),
[проверка артефактов](../dist/windows/native-build-r8/offline-verification.json),
[Windows unit tests OpenVPN](../dist/windows/r8-openvpn-native-unit.json) и
[Linux Go suite](../dist/windows/linux-regression-r8.json) прошли.

## Подтверждено на Windows 10 для R8

Проверки выполнены на чистой Windows 10 Enterprise Evaluation 22H2 без SDK.
Результаты ниже относятся к установленному R8, а не к отдельно заменённому daemon.

| Проверка | Результат и границы | Отчёт |
| --- | --- | --- |
| Обновление, UAC, служба, профили |14 PASS, 09:24:57. Сохранены пять основных и пять рабочих профилей всех пользователей, существующий qa2 и его пароль. |[Upgrade](../dist/windows/native-win10-r8/interactive-upgrade/20261107T092433241Z-upgrade.json) |
| Основной и три рабочих VPN | Реальный VLESS и WG multi/AWG/OpenVPN: IPv4/IPv6, DNS и совместная работа; main recovery 23 PASS. Полные рабочие туннели: 10 шагов PASS, исходное состояние восстановлено. |[Main recovery](../dist/windows/native-win10-r8/main/20261107T092836433Z-recovery-vless.json), [full work](../dist/windows/native-win10-r8/full-work/result.json) |
| Конфликт маршрутов и ручной выбор VPN/DNS |16 проверок/9 шагов PASS, восстановление подтверждено. Новые соединения через OpenVPN4/6 и последующий возврат WireGuard подтверждены пакетами. |[Route case](../dist/windows/native-win10-r8/route-conflict/result.json), [packet proof](../dist/windows/native-win10-r8/r8-openvpn-packet-analysis.json) |
| Сбой OpenVPN, службы и сетевого адаптера | Точный OpenVPN child4988 завершён, новый1656 восстановил трафик без RequestConnect; daemon604 не менялся, 15 PASS. SCM stop/crash и NIC down/up: 10 шагов/11 проверок PASS, состояние восстановлено. |[OpenVPN fault](../dist/windows/native-win10-r8/engine-faults/20261107T094931748Z-openvpn-vless.json), [service faults](../dist/windows/native-win10-r8/service-faults/result.json) |
| IPC и два пользователя | IPC admission 25 PASS. Существующий обычный qa2 вошёл в отдельный сеанс: reuse 53 PASS без импорта, сброса пароля и очистки store. Возврат владельца 4 PASS; основной профиль, guard, trafficSessionId и daemon2836 сохранились. |[IPC](../dist/windows/native-win10-r8/ipc/ipc-security-20261107T093940863Z.json), [qa2](../dist/windows/native-win10-r8/user2/20261107T103935607Z-reuse.json), [owner return](../dist/windows/native-win10-r8/owner-continuity/user1-return/20261107T104830416Z-capture.json) |
| Интерфейс | Шесть случаев EN/RU при реальном масштабе Windows 100/150/200% PASS; трей, скрытие/повторное открытие и файлы проверены, шесть снимков осмотрены root. |[UI controller](../dist/windows/native-win10-r8/ui/controller-result.json), [снимки](../dist/windows/native-win10-r8/ui/) |
| Перезагрузка и автозапуск | Pre-SCM 13 PASS при работающем BFE; временная задача удалена, Automatic восстановлен. Boot1 и отдельный обычный boot2 подтвердили службу, GUI, main и три work с реальным IPv4/IPv6/DNS без ручного подключения/старта. Boot2 завершён10:05:43; отчёт экспортирован после восстановления host IPC. Это не независимое доказательство защиты до BFE. |[Pre-SCM](../dist/windows/native-win10-r8/boot/prescm/result.json), [boot1](../dist/windows/native-win10-r8/boot/boot1-verify.json), [boot2](../dist/windows/native-win10-r8/boot/boot2-verify.json), [boot packet proof](../dist/windows/native-win10-r8/boot/r8-boot-packet-analysis.json) |
| Чужой WFP-фильтр и отказ удаления |9 PASS: точный чужой GUID сохранился до/после uninstall exit1; служба, десять profile IDs и 1768 имён файлов приложения сохранены. Затем проверенный QA helper удалил только свой тестовый GUID. Явное отключение завершено: main/work disconnected, guardfalse. Обычное удаление и повторная установка ещё не пройдены. |[Uninstall abort](../dist/windows/native-win10-r8/foreign-abort/r8-foreign-abort/result.json), [чистое отключение](../dist/windows/native-win10-r8/off-preflight-clean.json) |

На Win10 R8 пакетные проверки дали 0 прямых пакетов по восьми классам в 15 окнах main
и в проверенных boot-окнах. Положительные контроли взяты из отдельных серий R7,
включая два новых физических DNS6-запроса. Это ограниченные доказательства с
указанными окнами, а не завершённая матрица утечек для всех отказов и протоколов.
Историческая причина OpenVPN metadata-before-auth остаётся недоказанной;
успешное восстановление R8 подтверждено указанным реальным crash-сценарием.

## Подтверждено на Windows 11 для R8

Тот же установщик обновил Windows 11 Enterprise Evaluation 25H2 без SDK.
Результаты перечислены в таблице: обычное удаление завершилось FAIL, остальные
указанные сценарии имеют свои PASS и границы. Шесть снимков UI дополнительно
подтверждают реальные масштабы Windows, русский и английский интерфейс.

| Проверка | Результат и границы | Отчёт |
| --- | --- | --- |
| Обновление, UAC и профили |14 PASS, завершено 11:00:30; точные R8 installer/manifest/backend, noSDK. |[Upgrade](../dist/windows/native-win11-r8/upgrade/interactive-r8/20261107T105946627Z-upgrade.json), [entry](../dist/windows/native-win11-r8/upgrade/interactive-r8-entry.json) |
| Протоколы, импорты и подписки | Main 139 PASS для VLESS/Trojan/Shadowsocks/Outline; два свежих физических DNS6 positive controls PASS. Затем три рабочих VPN с реальным IPv4/IPv6/DNS и основной VLESS. |[Main all](../dist/windows/native-win11-r8/integration/20261107T110300240Z-all-vless.json), [DNS6](../dist/windows/native-win11-r8/integration/r8-dns6-positive.json), [integration](../dist/windows/native-win11-r8/integration/r8-win11-integration-batch.json) |
| Полные рабочие туннели и конфликт маршрутов | Full-work 10 шагов PASS, route 16 проверок/9 шагов PASS, оба сценария восстановили исходное состояние. |[Full work](../dist/windows/native-win11-r8/integration/full-work/result.json), [route](../dist/windows/native-win11-r8/integration/r8-route-conflict/result.json), [work controller](../dist/windows/native-win11-r8/integration/openvpn-recovery/result.json) |
| IPC, сбой службы, адаптера и OpenVPN | IPC 25 PASS; SCM/NIC 10 шагов/11 проверок PASS с восстановлением; точный OpenVPN child crash/recovery 15 PASS. |[IPC](../dist/windows/native-win11-r8/fault-ui/ipc/ipc-security-20261107T111735252Z.json), [service faults](../dist/windows/native-win11-r8/fault-ui/service-faults/result.json), [OpenVPN fault](../dist/windows/native-win11-r8/fault-ui/engine-faults/20261107T112244399Z-openvpn-vless.json) |
| Шесть случаев интерфейса |EN/RU при реальном 100/150/200% PASS, закрытие/повторный запуск; root осмотрел все шесть status PNG. |[UI](../dist/windows/native-win11-r8/fault-ui/ui/controller-result.json), [visual review](../dist/windows/native-win11-r8/fault-ui/ui/root-visual-review.json) |
| Нативный picker, трей и продуктовый UAC | Реальный Windows file picker открыл существующий private fixture, duplicate preview показал Already added, Cancel вернул окно без commit; значок трея виден. Выключение/включение boot profile через продуктовый UAC сохранило active profile и один trafficSessionId. Это проверка изменения настройки, не boot/reboot proof. |[Manual receipt](../dist/windows/native-win11-r8/native-ui-manual.json), [picker](../dist/windows/native-win11-r8/native-file-picker.png), [tray](../dist/windows/native-win11-r8/native-tray.png), [boot off](../dist/windows/native-win11-r8/integration/r8-gui-boot-off.json), [boot on](../dist/windows/native-win11-r8/integration/r8-gui-boot-on.json), [UAC off](../dist/windows/native-win11-r8/native-app-uac-off.png), [UAC on](../dist/windows/native-win11-r8/native-app-uac-on.png) |
| Реальная смена IP/DNS | Changed 22 и restored 22 PASS. UAC master подтвердил точный возврат исходных адресов и DNS; ordinary verify подтвердил основной и три work VPN без ручного RequestConnect. Первые QA ошибки DNS-family setters сохранены отдельно и не считаются PASS. |[Exact restore](../dist/windows/native-win11-r8/network-change/r8-network-change-change-20261107T114017930Z.json), [changed traffic](../dist/windows/native-win11-r8/network-change/network-change/20261107T113706150Z-changed.json), [restored traffic](../dist/windows/native-win11-r8/network-change/network-change/20261107T114100361Z-restored.json) |
| Остальные шесть engine-family faults | Шесть случаев завершены PASS, исходное состояние восстановлено: Xray для VLESS/Trojan/SS, настоящий Outline helper, WireGuard multi и AmneziaWG. OpenVPN проверен отдельно. PrefixV в прежней fixture позволил проверить именно Outline helper; продукт не изменялся. |[Engine matrix](../dist/windows/native-win11-r8/core-through-engines/r8-outputs/engine-matrix/20261107T115419999Z-result.json) |
| Два пользователя | Существующий обычный qa2 reuse 55 PASS; возврат владельца 4 PASS с сохранением servicePID, creationUTC, active profile и trafficSessionId. Пароль и чужие профили не менялись. |[qa2](../dist/windows/native-win11-r8/user2/20261107T114744345Z-reuse.json), [owner return](../dist/windows/native-win11-r8/owner-continuity/user1-return/20261107T115009631Z-capture.json) |
| Частичный отказ WireGuard peer | Baseline 29/blocked 29/recovered 29 PASS, завершено 12:42:20. Token-owned DROP только нужного peer: 22 пакета/3872 байта, cleanup=true/errors 0; тот же SCM 3312, без Connect/Reset. |[Host metadata](../dist/windows/native-win11-r8/r8-outputs/partial/r8-partial-host-20261107T123738Z.json) |
| Внешний OpenVPN | Dual 11 PASS 12:43:51 и IPv6-only 11 PASS 12:45:19. Exact cleanup 12:46:22: service/adapter/binding отсутствуют. Afterstop 2 PASS 12:46:45 включает main verify 22 с автоматическим восстановлением без RequestConnect. Builtin OpenVPN выключался перед setup из-за общего сертификата и восстановлен отдельно после proof. LAN endpoint не доказывает offlink exception. |[Dual](../dist/windows/native-win11-r8/external/r8-external/20261107T124350046Z-dual.json), [v6only](../dist/windows/native-win11-r8/external/r8-external/20261107T124517834Z-v6only.json), [cleanup](../dist/windows/native-win11-r8/external/r8-external-cleanup.json), [afterstop](../dist/windows/native-win11-r8/external/r8-external/20261107T124626015Z-afterstop.json) |
| IPv4 prefix overlap | Run 14 PASS/rulesRestored=true; точное удаление своего secondary IPv4/25 без изменения gateway; recovered 6 PASS 12:50:45.227. Это connected IPv4 case, не реальный Docker/HNS/NAT или IPv6 overlap. |[Run](../dist/windows/native-win11-r8/overlap/r8-overlap/20261107T124812216Z-run.json), [remove](../dist/windows/native-win11-r8/overlap/r8-overlap-remove-20261107T124942002Z.json), [recovered](../dist/windows/native-win11-r8/overlap/r8-overlap/20261107T124945215Z-recovered.json) |
| Чужой WFP и отказ удаления |13 PASS: точный чужой GUID пережил faults/boots и ожидаемый uninstall exit1; профили и файлы сохранены. Проверенный helper затем удалил только свой тестовый GUID. |[Foreign abort](../dist/windows/native-win11-r8/foreign-abort/r8-foreign-abort/result.json) |
| Inbound и pre-existing TCP | PASS в 329-frame capture: baseline 8/8; после arm LAN 4 positive/offlink 4 negative, pre-existing offlink TCP4/6 без ответного payload. Ровно четыре QA firewall rules и binding удалены. |[Analysis](../dist/windows/native-win11-r8/inbound/r8-inbound-analysis.json), [exact cleanup](../dist/windows/native-win11-r8/inbound/inbound-cleanup-20261107T125728813Z.json) |
| Обычное удаление с открытым GUI | **FAIL 13:05:25**: exit0/servicegone и 5 main+6 work профилей сохранены, но GUI 8756/session1 и 37 manifest-owned GUI/Qt/MSVC файлов остались. `file in use (5)`, `NeedRestartWindows? No`. Finally exact NRPT remove PASS; обычная повторная установка не выполнялась. |[Lifecycle result](../dist/windows/native-win11-r8/lifecycle-failure/r8-lifecycle/20261107T130512934Z/result.json), [uninstall report](../dist/windows/native-win11-r8/lifecycle-failure/r8-lifecycle/20261107T130512934Z/uninstall/20261107T130520463Z-uninstall.json) |

Пакетный [Win11 core proof](../dist/windows/native-win11-r8/r8-win11-packet-analysis.json)
покрывает 38 main-окон и семь engine-kill окон, включая настоящий Outline helper:
восемь direct classes 0, все восемь свежих positives в том же capture. Изменённые
и восстановленные physical IP подтверждены внешним зашифрованным трафиком.
Это scoped proof; inbound и ранний boot им не объявляются пройденными.

Win11 boot1: native pre-SCM 13 PASS/restored/taskRemoved, затем обычный main+три
work+GUI и реальный трафик PASS 12:14:56. [Boot1 packet proof](../dist/windows/native-win11-r8/boot1/r8-boot-packet-analysis.json)
остаётся ограниченным post-BFE/pre-Vault443 доказательством.

**Обычный boot2, попытка 2, PASS 12:35:32.778**. Запрос 12:33:46.140,
фактический boot 12:33:59.500; main recovery 23, три work VPN с реальным
IPv4/IPv6/DNS и GUI 8756/session1 восстановились без RequestConnect/ручного
StartService: [native report](../dist/windows/native-win11-r8/boot2/r8-boot2-verify.json),
[request](../dist/windows/native-win11-r8/boot2/r8-boot2-request.json).
Повторная QA привязка ifIndex 13→12 проверила прежние GUID/MAC/IPbytes; исходный
positive baseline 11:03 сохранён. Capture 4376/inv7f6… завершён; [tail packet proof](../dist/windows/native-win11-r8/r8-win11-tail-packet-analysis.json)
SHA7130476c…5c7ebe закрывает scoped normalboot2/partial/external/recovered windows
с отдельными outbound positives. Inbound подтверждён своим 329-frame capture.

Первая попытка normal reboot осталась отдельным неуспехом. Windows записала
ShutdownEnd 12:18:54 после 9.558с, затем Restarting и host Reset/SaveState зависли.
После сохранения [диагностики](../dist/windows/native-win11-r8/boot2-shutdown-delay/windows-shutdown-diagnostic.json)
и [incident receipt](../dist/windows/native-win11-r8/boot2-shutdown-delay/incident.json)
точный frontend остановлен 12:29:16; выполнен coldboot того же текущего VDI без
snapshot rollback. Причина неизвестна. Успешный повтор не стирает этот исход и не
доказывает полное устранение его причины.

R8 normal-uninstall failure выше сохранён как реальный FAIL. Его failure
checkpoint `7c3fab13-34b2-4b8e-969e-582f37be2d72` остаётся отдельно от нового R9
checkpoint. R9 исправление подтверждено новыми installer tests, а совпадение всех
113 PE и 1765 payload records позволяет связать прежние component proofs с тем же
runtime. Согласованная матрица Win10/Win11 завершена; итоговый статус
подтверждает [acceptance receipt](../dist/windows/validated-2026-11-07-r9/acceptance-manifest.json).

## Завершение

Все согласованные native строки выполнены с указанными identity и scope.
Остаётся только передача validated delivery с отдельным acceptance receipt,
report и evidence; installer/source/build-manifest bytes не меняются.
Замороженный candidate artifact-manifest с build-time acceptance=pending не
переписывается. Authenticode-подпись и публикация релиза не запрошены.

Ранее R7 Win10 прошёл external dual 11/IPv6-only 11, cleanup/auto-resume и два
physical DNS6 positive controls; это отдельное evidence R7. Дальше сохранена
история с исходными candidate identities. Старые пометки pending/stop ниже
относятся к соответствующему срезу и не заменяют текущий блок.

«Подтверждено» ниже означает только названный сценарий на указанной сборке.
Успех старого кандидата или отдельно заменённого daemon не переносится на другой
установщик. Ранние development-отчёты без backend SHA обозначены отдельно.

## Идентичность сборок

| Обозначение | Установщик / назначение | SHA-256 daemon `vault443d.exe` |
|---|---|---|
| R1 | [candidate-2026-11-06](../dist/windows/candidate-2026-11-06/artifact-manifest.json), 211703672 байта; installer SHA `dbfb068f6b6194483d0218ffa10d2be448eb8d0773abd9519b24c552e1c062bd` | `1a63e4ce93a5b5245e61cdd469b9077ea2a48006889a20eacbd0ffd8add2db3e` |
| R2 | [candidate-2026-11-06-r2](../dist/windows/candidate-2026-11-06-r2/artifact-manifest.json), 211719547 байт; installer SHA `83e34933b985a4fffcb23ca3aed3460ebfcffe78d85ebc9bfb823f263741aaef` | `3b68bfb4459b212187f8e38280a7a912a7aab6b006c099dcd36a2621ffe6f04d` |
| R3 | [candidate-2026-11-06-r3](../dist/windows/candidate-2026-11-06-r3/artifact-manifest.json), 208426967 байт, предыдущий кандидат; installer SHA `af592ded2a9d85404ff3a225504f1e73c4dd1a068de9df8f76a834756b837b6d` | `bc9792b81d882797aa2d88bf366b6d529829d11201fb9e5a91940e44dc1f9024` |
| R4 | [candidate-2026-11-06-r4](../dist/windows/candidate-2026-11-06-r4/artifact-manifest.json), 208438592 байта; installer SHA `ae5d8b7ddcbee4ad928522fb0e0ac009a313d6dab6f52f062f0c17c352309cf3`; Win10 upgrade 14 PASS, main 129 PASS | `b07bbf991fd214c4aa36aaee4b149d1215e8127a4bc14f7064b4249f45fa9497` |
| R5 | [candidate-2026-11-06-r5](../dist/windows/candidate-2026-11-06-r5/artifact-manifest.json), 208432077 байт; installer SHA `8076f589071e96b98e9fa0296abb925240f97866116062d8bef4202d0c4e7939`; Win10 coherent upgrade14/main139 и clean install14 PASS | `d33316230114627b483261317974f989f1358cde37c5f6c092daa8bd653b607b` |
| R6 | [candidate-2026-11-06-r6](../dist/windows/candidate-2026-11-06-r6/artifact-manifest.json), 208434301 байт; installer SHA `0cd92b64b464b7b429be85691ba2fac0008f72fb673c6d53642872f703e5a3cb`; clean Win10 interactive upgrade14 PASS | `9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25` |
| R7 | [candidate-2026-11-07-r7](../dist/windows/candidate-2026-11-07-r7/artifact-manifest.json),208453006bytes; installer SHA `491085f2d124fcaf2c1e047f15e9764f8b07c7b7fbc064892c1d52b2a0359f5d`; clean Win10 upgrade14/main139/coexist22 и fresh route16 PASS, остальная матрица pending | `2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6` |
| R8 | [candidate-2026-11-07-r8](../dist/windows/candidate-2026-11-07-r8/artifact-manifest.json),208434238bytes; installer SHA `12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e`; clean Win10 interactive upgrade14 PASS09:24:57, main/work integration pending | `4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50` |
| D13 | Старый отдельно установленный Win10 development backend; доказательство дефекта inbound guard | `13d18e1d4da68c37fb6112b92710ebe15c0e3ae3c96a27433be02a3355b5b059` |
| Dde30 | Recovery fix, диагностический SYSTEM `--console`, **не упакован** | `de30b2610e91f306b292e8049658315210113a6b2f0f890eb5251fba6a61515f` |
| D247 | Recovery fix + private `debug.SetCrashOutput`, диагностический SCM daemon с воспроизведённым WFP crash | `2475983d058fbdaf8315b5cbb3ae5fceb22abbe76101b76bcb894d760e18ebc0` |
| Dc077 | WFP allocator alignment + union ABI fix; отдельно установленный Win10 SCM daemon, на нём выполнен after-fix wire proof | `c077627ff35fbaf283b6fa0a06190f4ea26f4081647018de871d7046df84ac26` |
| Df569 | Отдельно заменённые daemon + helper `29d0ce8d54c2b400d947a0f9b1eb1a1d7e5734330995bd71ca69a7dc387cc73a`; work DNS identity fix, смешанный runtime поверх R4 | `f569f8fc864c4b64dde88aec791a6a8a4d3a70f3c247b1dc5e44ccb6762ac39a` |
| De58 | Development WFP foreign ownership fix, отдельно установлен на Win10 в 16:17 UTC; **не упакован**, native foreign/abort PASS16:29:55; SCM startup stability pending | `e58c5ebef22b5587baf148bb5ac119b15f4e277fe9b52154318507a9311add85` |
| Dd333 | Отдельный Win10 daemon с private startup logging fix; native SCM stop/start и forced crash/recovery PASS, не coherent installer | `d33316230114627b483261317974f989f1358cde37c5f6c092daa8bd653b607b` |
| Dfd31 | Отдельный clean Win10 daemon с private cleanup diagnostics; установлена точная ошибка прежнего порядка очистки | `fd31ee4726324e7ecd269202d176743a96e9173b8931c95381c7484094efc35c` |
| D9ced | Отдельный clean Win10 daemon с WG cleanup order fix; два cleanup цикла и WG helper crash/recovery PASS до упаковки R6 | `9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25` |

Artifact manifest R1–R8 содержат `acceptance: pending`, `signed: false`,
`published: false`. В предыдущем срезе фактические SHA установщика, build-manifest и
source.zip R1–R3 совпали с соответствующими artifact manifest.
Для R4 manifest/source идентичности дополнительно подтверждены native upgrade.
Source SHA: R1 `ef82326ae0bd390dc824ae40991708e5b8ac61d8fceadc76f319e5461c849633`,
R2 `fe7f68384fd4b39672bc9a98151e60b83869b966684f61e84a59e21c901f3980`.
R3 source SHA `98a64e26ccd4897493cc8dab197dc58927f21b7e2a4c8d2a795df9eccbcdb64b`,
build-manifest SHA `b65dda56aac9ae8a992098206e0703857dd14908d67e0e01179082a5d11dc7ce`.
R3 включает WFP/recovery/crash-output fixes и чтение собственного Boot UID;
QA test EXE исключены из runtime stage. Его ранний upgrade не закрывает последующие
исправления восстановления source routes. R4 включает их: source SHA
`18dbea68101ed87a8e99d4548f1cffc21d7ba45bdb0e19dc27fc8c120830a6d7`,
build-manifest SHA `2abefae2bd92ebf728cb01329f3abfc6b762f4ad48958eff2bbdb6ced48eac8b`.
Df569/De58 не являются coherent installer-кандидатами; их результаты не переносятся
на R4. De58: [host build/license checkpoint](../build-windows/prepackage-2026-11-06/wfp-foreign-ownership-checkpoint.json).
R6 source stage и offline checks PASS: source SHA
`07043a2d106bfc9a783858ed2a4a0f63c82cb6bc5753eda0db2b53b6b5efd1f2`,
build-manifest SHA `392faa05130ab32278b4d64cec0f51e452fc947f412b1841fcfa517dc2766ee7`.
SHA256SUMS/artifact manifest, пять backend PE, GUI53bc, официальный Wintun,
Qt/QML/CRT и patch/source provenance совпали; 1765 payload files, QA EXE отсутствуют.
Последующее обновление этого отчёта после source freeze не меняет идентичности R1–R6
и само по себе не требует новой упаковки.

Payload manifest R1–R5 фиксируют Qt 6.12.0, MSVC 2022 17.14.44 и SDK 10.0.26100;
QtCore с официальным QtBase patch имеет SHA
`01052b89dc4de0fddaf96d8445b2c711e89a8038ac6439124d7314eb192579ee`,
GUI — `53bc41422de5c1940a3e486c7d5a6442a2074d94fc22f8d33cfef91e5eb140df`.
Поставляются x64 Qt/QML/CRT, подписанный Wintun, движки, лицензии и исходники.
Повторная Inno упаковка неизменного R2 stage дала одинаковый installer SHA:
[repro-result.txt](../dist/windows/native-win10/repro-result.txt).
Полная побитовая пересборка из чистого toolchain не сравнивалась.

## Экспортированный checkpoint R7

- [Upgrade14](../dist/windows/native-win10-r7/interactive-upgrade/) на clean
  Win10/noSDK: all-SID profiles retained, existing qa2/password не менялись.
  [Main/work](../dist/windows/native-win10-r7/r7-protocols/):139+22 PASS.
- [Fresh route-case](../dist/windows/native-win10-r7/route-conflict-fresh/result.json):
  complete16checks/9steps PASS/restored=true. [Packet analysis](../dist/windows/native-win10-r7/r7-route-fresh-packet-analysis.json)
  подтверждает новые OVPN IPv4/IPv6 соединения и возврат WG;0physical в8classes.
  Это scoped route proof; full DNS6-positive baseline остаётся пробелом.
- [Attempt1](../dist/windows/native-win10-r7/route-conflict-attempt1/result.json)
  RPC unknown/timeout и [attempt2](../dist/windows/native-win10-r7/route-conflict-attempt2/observed-final-state.json)
  pooling HTTP/failed restore сохранены. Metadata-before-auth/name-in-use потребовали
  explicit stop+SCM restart; успешный fresh-case не стирает эти исходы и не доказывает auth fix.
- Отдельные [SCM stopped protection13](../dist/windows/native-win10-r7/r7-protocols/main/20261106T231532874Z-protection-vless.json)
  и [recovery23](../dist/windows/native-win10-r7/r7-protocols/main/20261106T231727715Z-recovery-vless.json)
  PASS; capture/metadata экспортированы, whole fault packet validation не заявлена.
- Overlap финал pending до экспорта; R7 Win11, lifecycle/foreign cleanup и остальная
  матрица впереди. Рефлексия23:21, следующий контроль23:51.

## Что подтверждено на каждой Windows

Windows10 — Enterprise Evaluation 22H2; после штатного обновления build 19045.6456.
Windows11 — Enterprise Evaluation 25H2, build 26200. Ранние Win10 R4/Df569 и R5 upgrade/main выполнены в builder VM.
Отдельный clean Win10 build19045.2006 без SDK прошёл install14; остальной clean
lifecycle ещё не завершён. Win11 первоначально получил R1 на `clean-os` без
MSVC/Qt SDK; затем обновлён тем же R6, upgrade14 PASS19:47:39, noSDK=true. Обе VM имеют 4 vCPU, 6 GiB RAM, 80 GiB disk;
для Win11 подготовлены UEFI/Secure Boot/TPM2. Конфигурация и снимки описаны в
хронологии, а не перепроверялись обращением к VirtualBox при этом аудите.

| Сценарий | Windows10: доказанное и граница | Windows11: доказанное и граница | Сохранённое evidence |
|---|---|---|---|
| Установка, UAC, SCM, приватное хранение | **R6 interactive upgrade14 PASS19:08:46**, session1/exit0, noSDK=true,22runtime hashes и4main+3work сохранены; SYSTEM/session0 попытка FAIL5/Session Mismatch → rollback. **R5 coherent upgrade14 PASS17:08**; затем тот же SHA на clean19045.2006 безSDK: UAC/install14 PASS17:25:40, ordinary GetSnapshot SUCCESS после grant-console. `guiProbeSkipped=true`: GUI этим не проверен | **R6 interactive upgrade14 PASS19:47:39**, exact source07043/manifest392faa/daemon9ced,22runtime hashes, Wintun Valid,4main+4work retained, noSDK=true. Ранний R1 clean install остаётся историческим evidence | [R6 interactive upgrade](../dist/windows/native-win10-clean/r6-interactive-upgrade-result.json), [session0 failure](../dist/windows/native-win10-clean/r6-upgrade-error.json), [R5 clean install](../dist/windows/native-win10-clean/install-result.txt); [Win11 R6 upgrade](../dist/windows/native-win11-r6/upgrade-result.json) |
| Удаление и сохранение профилей | Полный uninstall/cleanup пока не выполнен | Upgrade/uninstall пока не выполнены | Готов `tests/windows/installer-smoke.ps1`; наличие harness не считается результатом |
| VLESS / Trojan / Shadowsocks / динамический Outline | **R6 clean Win10 main 139/139 PASS**, 19:11:13–19:12:38: HTTPS/UDP4/6, DNS, импорты/подписки/переключения и 13 physical checks. Затем VLESS reconnect и verify 22 PASS при трёх work VPN. Полная matching pcap/fault matrix не закрыта | **R6 clean Win11 main139 PASS**, затем три work VPN/coexistence main verify22 PASS. Pcap: пять verify окон, все8 direct classes0, positive baseline8/8; это не fault/boot coverage | [R6 protocol reports](../dist/windows/native-win10-clean/r6-protocols/); [Win11 R6 main](../dist/windows/native-win11-r6/r6-protocols/), [main pcap analysis](../dist/windows/native-win11-r6/r6-main-pcap-analysis.json) |
| Импорт, переключения, подписка | Включены в **R6 main all 139 PASS** на clean Win10. Fault/reboot и весь lifecycle остаются отдельно | Включены в **R6 main all139 PASS**; отдельная fault/boot matrix не подменяется этим результатом | [R6 main all](../dist/windows/native-win10-clean/r6-protocols/main/20261106T191113316Z-all-vless.json); [Win11 main-all](../dist/windows/native-win11-r6/r6-protocols/main/20261106T195306918Z-all-vless.json) |
| R2 main и новый default DNS | **R2 Outline**: источник HTTPS/UDP обоих семейств и все A/AAAA UDP/TCP подтверждены. Полный verify остановился на устаревшем IPv6 link-local baseline: 11 успешных проверок из 13 записей. Baseline затем обновлён: 7 успешных. Это исторический неполный R2; повтор R4 main all уже PASS | R2 и D247 не установлены; DNS R1 работал без production NRPT | [R2 verify details](../dist/windows/native-win10/r2-outline-verify-details.json), [R2 IPC/диагностика PID](../dist/windows/native-win10/r2-service-restart-diagnostic.txt), хронология R2 |
| WireGuard / AmneziaWG | **R6 clean Win10 PASS**: реальные WG multi и AWG, handshake, HTTP IPv4/IPv6 и split DNS; одновременно с main и OpenVPN. Полная fault/full-tunnel матрица ещё не закрыта | **R6 real WG multi/AWG PASS**, HTTP IPv4/IPv6 и split DNS; connected вместе с main и OpenVPN, main coexistence verify22 PASS | [R6 WG multi](../dist/windows/native-win10-clean/r6-protocols/wireguard-multi.txt), [R6 AWG](../dist/windows/native-win10-clean/r6-protocols/amneziawg.txt); [Win11 work/coexistence](../dist/windows/native-win11-r6/r6-protocols/) |
| OpenVPN | **R6 clean Win10 PASS**: реальный OpenVPN, HTTP IPv4/IPv6 и split DNS, одновременно с main/WG multi/AWG; main verify 22 PASS. Full tunnel и вся fault matrix pending | **R6 real OpenVPN PASS**, HTTP IPv4/IPv6 и split DNS; coexistence с main/WG multi/AWG. Full-work сценарий10 PASS отдельно | [R6 OpenVPN](../dist/windows/native-win10-clean/r6-protocols/openvpn.txt), [coexistence result](../dist/windows/native-win10-clean/r6-protocols/result.json); [Win11 OpenVPN](../dist/windows/native-win11-r6/r6-protocols/) |
| Full work + main pause | **R6 clean Win10 10/10 PASS**, 19:33:41–19:35:41, restored=true: full WireGuard и OpenVPN, HTTP IPv4/IPv6, main paused_external/guard=true, после disconnect main resume/verify и восстановление исходных split VPN. Остальные route/fault комбинации не закрыты | **R6 full WG/OpenVPN10 PASS**, 19:57:01–20:00:19, restored=true: IPv4/IPv6, main pause/guard, disconnect/resume/verify и возврат исходных split VPN | [R6 full-work result](../dist/windows/native-win10-clean/r6-full-work/result.json); [Win11 full-work](../dist/windows/native-win11-r6/r6-full-work/result.json) |
| Partial WireGuard peers | **Df569 functional PASS**: partial16:15:47 — healthy44 HTTP IPv4/IPv6 работает, failed46 заблокирован; main/AWG/OpenVPN connected, guard=true. Recovery16:16:33 — оба пира connected, все четыре HTTP-пробы PASS. Стенд peer3 IPv6/source ACL/FIB исправлен без production изменений. Pcap IPv4-only (`host 192.0.2.2`), полная leak acceptance ещё pending | **R6 Win11 baseline/blocked/recovered по29 PASS**, noConnectOrAppChanges=true, exact fixture DROP21:39:26→21:43:11 снят,21packets/3696bytes, cleanup=true. Healthy peer продолжает4/6/DNS, failed peer blocked, recovery автоматическое. Scoped pcap PASS: оба captures IPv4-only при unfiltered argv, fresh physical IPv6 baseline отсутствует | [partial](../dist/windows/native-win10/multi-peer-partial-check.json), [recovery](../dist/windows/native-win10/multi-peer-recovery-check.txt); `/tmp/vault443-multi-partial.pcap` не покрывает IPv6/DNS; [R6 partial host](../dist/windows/native-win11-r6/r6-partial-host-20261106T213915Z.json), [scoped analysis](../dist/windows/native-win11-r6/r6-partial-pcap-analysis.json), [capture provenance](../dist/windows/native-win11-r6/r6-partial-capture-provenance.json) |
| Default DNS причина / NRPT | На D13/development A/B/A: TCP 10057 до правила, A/AAAA TCP/UDP работают с временным loopback NRPT, TCP снова падает после удаления. R2 production NRPT DNS работает в сценарии выше; конфликты/crash/uninstall ещё не проверены | **R1**: baseline/NRPT/after-removal, 12 DNS запросов успешны, cleanup подтверждён. `hypothesisSupported=false` означает отсутствие исходного TCP-дефекта на Win11, а не падение DNS | [Win10 ordinary A/B/A](../dist/windows/native-win10/ordinary-nrpt-after.txt), [Win11 NRPT](../dist/windows/native-win11/qa-reports/20261106T105241024Z-nrpt.json) |
| Outbound guard, отдельный pcap | Ранний Outline: protection 11 проверок; 45 секунд / 27 пакетов только к разрешённому внешнему TCP 192.0.2.1:8388, прямых тестовых TCP/UDP4/6 и LAN DNS нет. Это **один сценарий**, не вся матрица отказов | **R6 main pcap PASS scope**:5262frames,0truncated, five verify windows ×8classes,0direct packets. Fault capture9250frames/0truncated/0direct во всей последовательности и20временных окнах; ограничения SCM crash/link-down сохранены ниже | [Win10 pcap/analysis](../dist/windows/native-win10/guard-outline-analysis.json), [protection report](../dist/windows/native-win10/main-results/20261106T093322725Z-protection-outline.json); [main analysis](../dist/windows/native-win11-r6/r6-main-pcap-analysis.json), [fault analysis](../dist/windows/native-win11-r6/r6-faults-pcap-analysis.json) |
| Inbound guard / существующие TCP flows | **D13 дефект доказан**: после arm 92 off-link reply payload packets. R2 after-fix capture не засчитан из-за connect failure. **Dc077/PID1948 after-fix PASS**: 203 пакета, baseline8/8, четыре LAN positives, все четыре off-link попытки; **ноль off-link ответов**, включая уже открытые TCP IPv4/IPv6. `acceptancePassed=true` относится только к этому сценарию | Исправленный inbound guard ещё не проверен | [before-fix](../dist/windows/native-win10/inbound-before-fix-analysis.json), [after-fix analysis](../dist/windows/native-win10/inbound-c077-analysis.json), [after-fix pcap](../dist/windows/native-win10/inbound-c077.pcap) |
| IPC framing/auth/server DACL/admission | **R6 clean Win10 25 PASS**, включая admission; это отдельная проверка от двухпользовательского owner return | **R6 IPC/admission25 PASS**, ordinary console user; двухпользовательская матрица Win11 остаётся отдельно | [R6 IPC/admission](../dist/windows/native-win10-clean/r6-ipc/ipc-security-20261106T191438578Z.json); [Win11 IPC25](../dist/windows/native-win11-r6/r6-ipc/ipc-security-20261106T200222557Z.json) |
| Reconnect / аварии / SCM | R2 SCM7031 PID4052→3216; D247 после трёх успешных циклов также упал, PID1088→4804. Причина воспроизведённого crash установлена source/stack: `wf.toFilter0` → Go bulk barrier, невыровненный allocator. **Dc077 после after-fix capture** прошёл ещё три SCM disconnect/connect с неизменным PID1948. Это не полная fault/reboot матрица и не установленный R3 | **R6 SCM stop/start/crash и NIC down/up10 steps+11checks PASS**, restored=true: protection13, recovery23 и real verify трёх work VPN. Xray PID980 crash/recovery PASS20:11:39. Only explicit SCM stop monitored through probes; crash negatives не доказывают engine-down throughout | [R2 7031](../dist/windows/native-win10/r2-service-restart-diagnostic.txt), [полный D247 stack](../dist/windows/native-win10/scm-247-full-crash-stack.json), [Dc077 3 цикла](../dist/windows/native-win10/scm-c077-reconnect-cycles.txt); [SCM/NIC sequence](../dist/windows/native-win11-r6/r6-service-faults/result.json), [Xray fault](../dist/windows/native-win11-r6/r6-xray-fault/result.json) |
| Явное отключение / cleanup | Ранний checkpoint: guard выключен, owned routes отсутствуют, DNS восстановлен. Поздний Win10 disconnect также зафиксирован; uninstall WFP/NRPT cleanup ещё не доказан | **R1** main disconnect подтверждён, перед сохранением запрошено отключение work; OpenVPN disconnected. Это не uninstall cleanup | [ранний checkpoint](WINDOWS-PORT-CHECKPOINT-2026-11-06.md), [Win10 disconnect](../dist/windows/native-win10/main-results/20261106T094510455Z-disconnect-vless.json), [Win11 checkpoint](../dist/windows/native-win11/disconnect-checkpoint.txt) |
| WG cleanup order / helper crash | **D9ced clean Win10 PASS**: два цикла трёх work VPN, disconnect8326/8753ms, затем0managed routes/work adapters/NRPT. Реальный crash WG helper PID3312 при daemon5744 — автоматическое восстановление двух пиров, HTTP4/6 и split DNS PASS. Это ещё не coherent R6 installer/fault matrix | Актуальный fix ещё не установлен | [cleanup cycles](../dist/windows/native-win10-clean/cleanup-order-regression.json), [helper recovery](../dist/windows/native-win10-clean/helper-fault-recovery.txt) |
| Реальный UI и масштаб ОС | Native **stage GUI**, ordinary session: EN100 и RU100/150/200, Qt factor1; DPI144/192 при150/200, screenshots. RU close/reopen/Ctrl+Q с живым VPN наблюдались. Это builder stage, не clean installed UI всего сценария | **R6 installed Win11 EN/RU ×100/150/200 PASS**, actual HWND DPI96/144/192, QtFactor1/AppScale0.5, active VPN preserved, close/reopen/single-instance/quit и screenshots. EN150 завершён вручную тем же harness20:36:59 после QA Settings HWND recreation; remaining4 controller-r2 PASS20:42:02. RU200 visual status192/PNG20:47. Native OpenVPN picker→already-added preview→Cancel и настоящий tray context/close-hide/icon-reopen PASS; GUI7308/creation/VPN прежние | [Win10 RU100](../dist/windows/native-win10/ui-ru-build100.txt), [150](../dist/windows/native-win10/os-scale150.txt), [200](../dist/windows/native-win10/os-scale200.txt), [Win11 UI/scale](../dist/windows/native-win11/ui-results-saved); [R6 Win11 UI reports/screens](../dist/windows/native-win11-r6/r6-ui/); [native picker/tray report+3PNG](../dist/windows/native-win11-r6/r6-file-dialog/) |
| Native Qt suite | Свежий native EN/RU: каждый 57 passed, 0 failed, 15 Linux D-Bus skips. Старый RU failure LANGUAGE не учитывать как текущий результат после исправления Windows expectation | Отдельный native Qt suite на Win11 не выполнен | [EN](../dist/windows/native-win10/ui-native-en-r2.txt), [RU](../dist/windows/native-win10/ui-native-ru-r2.txt) |
| WFP ABI / allocator | Независимый MSVC SDK probe и два native Go теста ABI/alignment PASS. Reviewed fork/provenance включены в R3 | Отдельный native прогон не выполнен | [SDK ABI](../dist/windows/native-win10/wfp-sdk-abi.txt), [Go ABI/alignment](../dist/windows/native-win10/wf-abi-alignment-tests.txt) |
| Собственный Boot UID readback | Исправлено скрытие собственного BootProfileID от ordinary клиента. Три focused service теста PASS, полный service suite после fix — 4.144s PASS. Native чтение/UAC/boot сценарий R3 ещё впереди | **R6 ordinary BootProfileID readback и normal automatic boot PASS**: boot20:56:20, main connected/guard, recovery23 и три work VPN; no manual connect/service start. Pre-BFE enforcement отдельно не изолирован | [service после readback fix](../dist/windows/linux-service-boot-readback.txt); R3 backend; [normal boot](../dist/windows/native-win11-r6/r6-normal-boot-after.json) |
| WFP boot/ownership inspector | **De58 foreign/uninstall-abort PASS16:29:55**: чужой filter E76B… сохранён после restart и abort exit1; service, 1769 files и 9 profiles retained; exact QA cleanup PASS. Provider ServiceName пуст, enabled, disabled=0. Это не SCM stability и не early boot proof | **R6 post-BFE/pre-Vault44313 PASS** после реального reboot:41 sampled PID0/engines0/SCMStopped/BFERunning facts, physical up/globals/gateways. Pcap direct8classes0, ND/ARP присутствуют. Pre-BFE proof и foreign/uninstall на Win11 ещё не закрыты | [combined native result](../dist/windows/native-win10/wfp-ownership-native-result.txt); [boot attempt2](../dist/windows/native-win11-r6/r6-boot-attempt2/result.json), [boot pcap analysis](../dist/windows/native-win11-r6/r6-boot2-pcap-analysis.json) |
| Два пользователя / неавторизованный admin | **R6 clean Win10**: vaultqa2 unauthorized9 PASS, после явного UAC grant isolated34 PASS; owner return19:33:40 —4 PASS, exact PID/creation time/traffic session сохранены | **R6 Win11 PASS**: active-console user2 unauthorized9, после явного grant isolated34; возврат owner в21:16 —4 PASS с тем же PID3436/creation time/traffic session. Own import и deny foreign logs/diagnostics/connect/disconnect подтверждены | [R6 user2](../dist/windows/native-win10-clean/user2-r6/), [owner return](../dist/windows/native-win10-clean/user1-r6-return/20261106T193340427Z-capture.json); [Win11 user2](../dist/windows/native-win11-r6/user2-r6/), [Win11 owner return](../dist/windows/native-win11-r6/user1-r6-return/20261106T211612342Z-capture.json) |
| Linux regression после WFP / Boot fixes | **R6-compatible source07043 PASS**: pinned Go1.27.3, GOPROXY=off, go test -mod=readonly ./... ровно один раз, 19:55:38–19:55:44, exit0; используется допустимый Go test cache. 231 Go/mod/sum файл совпал с архивом. Прежний Qt EN/RU2/2 PASS сохранён отдельно | Не относится к Windows11 | [R6 Linux log](../dist/windows/linux-regression-r6.txt), [run identity](../dist/windows/linux-regression-r6.json) |

## Блокеры и обязательный остаток полного плана

1. **Завершить актуальную регрессию подтверждённого WFP исправления.**
   D247 повторно упал после трёх успешных циклов. Полный санитизированный export
   сохранил текущую goroutine1732: `runtime.throw → bulkBarrierPreWrite`
   (`mbitmap.go:390`) → `wbMove → github.com/tailscale/wf.toFilter0`
   (`compose.go:104`) → `AddRule → Guard.apply → Guard.Remove → FetchSource`
   при закрытии HTTP source connection. В закреплённом Go эта точка throw —
   `bulkBarrierPreWrite: unaligned arguments`; исходный allocator wf не выравнивал
   bump pointer после byte/string allocations. [Локальный fork](../third_party/wf/malloc.go)
   исправляет alignment вместе с отдельным исправлением union ABI `FWPM_FILTER0`.
   SDK/два Go native теста и Dc077 wire proof с последующими тремя SCM reconnect
   подтвердили названные сценарии. Длительные/fault/reboot проверки актуальной
   сборки остаются впереди; исторический R2 crash не имел собственного стека.
   Первый exporter61b нативно parsed/executed; последняя source версия exporter9e
   остаётся для последующего согласованного checkpoint, новая UAC ради неё не нужна.
   Отдельный orphan-adapter
   recovery fix прошёл native identity/status/collision tests и включён в R3:
   [main-adapter-recovery-tests.txt](../dist/windows/native-win10/main-adapter-recovery-tests.txt).
2. **Завершить clean приёмку упакованного R6 с WG cleanup order fix.**
   Win10 builder upgrade14/main139 и отдельный clean install14 PASS относятся
   к R5 installer8076f589…e7939. На clean Win10 дефект WG cleanup воспроизведён;
   D9ced прошёл целевые regression/fault проверки; coherent R6 interactive upgrade
   в session1 —14PASS19:08:46. SYSTEM/session0 FAIL5 с Session Mismatch и rollback
   сохранён отдельно. Послеустановочные main139, три work/coexistence и IPC25 PASS;
   owner return4 и full WG/OpenVPN10 PASS, clean GUI ещё не закрыт. Win11 R6
   interactive upgrade14 PASS19:47:39; main139/work-coexist22/full10/IPC25 и
   scoped main/fault pcap теперь PASS. Остальную матрицу завершить на одном R6
   hash; положительные результаты не повторять без нового дефекта.
3. На **обеих clean Windows** завершить install/upgrade/uninstall, сохранение
   main/work profiles, отсутствие SDK-зависимости, UAC/SCM/recovery, негативный
   cleanup-failure/uninstall-abort и отсутствие оставшихся owned routes/DNS/NRPT/WFP.
   Win10 clean install14 уже PASS, его GUI не проверен. Проверить сохранение
   чужих ресурсов на обеих clean ОС. Очистить четыре временных inbound QA
   firewall rules точным ownership cleanup после завершения измерений.
4. Положительные R6 main/work protocol проверки, импорты/подписки/переключения,
   counters и split DNS обеих ОС сохранены. Не повторять их без нового дефекта.
   Завершить оставшиеся fault/reboot сценарии каждого семейства и cleanup на
   coherent installer; unit/parser и normal connected PASS их не заменяют.
5. Закрепить успешный Dc077 inbound WFP pcap повтором на актуальном coherent installer обеих
   ОС; отдельно проверить ICMPv6 ND/MLD узкие исключения. Полная fail-closed матрица:
   connect, обрыв, engine/service crash, normal restart, смена/возврат сети,
   явное отключение; IPv4/IPv6 TCP/UDP/DNS с захватами пакетов.
6. Завершить маршруты/совместную работу: main + несколько work, manual precedence,
   overlap LAN/container/Docker-like, full work pause **и resume** для остальных
   комбинаций (R6 full WG/OpenVPN pause/resume PASS на обеих ОС). Partial-peer отказ/возврат функционально
   PASS на R6 Win11 по29checks в3phases; scoped pcap не закрывает fresh physical IPv6 baseline. IPv6 route-conflict сейчас FAIL/pending diagnosis; сторонние VPN verified ownership/admin
   bindings, exact outer endpoint conflicts. Production NRPT: чужая политика,
   конфликты, DHCP/RDNSS, crash/reboot, split/full DNS и uninstall restoration.
7. Win11 R6 normal Auto boot/main recovery23, три work VPN и новый GUI после
   входа подтверждены; post-BFE/pre-Vault44313 также PASS. Независимый pre-BFE
   enforcement не изолирован. На Win10 соответствующая текущая boot матрица
   остаётся pending. Service restart Desired и новый boot Boot — разные сценарии.
8. Двухпользовательские active-console сценарии R6 обеих ОС закрыты: unauthorized9,
   isolated34 и owner return4 PASS. Сохранить access/admin deny, UID+SID isolation,
   private files/logs/diagnostics, busy owner и exact PID/creation/traffic-session
   continuity evidence. Совпадение content profile IDs между UID допустимо;
   повтор этих успешных сценариев без нового дефекта не требуется.
9. Installed R6 Win11 EN/RU × OS100/150/200, close/reopen/single-instance/quit
   и реальный GUI launch-at-login/readback/normal boot уже PASS. Закрыть installed
   Win10 R6 UI и его native file dialogs/ручные tray/UAC сценарии. Win11 native
   OpenVPN picker/preview/Cancel и real tray context/icon reopen уже PASS.
   EN/RU unit suite и QT_SCALE_FACTOR override не заменяют OS DPI/screenshots.
10. Сохранить R6 Linux Go/IPC/service PASS (один offline прогон19:55, source07043)
    вместе с прежним Qt EN/RU2/2 PASS, указав связь с source checkpoint. Общий лог содержит средовой IPC
    FAIL, который закрыт отдельным успешным rerun, а не удалён из истории.
    Финальные журналы/pcap/screenshots/SHA/manifest/instructions
    собрать в `dist/windows/`, экспортировав недостающие guest-only evidence.
    Временные ключи/пароли/VM disks остаются вне Git. В конце штатно выключить
    проектные VM; saved state не выдавать за окончательно выключенную машину.

Этот перечень сохраняет согласованный объём. Общая готовность наступит после
закрытия всей матрицы на обеих Windows, а не после отдельного успешного протокола,
компиляции установщика или нескольких повторов диагностического daemon.

Checkpoint18:26 UTC: clean R5 cleanup failure воспроизведён. Private daemon fd31
уточнил причину: `work markDown: work routes.set: Element not found.` — TUN
закрывался goroutine отмены до перестановки маршрутов. В D9ced порядок изменён на
markDown routes/DNS → EOF/stop → finishSession с прежним bounded15s watchdog.
Два clean цикла всех трёх work VPN PASS8326/8753ms, после отключения0managed
routes/work adapters/NRPT; [native EOF test](../dist/windows/native-win10-clean/core-eof-test.txt)
PASS0.02s. Реальный WG helper crash18:26:08 и восстановление двух пиров с HTTP4/6
и DNS PASS. R6 готовится с этим fix; эти отдельные native результаты не закрывают
coherent installer, boot, всю leak/fault матрицу или Win11.


Checkpoint рефлексии 16:18 UTC: read-only оценка подтвердила фокус; повторные
normal-main проверки неизменённых файлов остановить. Следующий обязательный шаг —
native foreign-resource/abort proof, затем coherent R5 и актуальная полная Win11
матрица. Позитивный partial/recovery не закрывает остальные fault/reboot/lifecycle,
изоляцию двух пользователей и итоговую проверку утечек.


Checkpoint 16:29:55 UTC: foreign/uninstall-abort и точная QA cleanup PASS по
combined PowerShell output. Повторные startup SCM7024/7031 не объявлены успешными;
нужна диагностика d333 с исправленным приватным журналом. Пустой ServiceName при
enabled provider и disabled=0 не доказывает early boot enforcement. Исторический
R5 stage c1e6 до logging fix не использовать для итоговой упаковки.


Актуальный lifecycle checkpoint Dd333 (16:55:13 UTC): установлен Running16:44:42;
SCM stop exit0 16:47:54 → stopped protection11 PASS16:48:43 → start exit0/Running
16:49:35 → recovery21 PASS и multi-peer HTTP IPv4/IPv6 все4 PASS. После forced
crash PID4300 16:53:46 — ordinary protection11 PASS, recovery21 PASS и все4
multi-peer HTTP к16:55:13; main и три work VPN connected, guard=true.
[stop/start recovery](../dist/windows/native-win10/startup-log-recovery.txt),
[crash protection](../dist/windows/native-win10/startup-log-crash-protection.txt),
[crash recovery](../dist/windows/native-win10/startup-log-crash-recovery.txt).
Актуальные ordinary пробы используют main-matrix SHA
`2bc99bacb614841ec387143367de9e016100d23a0a4bafddbeeb2dcd6d086393`.

[Stop/start pcap analysis](../dist/windows/native-win10/scm-restart-d333.analysis.json)
содержит78IPv4/37IPv6 packets и ноль direct TCP/UDP/DNS ответов по всем шести
probe classes. Crash pcap ещё не засчитан: анализ pending. Прежние два
startup7024/7031 не воспроизведены, **но остаются необъяснёнными**; новые успешные
сценарии не закрывают boot, полный fault/lifecycle обеих ОС или итоговую приёмку.

Рефлексия16:48 UTC проведена read-only: обязательный lifecycle/pcap остаётся в
фокусе, повторять normal-main на неизменённых файлах не нужно. Следующая граница —
новый R5 stage d333/helper29d/latest QA; старый c1e6 pre-logfix остаётся историей.
Native package и текущая Win11 матрица ещё впереди.


Checkpoint R5 17:26 UTC: coherent builder upgrade14/main139 и clean Win10
install14 относятся к installer8076f589…e7939; source остаётся
`f4b5a4ce8f80cb59fb73ac5c9698a0b4b845e0bd30c1d1217cfd47f262d2486d`,
build-manifest `c5dba6d3a5bad25c3396faede3446f2b2fe97b22d24e8a4bc98a9da0feba0bf9`.
QA fixture IPv6 DNS listener добавлен после build (c1088…), не является runtime
исправлением и не меняет immutable R5. `r5-main-pcap-analysis.json` нельзя принимать
за полный capture четырёх main протоколов или DNS6: matching coverage неполон.

Открытый WG multi cleanup: cleanup_failed17:13, explicit retry17:16 успешен;
нужен targeted clean repro, исправление не заявлено. Builder all-VPN-off и shutdown
в17:21, сохранён snapshot `updated-builder-r5-2026-11-06`, UUID
`ead81b93-e12e-4265-b77b-be276155ce3f`. После restore clean-os использована
Win10 build19045.2006/NAT безSDK и приложения, ordinary token Admin=false.
Clean install14 PASS не закрывает GUI (`guiProbeSkipped=true`). Далее clean fixture,
cleanup repro, 13 matching fault probes/captures, boot/lifecycle, затем Win11
с тем же installer SHA; общая acceptance по-прежнему pending.

Checkpoint рефлексии 19:19 UTC: отклонения от цели нет. Остановить повторные
main прогоны, session0 debugging и сборки без новых product defects; ближайший
шаг — завершить owner return/full tunnel, затем R6 Win11. Следующий контроль —
19:49 UTC. Около десяти минут потребовалось на QA console logins после lock-screen
idle reset; это задержка управления стендом, не подтверждённый product bug.

Checkpoint 19:55 UTC: Win10 main и все пять work profiles явно disconnected,
guard=false в 19:36:44; затем штатный poweroff и snapshot
`r6-clean-protocols-users-full-2026-11-06`, UUID
`b7c15b10-f315-4c79-b455-3ad61892dea2`. Win11 выполняет текущую R6 matrix/pcap;
это ещё не PASS. Рефлексия 19:50 UTC: отклонения от плана нет, следующая —20:20.
Linux regression завершён exit0 и не повторялся. Кандидат R6 не изменён.

Win11 R6 fault checkpoint 20:14 UTC: capture PID12015/Invocation72ebe383…,
NRestarts0, unit start20:02:09 → controlled stop20:14:28.364838; 9250frames,
0truncated/malformed, все8 fixed physical TCP/UDP/DNS classes0 во всём capture
и20fault/protection/recovery окнах. Предыдущий main capture дал positive baseline
8/8 и0direct в пяти verify окнах. Оба анализа сохраняют SHA и timestamp proof.
У SCM crash PID2496 и Xray crash PID980 negatives могли идти после recovery;
link-down negatives отдельно не доказывают WFP. Явный SCMStopped-through-probes
с13checks подтверждает защиту без работающего daemon; отсутствие дочерних engines
проверялось до/после, а не непрерывно. Boot profile UAC/pre-SCM setup пока pending.
Следующий контроль саморефлексии20:20UTC; новая готовность не объявлена.

Boot/UI checkpoint21:00 UTC: attempt1 QA ZoneMismatch сохранил Auto/restored,
но probes не выполнялись; его0selected outgoing не считается PASS. Attempt2
после QA canonicalization scope/index6→9→13 прошёл13 probes при41 sampled
no-service фактах. Same GUID/MAC/globalIPs; physical up и оба gateways на месте.
В этот no-Vault443/BFERunning интервал pcap видит4NS/NA code0 и6ARP с guestMAC,
а все8 direct classes0. Отдельный normal reboot20:56:20 дал main+3work и GUI7308/S1
с start после boot, ordinary canAdmin=false, HKCU Run exact installed path;
ручные connect/service-start не запрашивались. Pre-BFE и независимый clock offset
не доказаны; kernel capture-drop counter отсутствует. Рефлексия20:51 подтвердила
фокус, следующий контроль21:21. Общая готовность не объявлена.

Win11 user-isolation checkpoint21:16 UTC: user1 capture3 PASS21:03:50,
qa2 unauthorized9 PASS21:09:04, после явного enrollment isolated34 PASS21:11:55,
owner return4 PASS21:16:12. Ordinary active-console sessions1→2→1, один daemon
PID3436; creation time, traffic session и active profile сохранены. Сверены
экспортированные user1-r6/user2-r6/user1-r6-return. Partial WG ещё выполняется,
не PASS. Общая готовность и остальные pending пункты не меняются.

Checkpoint21:51 UTC: partial host complete/passed/cleanup=true; exact own DROP
удалён21:43:11 с21input packets/3696bytes. Scoped partial capture analysis не
заявляет inbound или all-destination/fresh physical IPv6 leak acceptance; observed
unfiltered argv сохранён отдельным provenance JSON. Native picker Commit отдельно
проверялся CLI матрицей; GUI здесь подтверждает выбор/preview/Cancel без дубликата.
IPv6 route-conflict остаётся FAIL, диагноз pending. Рефлексия21:51 выполнена,
следующий контроль22:21. Повторные normal main/UI прогоны без нового дефекта не нужны.

Stop checkpoint: overlap теперь подтверждён exported `native-win10-r7/r7-overlap/`
(baseline/run14/recovered6, exact UAC add/remove). Ограничение: один IPv4 connected
prefix, не actual Docker/HNS/NAT/IPv6. External dual root11PASS, admin export есть;
current IPv6-only/final cleanup ещё pending. Финальный all-VPN-off/snapshot/VM OFF
статус в checkpoint7 заполняет root после завершения текущего теста. Сегодня новых
проверок, включая подготовленный DNS6 helper, не начинать.
