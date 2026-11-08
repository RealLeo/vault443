# Windows: остановка и продолжение 7 ноября 2026

> **Windows R9 опубликован в GitHub Release 1.3.4 по запросу пользователя.**
> [Скачать EXE](https://github.com/RealLeo/vault443/releases/download/1.3.4/Vault443-1.3.4-windows-x64-setup.exe) ·
> [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.4/Vault443-1.3.4-windows-x64-setup.exe.sha256).
> Публичное скачивание полного EXE и его SHA-256 проверены; прежние Linux-вложения сохранены.
> [Акт публикации](../dist/windows/publication-1.3.4/publication-receipt.json).
> Указания «не опубликован» ниже относятся к историческому состоянию до этой публикации;
> замороженные build/acceptance-артефакты не изменялись.

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

## Текущее продолжение — R9, 7 ноября 2026

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

R9: [каталог](../dist/windows/candidate-2026-11-07-r9/),208 435 592 байта,
installer SHA `f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d`,
manifest `3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a`,
source `9eb63b1cac9b7d1e8afba7fca8134058c2f855b6e5777679905ae76930ef8e9d`.
[Native build](../dist/windows/native-build-r9/result.json) gui/package PASS 13:15–13:17;
[offline verification](../dist/windows/native-build-r9/offline-verification.json)
PASS: все 1765 payload records, 113 PE/8 production EXE и 295 runtime-source файлов
идентичны R8. ISS-only fix
`d14b22327f8d1971062dd176f9567f34c960c78b18b9d14a4f4f0913f2fc5138`.
SDK/QtCore/Go не пересобирались. R8 component proofs применимы к этим точным
runtime hashes со своими границами; это не свежая полная R9/Win10 серия и не
перенос дефектного R8 installer lifecycle в PASS.

Win11 R9/noSDK: первый install14 PASS 13:26:57; ordinary GUI показан до/после
reinstall. Negative safe-abort11 PASS 13:31:22: намеренно приостановлен только
UI thread, finally Resume; Restart Manager отказал в graceful shutdown, принудительное
завершение не применялось. Те же SCM, 15 profile IDs и 1768 имён app files сохранены.
Positive lifecycle14 PASS 13:32:48: исходный GUI 4300/creation 13:27:59 подтверждён
удерживаемым process handle и закрыт самим uninstaller; child uninstall14
подтвердил 0 app files/routes/DNS/WFP, включая owned containers. Точные профили
сохранены; foreign NRPT пережил uninstall и reinstall, затем удалён только свой
QA GUID. [Installer proofs](../dist/windows/native-win11-r9/installer-proof/),
[negative](../dist/windows/native-win11-r9/installer-proof/r9-gui-close-abort/20261107T133050879Z/result.json),
[positive](../dist/windows/native-win11-r9/installer-proof/r9-lifecycle/20261107T133207708Z/result.json),
[final state](../dist/windows/native-win11-r9/final-state.json).

Win10 R9/noSDK: upgrade14 PASS13:40:28, свежий core complete/PASS14:02:16.704:
main139, physical DNS6 UDP/TCP positives, main recovery23 и реальный IPv4/IPv6/DNS
через WG multi/AWG/OpenVPN при VLESS. [Core](../dist/windows/native-win10-r9/core-proof/r9-core/result.json),
[main139](../dist/windows/native-win10-r9/core-proof/main/20261107T140015595Z-all-vless.json).
Шесть новых engine-fault случаев по15PASS и final restore PASS14:11:20;
[engine matrix](../dist/windows/native-win10-r9/engine-proof/engine-matrix/20261107T140438342Z-result.json).
OpenVPN exact15 — прежний Win10 R8 proof для byte-identical runtime, без повтора.

Actual physical IPv4/IPv6 .2→.3 и DNS4→DNS6: changed22 PASS14:12:26,
exact finally restore PASS14:16:02.745 и restored22 PASS14:16:45.992.
[Master restore](../dist/windows/native-win10-r9/network-ui-proof/r8-network-change-change-20261107T141602745Z.json),
[changed](../dist/windows/native-win10-r9/network-ui-proof/network-change/20261107T141226140Z-changed.json),
[restored](../dist/windows/native-win10-r9/network-ui-proof/network-change/20261107T141646015Z-restored.json).
Native Windows picker открыл прежний private OVPN→Already added→Cancel,
[снимок](../dist/windows/native-win10-r9/native-file-picker.png).
Product vault443-access UAC подтвердил boot On→Off→On; final On PASS,
те жеSCM1932/creation13:40:22.769415, IDs и trafficSession1794060527651907500-11.
[UI receipt](../dist/windows/native-win10-r9/network-ui-proof/r9-ui-result.json),
[final On PNG](../dist/windows/native-win10-r9/product-uac-boot-final-on.png).

Win10 R9 tail: partial baseline29/blocked29/recovered29 PASS;
[host report](../dist/windows/native-win10-r9/partial/r8-partial-host-20261107T141859Z.json)
complete14:23:44.649, exact token-owned DROP cleanup=true/errors0:20пакетов/3520байт.
Удаление DROP выполнено14:23:08.944, затем завершилась recovered проверка.
External dual11 PASS14:24:53.103, IPv6-only11 PASS14:25:56.098; exact Windows
service/adapter/binding cleanup прошёл, afterstop2 PASS14:27:30 включает main22
с автоматическим VLESS resume без RequestConnect.
[Dual](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142451867Z-dual.json),
[v6only](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142553329Z-v6only.json),
[afterstop](../dist/windows/native-win10-r9/tail-proof/r8-external/20261107T142712351Z-afterstop.json).
Overlap baseline/run14/rulesRestored PASS, owned secondary IP точно удалён,
recovered6 PASS14:31:03.706:
[run](../dist/windows/native-win10-r9/tail-proof/r8-overlap/20261107T142858318Z-run.json),
[recovered](../dist/windows/native-win10-r9/tail-proof/r8-overlap/20261107T143020673Z-recovered.json).

Новый offlink external test на Win10 **функционально11PASS14:32:58.545**:
точный endpoint93.184.215.14:1194, свой physical host route metric444,
тот же fixture SCM до/после binding. Unbound window14:32:16.798–14:32:37.900,
bound window14:32:37.965–14:32:53.103. Windows service/adapter/binding/route
очищены, Linux token967bd… DNAT точно удалён14:33:45.739; счётчик1packet/42bytes
подтверждает попадание нового flow, а не полный объём трафика.
[Proof archive](../dist/windows/native-win10-r9/offlink-export.zip),
[ownership/cleanup](../dist/windows/native-win10-r9/offlink-owner.json),
[QA provenance](../dist/windows/native-win10-r9/controllers/r9-external-offlink-provenance.json).
QA variant PE b06c… разрешает только exact offlink literal; production113PE
не менялись. Functional proof дополнен qualified packet proof ниже.

Win11 R9 installer проверки завершены; актуальное состояние VM указано ниже.


Win10 R9 inbound PASS: baseline8/8, после guard arm LAN4positive/offlink4negative,
pre-existing offlink TCP4/6 без reply payload. [Analysis](../dist/windows/native-win10-r9/inbound/r9-inbound-analysis.json)
acceptancePassed=true; четыре QA firewall rules/binding точно удалены14:38:24.979:
[cleanup](../dist/windows/native-win10-r9/installer-proof/inbound-cleanup-20261107T143824990Z.json).

Win10 R9 hung-GUI safe-abort11 PASS14:39:48.574; live-GUI lifecycle14 PASS
14:41:18.131, включая child uninstall14/reinstall14, закрытие исходного GUI388
самим uninstaller, сохранение точных SID/profile IDs и чужого NRPT, затем exact
QA cleanup. [Safe abort](../dist/windows/native-win10-r9/installer-proof/r9-gui-close-abort/20261107T143920716Z/result.json),
[lifecycle](../dist/windows/native-win10-r9/installer-proof/r9-lifecycle/20261107T144046093Z/result.json).
Ordinary GUI6544/session1 после reinstall:
[PNG](../dist/windows/native-win10-r9/ordinary-gui-after-reinstall.png).
[Final state](../dist/windows/native-win10-r9/final-state.json): OS19045/noSDK,
LocalSystem7112/Auto, четыре own main и пять work сохранены, все VPN off,
guardfalse, нет offlink route/external service/adapter/overlap IP.

Post-offlink main22 PASS14:34:10.749:
[verify](../dist/windows/native-win10-r9/clock-final-main-proof/20261107T143353875Z-verify-vless.json).
Capture5507/N0 controlled stop14:35:14.496,14185frames/no kernel drops.
[Main packet proof](../dist/windows/native-win10-r9/r9-win10-packet-analysis.json)
SCOPED_ZERO_COUNTS_CLOCK_INTERVAL_CHANGE_QUALIFIED,
SHA `d1f3bb3ec99dfc4df5f816ea43e287b68f372ab7e2d6eb739534f45de698d4b2`.
[Offlink packet proof](../dist/windows/native-win10-r9/r9-offlink-packet-analysis.json)
SCOPED_UNBOUND_DENY_BOUND_ALLOW_CONFIRMED__CLOCK_VARIATION_QUALIFIED,
SHA `ff1d92e4f141a151201badfe59d2733a5cec8b26a004ad752dfe5b8b47a65a23`:
unbound0 включая expanded edges; certain bound113out/23in, первый OUT
14:32:47.704861 более8.25с после latest possible binding.
Clock variation учтена консервативным union[-0.6450152,+1.4826]с и точными
DNS ID/ports causal calibration. Стабильный UTC не заявлен; первоначальный
неуспешный clock-interval анализ сохранён.
[Provenance/limits](../dist/windows/native-win10-r9/packet-proof-provenance.json).

Win10 штатно выключена через guest shutdown.exe; OFF checkpoint `d4de2a10-95b9-4d9d-8444-49d4694bb32a` подтверждён14:45:07 [receipt](../dist/windows/native-win10-r9/off-snapshot.json).
Win11 offlink/cleanup и финальный OFF завершены; current snapshot 235e530f, прежний f4cac сохранён.

**R8 uninstall failure остаётся отдельным неуспехом**, исправленным новым
installer R9 и отдельным proof; прежние журналы не переписаны:

13:05:25 uninstall вернул 0 и удалил службу, сохранил 5 main+6 work профилей, но GUI 8756
в session1 продолжал работать и 37 принадлежащих приложению GUI/Qt/MSVC файлов
остались. Inno: `file in use (5)`, `NeedRestartWindows? No`.
[Lifecycle failure](../dist/windows/native-win11-r8/lifecycle-failure/r8-lifecycle/20261107T130512934Z/result.json),
[uninstall report](../dist/windows/native-win11-r8/lifecycle-failure/r8-lifecycle/20261107T130512934Z/uninstall/20261107T130520463Z-uninstall.json).
Finally удалил только свой NRPT GUID; обычная повторная установка не запускалась.
Отдельный прежний отказ QA-preflight также сохранён; он не заменяет реальный defect.

Ниже сохранена история предыдущей остановки; при продолжении использовать этот
верхний блок и актуальную [хронологию](WINDOWS-PORT-PROGRESS-2026-11-07.md).

- R7 на clean Win10: physical DNS6 UDP/TCP controls PASS09:07:55; external
  dual11 и IPv6-only11 PASS, cleanup и автоматическое main recovery PASS.
  Первая DNS6 попытка упёрлась в отсутствующий listener, первый afterstop — в
  старый fixture binary; оба QA отказа сохранены, тестовые серверы обновлены без
  смены ключей. Последний R7 noSDK snapshot:
  `037f3924-b30b-4bc2-84f7-e262a70dc023`, `r7-resume-complete-2026-11-07`.
- Frozen R8: [каталог](../dist/windows/candidate-2026-11-07-r8/), версия1.3.4 x64,
  installer208434238bytes SHA
  `12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e`;
  manifest `bc6692d6939e0798de19465963e24de765eb84938b33866e4e295ea5bba65f19`;
  source `957c7399aef10e067e593b66120a5cf9a67476ee446b19734e3bd7848e2d35c2`.
  Daemon `4a799842a43d949740f3567698371a95118fce90cc1f004a142527825fcbde50`,
  CLI `514c067b23e6adbfd8a245f592aa338ec62105f08de59c3286065fd1a278f1c6`,
  access `ba857c38df6b765687c7328619ab7a70d93b7e68904af1c9ac6835917e0a81fc`.
  GUI53bc/QtCore01052/tunnel/Outline прежние. SHA256SUMS и
  [offline verification](../dist/windows/native-build-r8/offline-verification.json)
  PASS:1765payload records,113PE records,8productionEXE/0QAEXE.
- R8 содержит только два изменённых product файла OpenVPN: строгий
  HOLD→stateACK→logACK→releaseACK barrier и отдельный stop budget с освобождением
  адаптера только после подтверждённого завершения child. Native focused units
  [PASS](../dist/windows/r8-openvpn-native-unit.json), Linux full suite
  [PASS](../dist/windows/linux-regression-r8.json); метаданные связаны с exact source.
  **Историческая причина metadata-before-auth не доказана.** Реальное
  startup/recovery и route restoration R8 уже подтверждены отдельными native
  сценариями; это не доказывает точную причину старой гонки.
- Native cached GUI/package PASS09:18:08–09:20:05UTC; build evidence:
  [native-build-r8](../dist/windows/native-build-r8/). Builder snapshot
  `25c4a997-e0dc-4f94-b081-da2b938fdf30`, `updated-builder-r8-2026-11-07`.
  SDK/QtCore/MSVC не пересобирались. R1–R8 frozen artifacts не перезаписывать.
- Win10 R8/noSDK: upgrade 14, full-work 10, fresh route conflict16/9,
  SCM/NIC 10/11, IPC 25, exact OpenVPN child crash→newPID/automatic real traffic,
  RU/EN UI 100/150/200, preSCM13 и обычный Automatic boot2 — PASS.
  Два пользователя: existing qa2 reuse PASS, owner-return 4 PASS10:48:30;
  сохранены trafficSessionId, PID2836 и CIM creationUTC10:04:01.5164930Z.
  Артефакты `dist/windows/native-win10-r8/`.
- Boot capture proof PASS_SCOPED_POST_BFE_WITH_SEPARATE_POSITIVES:
  5044frames/no errors, восемь direct classes 0 в preSCM/boot verify windows.
  Это postBFE/preVault443; ранний preBFE не подтверждён.
- При финальном disconnect intentional foreign WFP fixture вызвал ожидаемый
  FWP_E_IN_USE и transactional cleanup refusal. **Owned filters/routes/DNS до
  успешного retry не считать очищенными.** Foreign uninstall-abort PASS9
  10:54:18: exact GUID сохранился, uninstaller exit1, служба/10 профилей/1768
  имён app files сохранены; известный QA helper удалил только свой exact GUID.
  Отчёты экспортированы: `native-win10-r8/foreign-abort/`.
- R9 builder сохранён выключенным как
  `096ddfd6-f49e-4f72-8761-ce200e31dcef`.
- Win11 R9 штатно **выключена 13:36:15**, финальный checkpoint
  `f4cac319-69b6-4f3f-ab58-8836b1c103c3`. Прежний R8 failure checkpoint
  `7c3fab13-34b2-4b8e-969e-582f37be2d72` сохранён отдельно.
- Win10 R9/noSDK завершена и OFF, новый checkpoint
  `d4de2a10-95b9-4d9d-8444-49d4694bb32a` подтверждён14:45:07.
  Прежняя clean branch e4cc сохранена. Linux fixture работает;
  Win11 — OFF/final snapshot 235e530f; итоговый receipt указан выше.


Win11 R8/noSDK: upgrade 14, main 139, три рабочих VPN с реальным IPv4/IPv6/DNS,
full-work 10 и route 16/9/restored, IPC 25, SCM/NIC 10/11, точный OpenVPN fault 15,
RU/EN UI 100/150/200 и native picker/tray/product boot-profile UAC — PASS.
Реальная смена физических адресов/DNS завершена: changed 22 и restored 22 PASS,
точное восстановление исходной конфигурации подтверждено. Existing qa2 reuse 55
и owner-return 4 PASS с сохранением PID/creationUTC/trafficSessionId. Шесть
оставшихся engine-family cases завершены PASS/restored: Xray VLESS/Trojan/SS,
настоящий Outline helper, WireGuard multi и AmneziaWG; OpenVPN отдельно уже пройден.
[Core packet proof](../dist/windows/native-win11-r8/r8-win11-packet-analysis.json)
покрывает 38 окон main, восемь direct classes 0 и свежие positives в том же capture;
это ограниченный proof, без inbound/раннего boot claim.

Win11 boot1: pre-SCM 13 PASS/restored/taskRemoved и обычный main+три work+GUI
с реальным трафиком PASS 12:14:56. Это post-BFE/pre-Vault443 proof:
[boot1 packet analysis](../dist/windows/native-win11-r8/boot1/r8-boot-packet-analysis.json).

**Обычный boot2, попытка 2, PASS 12:35:32.778**: запрос 12:33:46.140,
фактическая загрузка 12:33:59.500, main recovery 23 и три work VPN с реальным
IPv4/IPv6/DNS, GUI 8756/session1 без RequestConnect или ручного StartService.
[Отчёт](../dist/windows/native-win11-r8/boot2/r8-boot2-verify.json),
[запрос](../dist/windows/native-win11-r8/boot2/r8-boot2-request.json).
QA ifIndex 13→12 привязан повторно только после проверки того же GUID/MAC и
байтов IP; исходный positive baseline 11:03 сохранён, новый positive не заявлен.
Capture4376/inv7f6… завершён и экспортирован. [Tail packet proof](../dist/windows/native-win11-r8/r8-win11-tail-packet-analysis.json)
SHA7130476c…5c7ebe подтверждает scoped normalboot2/partial/external/recovered windows,
с отдельными outbound positives; он не заменяет inbound proof.

Первая попытка boot2 **не была normal PASS**: Windows записала ShutdownEnd
12:18:54 после 9.558с, затем VM оставалась Restarting, host Reset/SaveState
зависли. Сохранены [диагностика](../dist/windows/native-win11-r8/boot2-shutdown-delay/windows-shutdown-diagnostic.json)
и [incident receipt](../dist/windows/native-win11-r8/boot2-shutdown-delay/incident.json).
Точный frontend остановлен 12:29:16, затем выполнен coldboot того же текущего VDI.
Причина исходного зависания неизвестна; успех попытки2 не доказывает её устранение.

Win11 partial WireGuard peer: baseline29, blocked29 и recovered29 PASS,
завершено12:42:20. Прицельный token-owned DROP дал22пакета/3872байта, cleanup=true,
errors0; без Connect/Reset, SCM3312 прежний. [Host metadata](../dist/windows/native-win11-r8/r8-outputs/partial/r8-partial-host-20261107T123738Z.json).

Win11 external OpenVPN: dual11 PASS12:43:51, IPv6-only11 PASS12:45:19,
exact cleanup PASS12:46:22 — service/adapter/binding удалены. Afterstop2 PASS
12:46:45 включает main real verify22, автоматическое восстановление без
RequestConnect. [Dual](../dist/windows/native-win11-r8/external/r8-external/20261107T124350046Z-dual.json),
[v6only](../dist/windows/native-win11-r8/external/r8-external/20261107T124517834Z-v6only.json),
[cleanup](../dist/windows/native-win11-r8/external/r8-external-cleanup.json),
[afterstop](../dist/windows/native-win11-r8/external/r8-external/20261107T124626015Z-afterstop.json).
Builtin OpenVPN явно выключался перед setup из-за общего client certificate и
восстановлен отдельно только после external proof, вне измеряемых окон.

Win11 overlap полностью завершён: run 14/rulesRestored=true, точное удаление
своего IPv4/25 без смены gateway и recovered 6 PASS 12:50:45.227.
[Run](../dist/windows/native-win11-r8/overlap/r8-overlap/20261107T124812216Z-run.json),
[recovered](../dist/windows/native-win11-r8/overlap/r8-overlap/20261107T124945215Z-recovered.json).
Это connected IPv4 prefix case, не Docker/HNS/NAT или IPv6 overlap.
Foreign-WFP uninstall-abort 13 PASS и exact known-helper cleanup также завершены:
[report](../dist/windows/native-win11-r8/foreign-abort/r8-foreign-abort/result.json).

Win11 inbound PASS: 329 frames, baseline 8/8, после arm LAN 4 positive/offlink 4 negative,
pre-existing TCP4/6 без ответного payload. [Analysis](../dist/windows/native-win11-r8/inbound/r8-inbound-analysis.json).
Ровно четыре принадлежащих QA firewall rules и binding удалены:
[cleanup](../dist/windows/native-win11-r8/inbound/inbound-cleanup-20261107T125728813Z.json).
Это scoped fixture proof, не полный глобальный leak PASS.

Оставшихся обязательных native проверок нет. Следующий шаг — только упаковка
подтверждений и передача локального результата. В validated delivery используются
те же installer/source/build-manifest bytes и отдельные acceptance-manifest/report.
Frozen candidate artifact-manifest acceptance=pending сохраняется как метаданные
исходной сборки, а не текущий статус приёмки. VM оставлены OFF. Подписание и
публикация по умолчанию не запрошены; дополнительные исследования не планируются.

Fixture CA остаётся прежним: notAfter **7 ноября23:11:28 UTC =8 ноября02:11:28 МСК**.
Перед TLS проверками после этого срока обновить только временный стенд/QA trust/
профили; не принимать истечение сертификата за отказ приложения. После завершения
плана штатно выключить все VM. Последняя саморефлексия14:34UTC; native работа завершена. Если передача
затянется после15:04UTC, провести короткий контроль фокуса.

## История предыдущей остановки

Пользователь попросил закончить только уже начатый external VPN тест, сохранить
состояние для завтра и остановиться. **Полная приёмка не завершена, R7 не релиз.**
Новые проверки, исследования, сборки и публикация сегодня не запускаются.
Текущий тест завершён и очищен, все три VM выключены. Финальные факты записаны
ниже; автоматического продолжения ночью нет.

## Артефакт и исходники

Репозиторий: `/var/www/projects/ubuntu/vless-terminal`.
Immutable кандидат: `dist/windows/candidate-2026-11-07-r7/`, версия1.3.4 x64,
локальный/неопубликованный/без Authenticode-подписи приложения.

| Файл | SHA-256 |
| --- | --- |
| Vault443-1.3.4-windows-x64-setup.exe,208453006bytes | `491085f2d124fcaf2c1e047f15e9764f8b07c7b7fbc064892c1d52b2a0359f5d` |
| build-manifest.json | `3a0fdae5ca17d00717ce1282cf51c280627c9331acd8bc094e2bcfc2075c8a6d` |
| source.zip | `69d82a39026a20d9d0cfc6ba3d4b18670fa4ab7c10c767792bc5d05da4ddb76c` |
| vault443d.exe | `2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6` |
| vault443-cli.exe | `c07f3efa2af7557806d46a74aca13576b94a752ac03737c0fe9ebc811c8ee895` |
| vault443-access.exe | `e5222dd613fd30f7140146c1e30ab6226ec6933fa852806bb782d3cf99e9bdfb` |

GUI `53bc41422de5c1940a3e486c7d5a6442a2074d94fc22f8d33cfef91e5eb140df`
совпадает с R6; QtCore/MSVC/SDK не пересобирались. Tunnel/Outline также прежние.
[Offline verification](../dist/windows/native-build-r7/offline-verification.json)
PASS:1765payload records,5PE/22runtime records,59Go modules, официальный Wintun,
QtBase/wf source provenance,0QA EXE. Source R7 заморожен; последующие delivery docs
и QA отчёты не требуют перепаковки source.zip. R1–R7 не перезаписывать.

R7 исправляет только нормализацию синтезированных full-OpenVPN IPv6 redirect
ranges и full-IPv6 classification внешнего VPN. Подробности и история:
[progress7](WINDOWS-PORT-PROGRESS-2026-11-07.md),
[acceptance](WINDOWS-ACCEPTANCE-STATUS-2026-11-06.md).

## VM и сохранённые ветки

Все VM запускать последовательно, через private VirtualBox registry
`/var/www/projects/windows/virtualbox`, вне ограниченного VBox sandbox.

| Ветка | Snapshot / состояние |
| --- | --- |
| Win10 builder с SDK/Qt/MSVC/Inno и R7 cache | `cf984d38-8e3e-4777-a916-0cbff4479afb` |
| Win10 прежний clean R6/noSDK | `b7c15b10-f315-4c79-b455-3ad61892dea2` |
| Win10 текущий clean R7/noSDK | `703732cb-4d42-4b0a-b5b7-dfa9c7183a2d`, `r7-clean-checkpoint-2026-11-07`, OFF |
| Win11 clean R6/noSDK/no external | `201a6c36-b2f2-42e7-95fb-a4c279a49288`, OFF; R7 ещё не установлен |
| Linux fixture | OFF; active captures0, fault DROP rules0, partial owner journal отсутствует |

`vaultqa` — существующий QA controller, ordinary token с явным UAC для admin;
`vaultqa2` уже существует как standard user. Не запускать повторно
`qa-user-bootstrap.ps1`: skip/reuse флага у него нет, повтор может сбросить пароль.
Существующие credentials/SID и private QA journal сохранить, пароль не генерировать.

## Что подтверждено R7 на clean Win10

- Interactive upgrade14 PASS22:52, noSDK baseline, профили всех SID сохранены,
  existing qa2 без password reset: `native-win10-r7/interactive-upgrade/`.
- Main139 и main+три work coexistence22 PASS; real WG multi/AWG/OpenVPN HTTP4/6/DNS:
  `native-win10-r7/r7-protocols/`.
- Fresh full-route/manual DNS owner case complete16checks/9steps PASS/restored=true:
  `route-conflict-fresh/result.json`. Новые OVPN4/6 SYN/TLS, затем новые WG path
  подтверждены `r7-route-fresh-packet-analysis.json`; physical8classes0.
- Отдельный SCM stop protection13 и start recovery23 PASS; capture/metadata
  экспортированы. Это не полная fault matrix и не готовый whole-capture PASS.
- IPv4 connected-prefix overlap: baseline/run14/recovered6 PASS, UAC add23:27,
  exact remove23:30:06 и0owned secondaryIP: `r7-overlap/`. Это один IPv4 overlap,
  не реальный Docker/HNS/NAT или IPv6 overlap.
- External OpenVPN dual: root подтвердил11 PASS, verified Full4/6, corp/default
  HTTP4/6, default DNS и сохранённую WG zone, main paused. Ordinary reports:
  `r7-external/`; admin export `r7-external-admin-dual.json`. Cleanup23:46:34 PASS:
  service/adapter/binding отсутствуют; afterstop PASS, включая main real verify22.
  IPv6-only не проверен на приложении: Start-Service остановился на QA fixture.
  Его `validateConfig` разрешает только `redirect-gateway def1 ipv6`, а переход
  пишет `redirect-gateway ipv6 !ipv4`. Причина установлена по исходнику allowlist;
  это не подтверждённый отказ приложения. Исправить только QA helper и его pins,
  затем повторить этот пункт; установщик R7 ради этого не пересобирать.

Пробел positive controls: `r7-main-pcap-analysis.json` покрывает пять verify окон
и0direct по8classes, но свежий baseline только6/8 — DNS6 UDP/TCP не выполнялись.
`/tmp/r7-dns6-positive.ps1` SHA
`4a0e1db4a532839bc51932c35ff39f6fe744816121b1a45d7025151e2da295c0`
подготовлен, **НЕ запускался**. Сегодня его не запускать. Он требует заранее
отключённых main+всех work и guard=false, делает только2physical IPv6 DNS probes;
захватом управляет root. Не повторять main139 ради этих двух controls.

Не скрывать ранние ошибки: route attempt1 RPC unknown/timeout; attempt2 pooled
HTTP и failed restore, metadata-before-auth/adapter-name-in-use. Потребовались
explicit work stop и SCM restart. Fresh-case позже полностью восстановился,
но это не доказательство устранения причины auth/metadata/RPC failure. Сохранены
`route-conflict-attempt1/`, `route-conflict-attempt2/observed-final-state.json`,
`r7-openvpn-recovery-logs.json`. При повторе сначала взять приватный service.log
и точный PID/stage; не вращать GUID и не удалять чужие адаптеры вслепую.

## Ближайший порядок завтра

Только после нового разрешения продолжить:

1. Прочитать финальный блок ниже, этот checkpoint и актуальный acceptance.
   Проверить сохранённый installer/source SHA, использовать готовый R7; сборка
   без нового product fix не нужна. Уточнить итоговый Win10 snapshot и fixture
   readiness после штатного старта; не регенерировать ключи/профили вслепую.
   **Сначала проверить сертификат fixture:** notAfter `2026-11-07 23:11:28 UTC`
   (`8 ноября 02:11:28 МСК`). При следующем дневном запуске он может истечь;
   обновить временные сертификаты, доверие QA и fixture profiles до сетевых тестов.
   Это изменение стенда, не причина пересобирать приложение.
2. Закрыть точечный DNS6 positive gap отдельно, затем remaining R7 acceptance.
   Не повторять уже прошедшие normal main/full-route/overlap кейсы без причины.
3. Довести R7 Win10 engine/fault/boot/UI/security и coherent lifecycle, затем
   тот же installer SHA на Win11 clean201: upgrade через interactive UAC,
   main/work/routing/external и остальные обязательные сценарии. Старые R6 PASS
   — только evidence конкретных компонентов. Win11 GUI53bc/6DPI cases, user
   isolation9/34/4, boot/fault/inbound R6 сохранены, но R7 integration не заявлена.
4. Завершить на обеих ОС foreign WFP/NRPT/DNS/DHCP/RDNSS конфликты, split/full DNS,
   exact uninstall-abort/cleanup/profiles-retained/reinstall, оставшиеся protocol
   engine faults и IPv4/IPv6 TCP/UDP/DNS leak scopes. Независимый pre-BFE proof
   не получен; R6 имел post-BFE/pre-Vault443 proof, не подменять одно другим.
5. Консолидировать logs/pcap/screenshots/manifest/instructions, затем штатно
   выключить все проектные VM. Общая готовность только после полной матрицы.

Готовые средства: `tests/windows/{installer-smoke,qa-bootstrap,qa-runner,
main-matrix,work-smoke,openvpn-smoke,inbound-guard,ui-native-smoke,
set-display-scale,user-isolation}.ps1`, `host/wfp-foreign`/`wfp-inspect`,
`run-inbound-proof.py`, `analyze-inbound-pcap.py`, external OpenVPN fixture.
Host QA bundle: `/var/www/projects/windows/qa-source-r7`, mutable exchange:
`/var/www/projects/windows/exchange`. Нативные reports: `dist/windows/native-win10-r7`.

Для обновления QA на существующем testbed: current controller запускает
`C:\Users\Public\qa-source-r7\r7-bootstrap-upgrade.ps1` через интерактивный UAC;
внутри qa-bootstrap обновляет protected dynamic hashes, затем installer-smoke
`-Phase upgrade`. SYSTEM/session0 upgrade с живым GUI уже дал RM Session Mismatch;
не возвращаться к этому ошибочному QA flow. После actual upgrade14 повтор не нужен.
Fixed tasks подходят для inspect/service fault/uninstall; fresh install требует
отдельного interactive `installer-smoke -Phase install`. Foreign helper требует
UAC controllerSID; exact GUID survival проверить **до** его идемпотентного cleanup.
Uninstall harness отдельно не проверяет NRPT — сверить saved exact ruleGuid.

Ключи/пароли и raw private profiles не копировать в Public/Git/dist. Auto-review
ранее отклонил Public-copy приватного OpenVPN profile; безопасный путь уже принят:
читать `%LOCALAPPDATA%\Vault443\qa-ui-import\fixture-openvpn.ovpn` и писать только
в защищённые SYSTEM/admin каталоги fixture. Новый приватный input в Public не
копировался; старые временные fixture JSON из ранних QA не являются приватными
пользовательскими профилями службы.
Шесть `tests/windows/r7-*.ps1` и `tests/windows/R7-ACCEPTANCE.md` сохранены в рабочем
checkout **после** заморозки source69d82 и не входят в этот immutable source ZIP.
Использовать их README/hashes и финальный VM snapshot; `/tmp` не единственный
источник для продолжения. Не менять архив кандидата ради QA/delivery docs.

## Финальная остановка — выполнена

- External dual11 PASS; IPv6-only NOT TESTED из-за QA allowlist; cleanup и main
  auto-resume PASS. Все отчёты и `r7-external.pcap` экспортированы.
- Win10 final-stop-state23:50:30 PASS: main disconnected, guardfalse, workActive0,
  owner main profiles4/work profiles5 сохранены, corp service/adapter0, overlapIP0.
- Win10 snapshot `703732cb-4d42-4b0a-b5b7-dfa9c7183a2d` сохранён после штатного
  выключения. Win10/Win11/fixture **poweroff** подтверждены23:52:09 UTC:
  `dist/windows/vm-final-states-2026-11-07.json`.
- Саморефлексия23:51: работа ограничена запросом остановки; завершены только
  очистка и фиксация состояния, новых тестов/сборок/исследований нет.

После финальной записи остановиться; никаких ночных DNS6/других прогонов.
Саморефлексию каждые30мин (до5мин) возобновить вместе с работой завтра; таймер
не является разрешением на автоматическое продолжение после просьбы остановиться.
