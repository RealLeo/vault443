# Windows port: 7 ноября 2026, R7 native acceptance

Полная приёмка не завершена. R6 и его source ZIP остаются неизменными.
Актуальная остановка и порядок завтра: [checkpoint7](WINDOWS-PORT-CHECKPOINT-2026-11-07.md);
ранние абзацы ниже сохраняют хронологию и не заменяют финальный статус.
Подробные предыдущие проверки: [статус приёмки](WINDOWS-ACCEPTANCE-STATUS-2026-11-06.md).

В R6 дважды воспроизведён конфликт full WireGuard/OpenVPN: OpenVPN автоматически
экспортировал более специфичные IPv6 redirect ranges, и Windows выбирала их
поверх incumbent default. Native FIB и пакетные факты сохранены в
`dist/windows/native-win11-r6/r6-route-conflict-attempt2*`.

R7 содержит два узких исправления:

- OpenVPN `::/3`, `2000::/4`, `3000::/4`, `fc00::/7`, синтезированные для полного
  IPv6-туннеля, сводятся к `::/0`. Явные client/PUSH routes, connected networks
  и DNS host routes сохраняются. Generic selection/partition не менялись.
- Внешний VPN признаётся полным IPv6-туннелем при наличии точного набора всех
  четырёх диапазонов. Неполные наборы/дубли не дают full classification.
  Проверки принадлежности службе/процессу и WFP gates не менялись.

Изменены четыре production-файла: `internal/worknet/openvpn_windows.go` и его
тесты, `internal/network/windows_binding_contract.go` и его тесты.
Нативно на Windows 11 прошли семь OpenVPN test groups и два focused external
classification test groups. Полный Linux `go test -mod=readonly ./...` прошёл
после разрешения loopback sockets тестов; результаты в `dist/windows/*r7*unit*`
и `linux-regression-r7.*`. Неподдерживаемые Go flags в первом PS5 запуске и
sandbox socket denial были ошибками запуска, не product failures.

Текущий backend R7:

| PE | SHA-256 |
| --- | --- |
| daemon | `2ad9a62ab0e14825cf265100891a16f74e80911e03b2d63cb036f3d976f3b1c6` |
| CLI | `c07f3efa2af7557806d46a74aca13576b94a752ac03737c0fe9ebc811c8ee895` |
| UAC helper | `e5222dd613fd30f7140146c1e30ab6226ec6933fa852806bb782d3cf99e9bdfb` |

Tunnel/Outline PE совпадают с R6. Лицензии/SBOM повторно собраны для новых PE.
Immutable R7 упакован22:41:21 UTC и находится в
`dist/windows/candidate-2026-11-07-r7/` (208453006bytes):
installer SHA `491085f2d124fcaf2c1e047f15e9764f8b07c7b7fbc064892c1d52b2a0359f5d`,
manifest `3a0fdae5ca17d00717ce1282cf51c280627c9331acd8bc094e2bcfc2075c8a6d`,
source `69d82a39026a20d9d0cfc6ba3d4b18670fa4ab7c10c767792bc5d05da4ddb76c`.
Native GUI cached hash53bc и QtCore01052 совпали с R6; MSVC/SDK/Qt не пересобирались.
[Offline verification](../dist/windows/native-build-r7/offline-verification.json)
PASS:1765payloadrecords,5PE/22runtime records,59Go modules, officialWintun/Qtpatch/
wf source provenance,0QA EXE. Это не полная Windows acceptance.

Ранняя подготовка external fixture не дала PASS: нестандартный тип тестового адаптера отклонялся
VPN discovery; после исправления QA type на `OpenVPN Wintun` immediate service
recreate/start также не прошёл. Исходы сохранены, продолжать на установленном
R7 с нормальным разделением stop/delete/create. Автоматическая проверка отклонила
копирование ключа в Public; безопасная подготовка читает частный профиль из
LOCALAPPDATA и пишет только в защищённые SYSTEM/admin каталоги. Публичной копии
профиля не создано. QA helper/README обновлены; production security не ослаблена.

Win11 штатно выключена и возвращена к чистому checkpoint
`201a6c36-b2f2-42e7-95fb-a4c279a49288`: SDK нет, внешней QA-службы нет, main/work
отключены, GUI закрыт. Win10 запущена на builder snapshot
`9b7b48f0-bff0-48fe-8e4f-7e79ede7c77b`. Её чистая R6 test branch сохранена как
`b7c15b10-f315-4c79-b455-3ad61892dea2`. Windows VM работают последовательно.

После упаковки R7 остаются native conflict/manual route+DNS/external tests,
LAN/container overlap и foreign DNS scenarios, актуальные engine/fault/boot/UI
проверки Windows 10, coherent lifecycle/foreign-WFP/uninstall/reinstall на обеих
ОС и финальная консолидация evidence. Старые PASS не объявлять полным PASS R7.
Рефлексия22:21 UTC выполнена; следующая22:51 UTC. Приоритет — установщик R7,
без дальнейшего развития QA-службы до проверки самого кандидата.


## Coherent R7 Win10, checkpoint23:30 UTC

На clean Win10 безSDK interactive upgrade14 PASS22:52:18, сохранены профили всех
SID/UID; existing standard qa2 сохранён без password reset. Evidence:
`native-win10-r7/interactive-upgrade/`. Main-all139 PASS22:55:29, затем три work VPN
с реальным HTTP4/6/DNS и main coexistence verify22 PASS22:56:16:
`r7-protocols/`. Новые controller exit-code checks не игнорируют failed child.
Main pcap2070frames даёт0direct в пяти verify окнах по всем8classes, но fresh
positive controls только6/8: нет DNS6 UDP/TCP baseline. Анализ
`r7-main-pcap-analysis.json` честно INCONCLUSIVE_POSITIVE_CONTROLS, не full leak PASS.

Первые два route-case не засчитаны. Attempt1 завершился RPC unknown/timeout на
explicit-openvpn-owner (причина не доказана); attempt2 использовал pooled HTTP
соединения и завершился HTTP failure. Его первоначальный result был экспортирован
до finally; отдельный `route-conflict-attempt2/observed-final-state.json` сохраняет
completed=true/passed=false/restored=false: OpenVPN error/retry_wait, metadata до
auth и затем `work adapter name is already in use`. Потребовались explicit work
stop и SCM stop/start; это не объявлено исправленным источником auth failure.
Сохранены `before-service-recovery.json`, `r7-openvpn-recovery-logs.json` и manual
packet facts. Отдельные protection13 и recovery23 PASS в23:15–23:18, затем реальный
OpenVPN connect восстановил main+три work. Capture/metadata экспортированы, однако
само их наличие не заменяет packet analysis и не означает whole fault matrix PASS.

Свежий route-case23:20:05–23:22:46 завершён complete/passed/restored=true:
16checks/9steps, full WG incumbent → full OpenVPN conflict retains incumbent →
explicit OpenVPN owner → explicit WG owner → exact new-rule cleanup и возврат
трёх original split VPN с реальным трафиком. Evidence
`route-conflict-fresh/result.json`. `r7-route-fresh-packet-analysis.json` —scoped
routeTransport PASS: реальные новые OpenVPN TCP4/6 SYN/SYNACK+TLS, затем новые WG
соединения. Inner WG/OVPN traffic отделён от physical fixture0;8physicalclasses0.
Не заявляется полный eight-class leak PASS: DNS6 fresh baseline отсутствует и
не каждая forced-physical negative probe выполнялась в этом route-case.

Overlap baseline/run/admin-remove/recovery пока не засчитаны: guest результаты
ещё не экспортированы на этот checkpoint. Сообщённое удаление23:30:06 и0IP не
подменяют окончательный экспорт/проверку recovery. Root продолжает этот сценарий.
Win11 остаётся выключенной на clean checkpoint201; R7 там ещё не принят.
Рефлексия23:21 выполнена, следующий контроль23:51. Остальная матрица pending;
этим обновлением изменены только progress7 и acceptance6, без VM/product/candidate.


## Остановка по просьбе пользователя — handoff для завтра

Создан [самодостаточный checkpoint](WINDOWS-PORT-CHECKPOINT-2026-11-07.md).
Новые тесты/исследования/сборки не запускать; root завершает только текущий
external IPv6-only/cleanup, затем all-VPN-off, snapshot и все VM OFF.
Финальные факты: Win10 snapshot `703732cb-4d42-4b0a-b5b7-dfa9c7183a2d`, все три
VM poweroff подтверждены23:52:09 UTC. Main/work явно отключены, guardfalse,
временный IP, external service/adapter/binding отсутствуют; профили сохранены.

Теперь экспортирован `native-win10-r7/r7-overlap/`: baseline PASS, run14 PASS,
recovered6 PASS, exact UAC add23:27:07/remove23:30:06 и0secondaryIP. Это один
IPv4 connected-prefix overlap, не Docker/HNS/NAT/IPv6 acceptance. External dual
root подтвердил11PASS (verifiedFull4/6, corp/defaultHTTP4/6, defaultDNS+WGzone,
mainpaused); admin и ordinary reports экспортированы. IPv6-only не дошёл до
проверки приложения: QA helper allowlist не разрешает `redirect-gateway ipv6 !ipv4`.
Cleanup23:46:34 и ordinary afterstop/main verify22 PASS; это завершённый и очищенный
тест с оставшимся неподтверждённым IPv6-only пунктом, без новой правки сегодня.

DNS6 helper подготовлен, НЕ запускался; gap6/8 остаётся. Ранние route RPC/HTTP/
auth-metadata/name-in-use/failed-restore не скрыты успешным fresh16/restoredtrue.
Source69d82/candidate491085 неизменны. Завтра использовать готовый R7, не пересобирать
ради docs; остаток полной матрицы и безопасные existing QA paths записаны в checkpoint.


## Возобновление 7 ноября, 09:04 UTC (12:04 МСК)

Пользователь явно разрешил продолжить с checkpoint. Предыдущая остановка снята.
Frozen R7 installer/manifest/source SHA256SUMS проверены, все три VM были OFF.
Fixture CA действителен до 2026-11-07 23:11:28 UTC; пока не регенерирован.

- Win10 clean R7 запущен без restore. Все VPN при старте disconnected, guard=false.
- Fixture transient servers после cold boot не поднялись; запущены сохранёнными
  staging scripts. Обнаружены устаревшие staging: main DNS без IPv6 listener и
  старый e2e-fixture без UDP18081. Обновлены из текущих исходников, не меняя keys.
- Два physical DNS6 controls UDP/TCP PASS09:07:55; packet request/response ID
  корреляция PASS. `native-win10-r7/r7-dns6-positive*.json/pcap`, pcap SHA
  cef68c2058d5202f701eb9235660f0e5c0711a68e9253047def830a79e7d4e28.
  Первая попытка FAILED из-за absent DNS6 listener, ICMPv6 port-unreachable,
  сохранена отдельно. Дополнительный контроль получен в новом capture/date;
  исходная отрицательная серия R7 не переписывается.
- QA external helper allowlist разрешает дополнительно ровно
  `redirect-gateway ipv6 !ipv4`; production/frozenR7 не менялся.
  QA PE b9237d65249bbc5b23b2d98d95e1b75af857940b5b98dfbaf236832244bca084.
  External dual11 PASS09:10, IPv6-only11 PASS09:11:53: verifiedFull6/notFull4,
  main paused_external+guard, corpHTTP4/6, DNS, defaultHTTPS6, noIPv4response,
  rootDNS+specificWGzone. Exact cleanup PASS09:13:17 service/adapter/binding0.
  Первая afterstop traffic серия failedUDP из-за старого fixture binary;
  updater web-only выполнен без main RequestConnect/SCM restart. Повтор в работе.
- Два product файла OpenVPN получили строгий HOLD/stateACK/logACK/releaseACK
  startup barrier и independent process stop budget/late confirmed-exit cleanup.
  Native Windows10 focused units PASS, Linux full regression PASS. Root+второй
  read-only reviewer проверили pinned OpenVPN command echo before releaseACK.
  Историческая причина metadata-before-auth всё ещё не доказана; нужен реальный
  повтор восстановления до заявления об исправлении. Готовится отдельный R8;
  R7 frozen files сохраняются.


Завершение resume R7: afterstop повтор PASS09:14–09:15, без RequestConnect;
предыдущий UDP fixture failure сохранён. External evidence экспортирован в
`native-win10-r7/external-resume-20261107/`, `completed-reports/` содержит финальные
report версии (earlier `final-reports/` мог содержать in-progress copy).
Clean Win10 final-state PASS09:16:17: disconnected/guardfalse/work0/external0.
Штатный shutdown09:16:51 (GuestControl exit1 из-за завершения ОС, VBoxpoweroff
подтверждён), snapshot `037f3924-b30b-4bc2-84f7-e262a70dc023`,
`r7-resume-complete-2026-11-07`. R8 builder использует отдельную ветку cf984.

Offline external capture review PASS_SCOPED:5941frames/0truncation/decode/fragment;
fresh dual443IPv4+IPv6 иv6only443IPv6 имеют SYN/SYNACK+двусторонний TLS через OVPN.
Physical defaultIPv4target TCP/UDP0 в обоих окнах. Отчёт
`external-resume-20261107/r7-external-resume-packet-analysis.json`, SHA
`e888684068bfb8c7b4b12357fd8c657e3280a3efeb0750e56a876ec6f739eed7`.
Это ограниченный proof actualHTTP, не полная fault/UDP/DNS-negative матрица;
endpointLAN192.0.2.1 не доказывает необходимость offlink exception.


## Кандидат R8 и начало native acceptance

Frozen directory `dist/windows/candidate-2026-11-07-r8`,208434238bytes,
installer12896544881b15553c8b8c60d3f07d09f8e9ff02ec64f856e1583551b1d5ca3e,
manifestbc6692d6939e0798de19465963e24de765eb84938b33866e4e295ea5bba65f19,
source957c7399aef10e067e593b66120a5cf9a67476ee446b19734e3bd7848e2d35c2.
Native cached GUI/package PASS09:18:08–09:20:05UTC; root SHA256SUMS allOK.
BuilderR8 snapshot25c4a997-e0dc-4f94-b081-da2b938fdf30. CleanR7 restored037f3924.
Win10 R7→R8 upgrade14 PASS09:24:57, existingqa2 preserved/passworduntouched,
global5main+5work retained, exactbackend4a7998/manifestbc6692, noSDK.

QA bundle46files: dist/windows/qa-source-r8-inventory.json,
zipSHAe38f8b5ca3fd1dabc341c5bc51358bb3255c276f1288dc06418ceb0094c7b699.
All43PS5scripts parsedPASS. Later QA patches (engine runner workID regex,
foreignNRPT recovery, recoverycontroller) are postbundle/postfreeze and must be
staged separately with their hashes; productcandidate unchanged.

Root QA controller initial failure09:27: PowerShell function used reserved
`$Args` parameter, causing RPC argumentloss before connection steps. Fixed to
`$Parameters`, failedattempt archived; not a product failure. EnhancedQA runner
initially accepted onlymainIDs; reviewerroot caught workIDprefix omission before
fault execution, fixed selector-aware patterns. Protected VM runner still needs
refresh at next explicit QA UAC; no enginefault claim with oldrunner.

R8Win10 integration: initialWGmulti/AWG/OpenVPN4/6DNSrealPASS09:28:34,
mainrecovery23PASS09:28:55. Full-work10steps completePASS/restoredtrue09:32,
WGfull+OVPNfull pausemain→disconnect→autoResume verifiedrealtraffic.
Rootcompoundcontroller180s wait exceeded near childfinish; child NOT killed,
independentchildreportPASS10/restored preserved. Parentfailure retained, future
compoundwait360s; nofull-case repeat, nextunrunrouteconflict launched09:32.
QArefresh fixedrunnerbfcdfd PASS09:31:40, exactforeignWFPfixture installed;
qa2IDexportfirstname correctbutemptycollectionsserialized[""] (QAexportbug),
strictownbaselinewillbereexportedwithschema/source/uid andemptyarrayfilter before
reuseisolation. No engine fault oruserreuse claimed yet.


09:34UTC: начата обязательная независимая reflection30min, readonly≤5min.
До неё scope: installerR8+actualWin10acceptance, затемWin11. Rootнамерен
остановить дальнейшее расширениеQA, использовать подготовленныесценарии,
неповторятьfullwork10 радиrootdeadlinefailure. Currentroute8/16nativepending.
WFPforeignexactGUID{F8BF4EC5-4A1B-448C-B2BE-7570BDF42ED0} установленUAC09:31,
долженпережитьservice restart/uninstall-abort; cleanupтолькочерезownhelper57f5.

Reflection09:34 завершена≤5мин: focusсохранён, directinstaller/nativeprogress;
заморозитьновыеQAframeworks/абстракции/версииresearch. Использоватьготовые
сценарии; правитьтолькореальныйblocker. Ближайшийшаг—routecompleted/restored,
одинexactOpenVPNcrash→newPID→autorecoveryHTTP4/6DNS, thenexistingmatrixWin10→Win11.
Необъявлятьисторическуюauthгонкуисследованнойбезвоспроизведения. Scopeнеурезан.
Следующаяreflectionеслиработапродолжитсяпосле10:04UTC (13:04МСК).

R8 routefresh completePASS16checks/9steps/restoredtrue, exported
native-win10-r8/route-conflict/. ExactOpenVPNfaultattemptbaselinepassedmain22+
all3work4/6DNS, butfixedSYSQA task failed beforekill withRuntimeException/details{}.
Daemon5432 andOVPN4500 unchanged09:38; installedrunnerbfcdfd exact.
ThisisQAblocker, NOTproductcrashfailure; readonlydiagnostic≤5mininpreparation.


R8Win10 продолжение: SCMstop/crash/NIC10steps11checksPASS/restoredtrue,
IPC-admissionPASS, exactOVPNchildKill498809:50:09confirmed→new165609:50:15,
daemon604unchanged; enginefaultcontroller15PASS/noRequestConnect, all3workreal
traffic4/6DNSrestored. NativeUID1profilepinscorrect. QAACLfalse-refusalисправлен:
publicappTrustedInstallerтеперьпризнан, private/QAACLнеослаблены. Runner880a27…
иreadonlyselectorallchecksPASS09:48:30. UI6casesEN/RUreal100/150/200PASS09:51:39,
все6statusPNGосмотреныroot: кнопки/тексты/масштабкорректны, профилидлинные
ellipsisожидаем, noUIproductchanges. FinalOSscale150 восстановлен.

ContinuousR8capture09:25:53→controlledstop09:52:00, PID4505/invf0841565…/N0,
14818frames/no trunc/decode/fragment. BoundedpacketproofSHAc31e9c49fa5abf961ac17cc66d2796964764b3a56fa402f1bb7964c85c01c602
PASS_SCOPED_WITH_SEPARATE_POSITIVES:15mainwindows8physicalclasses0,
freshOVPN4/6TLS→WG4/6TLS, SCMStopped13, exactOVPNkill→realHTTP4/6restore.
PositivecontrolsseparateR7six+todayDNS6; noearlyboot/inboundclaim.

PrebootinspectWFPexactforeignGUID F8BF4EC5-4A1B-448C-B2BE-7570BDF42ED0
exists09:55:23afterallfaults; preSCMtaskarmed09:55:29, serviceManualreadback.
BootcapturePID4843/inv00368a3b88ed4b50ad98a3e09f41c5f6/N0start09:55:21.
Реальныйrebootзапрошенпослеarm; resultpending. ЭтоpostBFE/preVault443proof,
неприписыватьearlypreBFE.


10:04UTCreflection2≤5min: realacceptanceprogresscontinues, noadditionalproduct
work. Finishboot2→users→remainingmatrix→Win11; nofullreruns/newbuildunlessdefect.

Host incident10:06–10:23UTC: CLI reportedoff/oldcleanstate while bothoriginal
VBoxHeadless andoriginalSvc/IPCDalive. OriginalIPCDfd3lockdeleted, fd4socket
unlinked; newIPCdaemonlistenerreplacedpathname. Guestdata-planeSSHkeptworking.
Noevidenceofappfailure. NoVMrestore/newVDIopen/kill9 performed. Default-sandbox
VBoxCOMcalls are a suspected cause, not proved. ALL VBoxCOMcalls evenhelp must
run escalated; privateVBOX_USER_HOME alone doesnotisolatedefaultIPC.

Official7.0.16sourcearchiveca9062daf386a1810282503f83a7baa296ad46c4fc38aa988bca57f037e811fb
verified againstOracleSHA256SUMS; exactHeadlesssource5dcc9b82…55f3343 confirms
SIGUSR1 caught→SaveState onRunning machine. Exactfrontend76404/UUIDchecked,
handlerregistered/free12.1GBchecked; SIGUSR1sent10:21:07. NativeVBoxlogSaved10:21:44,
3.5GBstatefile2026-11-07T10-21-07-530232000Z.sav. Linuxfixture shutdown viaSSH,
alloldVBoxprocessesexitednormally. Nohardpoweroff. Hostsourceproof/receipts under
`dist/windows/host-ipc-recovery-20261107/`. New project namespace now
`VBOX_IPC_SOCKETID=vault443-1000`, togetherwithprivateVBOX_USER_HOME;
vm.py/fixture_vm.py setitautomatically (postR8freeze tooling-only). CLI sees
Win10Saved correctly10:23. Rootwillstartfixture+healththenresumeWindowsSaved;
originalboot2reportstillinguestnotyetexported, doNOTclaimPASSuntilread.
Bootcapture4843/N0stopped10:17:42/exported evenwithlostIPC.

Recoveryfixturecoldstart/resume_fixture.py PASScomplete(all9services/listeners)
10:28receiptcopiedhost-ipc-recovery/fixture-resume-complete.json. Win10Saved
возобновляетсячерезprojectIPC, нечерезsnapshotrestore. Нативныйboot2report
внутриguestдолженбытьпрочитанпослеresumeдоPASSclaim. Никакихfreshroute/UI/SCM
повторовиз-заhostcontrolincident, толькоresumedhealthиоставшаясяматрица.

10:34UTC обязательная reflection3 завершена: инцидент host IPC закрыт;
закончить owner-return и переходить к Win11, не повторять уже успешные Win10
сценарии и не расширять QA architecture. Следующая reflection11:04UTC.

Оригинальный boot2 report экспортирован после SaveState/resume: PASS,
bootUTC10:03:54.500, Automatic service2836, GUI6360/session1, main recovery23
и три рабочих VPN с реальными IPv4/IPv6/DNS без RequestConnect/StartService.
Completed10:05:43.5256153Z; `native-win10-r8/boot/boot2-verify.json`.
После host recovery контроль10:31 подтвердил те же подключения.

User isolation R8: existing standard qa2 native session2 reuse PASS10:39:35,
без сброса пароля, импорта, очистки store и TakeControl. Exact own-ID baseline
экспортирован из защищённого store; совпадающий content-ID между UID допустим,
все непересекающиеся owner IDs проверены. Первая попытка выявила QA bug:
JSON null коллекции PowerShell превращал в один null ID. Исправлен только
Assert-ExpectedOwnIDs (foreach null -> zero elements); native parser PASS,
исходный отказ сохранён. Повторный owner capture10:48:30 PASS4: active main,
guard, trafficSessionId и servicePID2836 прежние. Независимый CIM creationUTC
10:04:01.5164930Z предшествует capture10:34; непрерывность daemon подтверждена.
Ordinary helper не может читать process times LocalSystem и возвращает0,
поэтому этот ноль сам по себе не является доказательством creation continuity.
Артефакты: `native-win10-r8/user2/`, `owner-continuity/`.
Возврат через Windows LogonUI сначала неуспешен из-за ввода до готовности поля;
после явного выбора owner tile, ожидания и проверки поля вход успешен. Пароль
не менялся. Дальше явный disconnect, OFF snapshot R8 и Win11 R8 upgrade.

10:49–10:54UTC closing Win10: intentional foreign WFP fixture outside ownership
journal caused final work guard removal FWP_E_IN_USE. This is expected preservation,
not an OpenVPN teardown regression. WFP transaction abort means owned filters and
final routes/DNS were NOT yet cleaned; no false cleanup claim. Protected log read
confirmed exact native error. Native UAC uninstall-abort PASS9 completed10:54:18:
exact GUIDF8BF4EC5-4A1B-448C-B2BE-7570BDF42ED0 exists before/after, uninstallerexit1,
service retained, exact global10profileIDs and1768appfilenames preserved. Known
QA helper57f5 verified complete identity then removed ONLY that fixture GUID;
postlookupabsent. Explicit disconnect afterservice-start PASS10:54:50: main/work
all disconnected, guardfalse. No product edits/rebuild. Reports+actual temporary
controllers saved `native-win10-r8/foreign-abort/`, `controllers/`, off-preflight.
The first-off refusal is retained separately. Normal uninstall/reinstall remains.
Read-only boot pcap analysis complete:5044frames/no errors, exactpreSCM13 and both
boot verifies direct8classes0, bidirectionaloutertraffic. ResultSHAe96726bbe191cc194e72ce4d91678623cda44211151046095414f8264a147301,
PASS_SCOPED_POST_BFE_WITH_SEPARATE_POSITIVES; no earlypreBFE claim.
Fresh Win11 QA overlay52inputs/49PS prepared with exactfrozeninstaller/publicCA;
SHA7305e9427f36bf05d6e0609f5dd84fe718bd4bf5f8b6f1c0bbc30379b167b514,
per-file inventory+postfreezeprovenance in dist/windows/qa-overlay-win11-r8-*.

10:57UTC Win10 OFF snapshot e4cca188-981f-4cd3-b4f6-bd0d72f12194,
r8-win10-acceptance-checkpoint-2026-11-07. ACPI first had no shutdown effect;
ordinary shutdown.exe /s /t0 completed normally, no hard poweroff. Win11 started
sequentially after confirmedWin10OFF, stillR6 beforeinteractiveR8upgrade.

Win11 R8 native interactiveupgrade14 PASS11:00:30, clean/noSDK, existingqa2
preserved/passwordTouchedfalse. Overlay52inputs/49PS hashes/nativePS5parser PASS;
activeconsole1 afterboot. Capturingfixture0 since11:00:00UTC:
unitvault443-r8-win11-capture, PID3193/invc5ad391a519e4e06b19ae4cb7fe64c73/N0,
RuntimeMaxSec5400, unrestrictedfixture0Ethernet. Mainall+DNS6freshcontrols→existing
R8main/3work/full/routecontroller launched11:01, outputsr8-protocols/r8-outputs.
No SDK/Qt/product rebuild. Win10OFFsnapshot e4cca188 remainspreserved.

Reflection11:04UTC (readonly≤5min) завершена: фокусinstaller+двеОСсохранён.
Не пересобирать R8/не повторять готовый Win10 integration. Один boundedactual
IP/DNSchange scenario оправдан отсутствующей строкой; безnetworkframework/DHCPRA
server. Rootближайшийшаг—текущийWin11main→3work/full/routecompleted+restored.
InitialWin11batchQApreflight11:01failedstringGUID-vs-Guid equalitybeforeanytest;
actualGUID/MACmatched, castleftfixed. Failedreportpreserved. FreshDNS6positive
UDP/TCPPASS11:02:58; mainallnativephaseRUNNING. Nextreflection11:34UTC.

Win11 R8 completed nativeintegration11:10:20: freshDNS6positiveUDP/TCP,
main139PASS11:04:36 (allfourmainfamilies/import/switch/subscription/guard),
mainrecovery23+WGmulti/AWG/OpenVPNreal4/6DNS, fullwork10/restoredtrue,
routeconflict16checks/9steps/restoredtrue. Exported native-win11-r8/integration/.
ManualnativeGUI: systemfilepicker ownerLocalAppData/qa-ui-import existingOVPN
selection→Already addedpreview/privatekeysnotdisplayed→Cancel; trayiconvisible.
PNG+manualreceiptin native-win11-r8. AppUAChelper pinnedba857: GUIbootOffPASS
11:14:49→SettingsselectVLESS/Apply/UAC→OnPASS11:16:23; mainID+trafficSession
1794049480053791700-6 unchanged. NativeGUI normalCtrlQPASS11:17:32.
Existingqa2baselineprotectedexport(noimport/passwordreset), foreignWFPfixture
{8CE0BA94-4F2C-469D-8EB8-58435F7F6223} installed11:11:41 forfault/boot/abort;
exactGUIDmustsurviveandlatercleanupONLYknownhelper57f5.
IPC25nativePASS11:17:52; servicefault→exactOVPNfault→UI6currentrunning.

One newQAfile r8-network-change.ps1 createdpostfreeze foractualstaticIP+resolver
change missingrow, noDHCP/RDNSSclaim. Independentreview caughtfalsepositiveTCP
port18080→8080, ownershipwrite-aheadandboundedDNSintermediaterecovery fixes;
rootnativePS5parser caught catch-token whitespace beforeanymutation. Fixedsingle
space, finalQA SHAec28fe0c4a04c7189ca2ba089142d18e768d116e56301ad6dc1c1b3ce3deb26f,
nativePS5ParseFilePASS11:16. NO nativeIP/DNSchange executed yet. Priorparsefailure
and subsequentbadIPChelperpath were QA-only beforeIPCstart; corrected pathfrom
qa-source-r8 thenIPC25PASS. Frozen productR8/archives unchanged.

Win11 R8 fault/UIbatch completedPASS11:25:12: SCM/NIC10steps11checks/restored,
exactOVPNengine3056terminated→autorecovery15PASS11:24:14/noRequestConnect,
UI6realOSscale/languagecasesPASS. All6statusPNGs viewedroot(text/buttons/scalefit),
actualru200 preserved underru200-at200. Normalquitbeforematrix/closehide/reopen/
quit allPASS, finalOSscale150. Exported native-win11-r8/fault-ui/.
ActualnetworkQAattempt1 11:27 changedIPs .3/::3 butDNSreadbackfailed because
SetDnsClientServerAddress(v6only) retains IPv4family. finally restoredIPs .2/::2,
but oldsetter(v4only) leftIPv6DNS; cleanupfailed, preservedQAfailedreport.
No productfailureclaimed. QAfixfamily-scopedCimInputObject setters/reset; newSHA
fb74e5291ab715861457ffa2badb00ffa555d48fadf2bfbfd5ceaafe23d55d6e,
nativePS5ParseFilePASS. ExistingprivatejournalusedsameUACrestorePASS11:31:26:
original2IPs+IPv4DNS.1/IPv6empty restored; signalrestored/token77ce2a3f...,
ordinaryrealtrafficverifyrestored started. Newactualnetworkchange MUST wait for
thisverify and archiveonlyownrestoredjournal/signal; firstattemptnotacceptancePASS.

Reflection11:34UTCreadonly≤5min: focusnativeacceptancesaved; finishrestoredverify,
ONEfreshcorrectedactualchange/exactrestore; no harness expansion/faultswhileIPs
changed. Thenexistingenginecontrollers/boot/users/lifecycle, noOpenVPN/UI139repeat.
Nextreflection12:04UTC. Ordinaryrestoredrealverify22PASS11:32:52.890: all main
HTTP4/6UDP4/6DNSA/AAAATCP/UDP,8directnegatives,3workrealhelpers, samewindowtoken.
Nativeengine-matrix ParseFilePASS; orchestratorSHA63817810158b22ca5a2c9faed3359399573cc6c3b1622a958fb6bd2801767681,
6remainingcases/noOVPNrepeat. Notstarteduntilnetworkrestorecomplete.
Beforearchive/retry rootmistyped exactverifyreportfilename(.890vsactual.909);
noticed fromnativeenumerationBEFOREapproval, cancelledUAC, corrected/rehashed,
relaunched; nojournal/networkmutationfromcancelledattempt. RetrycontrollerSHA
5a74d379b1a706f9eebdc95325f717a8d2bff69c5734b21dc07b29ba3983f43a
movesONLYknownrestoredtoken77ce...journal/signal preservingACLs/history, requires
actual22PASSreport, theninvokes reviewedfb74networkQA Hold240. No productedits.

FreshnetworkretryownTOKEN1a12b64b-10da-4fe9-9ecf-fb55a3f0c80a changed11:36:11,
IPs192.0.2.3/2001:db8:44::3 + onlyphysicalIPv6DNS2001:db8:44::1 confirmed.
Ordinarychanged22PASS11:37:06.128: actualmain4/6HTTPUDP/splitDNS/work3,
8directphysicalnegativechecks, samecompletewindowtoken/noRequestConnect.
Boundedholduntil~11:40:11; exactautomaticrestore+restoredverifyremainpending.
Continuousfixturecapture3193/N0 stillactive/unrestrictedfixture0 includesold/newIPs.

Win11 user2 reuse55PASS11:47:44/nativeconsole2; ownerreturncapture4PASS11:50:09,
samePID/creation/activeID/trafficSession exact. Reports exporteduser2/owner-continuity.
A nativeinactiveownerRPC duringqa2session was correctlydenied activeconsole;
not an appfailure. Firstqa2loginentry went todefaultownerafterLogonUIidle timeout,
acknowledged/reselectedqa2/delay2sec/typedpromptly→success; no passwordreset.
Engine6attempt11:41safe-preflightfailedbeforeanymutation: Outline modelkind is
shadowsocks, not outline. Fixed QA typechecks only; actualnativeexistingOutline
was transporttcp/sourcekindoutline (optimizedsimpleSS), so separatehelperdidnotrun.
Pinnedsource permitsONEbyteprefixV inAEADsalt usingSAMEexistingSS8388/key/cipher;
privatefixture-responseatomicallyaddedprefix/no existingfieldchanged, fixture-server
QA source/stagingupdated forrepeatability. No newserver/container/protocol/product.
RequestSourceRefresh SAMEexistingOutlineIDee9f... confirmedkindshadowsocks/
transportoutline/sourcekindoutline withmainVLESSunchanged. NativePS5parse3QAfiles
PASS, UACbootstrapprotectedrunner733f...PASS11:53:33, noUserBootstrap/password/product
changes. Currentfaultcontroller29cc..., matrix2a65..., diagnosticpin133b...;
newmatrix started11:54:19; firstexactXrayVLESSfaultPASS11:55, nextTrojaninprogress.
Oldpreflightfailedreportkept; no priorOutlinehelperPASSclaimed.

Win11 networkarchive exported afterseparatestatuspathQAerror: actualengine-matrix
reporttimestamped (*-result.json), notresult.json; noactiveprocessinterrupted.
Actualchange+restore44PASS andCIMservice5876/creation11:19:53.990 continuity saved.
Currentmatrix2a65report20261107T115419999Z: XrayVLESS/Trojan PASS11:57;
Shadowsocksnext, no productfailure. Win11bootarmtemporarycontrollerprepared
using EXACTforeignGUID8CE0...; NOTarmed/rebootedwhileenginecasesrunning.

Reflection12:04UTCreadonly≤5min: всё ещё nativeacceptance; прекратитьfixture/runner
развитиепослеуспеха, сократитьдлинныйанализмеждуtools. БлижайшийшагAWG/finalrestore,
одинэкспорт→preparedboots/остаток. Следующаяreflection12:34UTC.
Win11engine6matrix2a65 completedPASS/restoredtrue by12:03:37: exactXrayVLESS,
Trojan,SS,realOutlinehelper(prefixV),WGmulti,AWG; noOVPNrepeat. Corecompletebundle
exported/extracted native-win11-r8/core-through-engines/. Firstcontinuouscapture
PID3193/invc5ad391a519e4e06b19ae4cb7fe64c73/N0 controlledstop12:04:25.071,
22274167bytesSHA5fcc02c4bb3898879cb68c6619a1ae67d7f927648d4f72f369137c3f9822152c;
offlineboundedanalysisdelegated,noVMactions. Newbootcapture3752/invb0cb9f8e65594fff9155b340a3658762/N0
started12:03:29beforeoldstop (overlap, no gap), RuntimeMax1800sec.
Win11bootarmUACinprogress, firstrebootnotyetrequested. ExactforeignGUID8CE0...,
mainVLESS+3work restored, BootProfileVLESS alreadyselectedthroughproductUAC.
SmallQA-delta227838bytesSHA9da67d9a3efa8d04b3d2b06214bddeecb4abe76180bb3849bd39dd7d356e89ef
readyforWin10/currentfinalprovenance; noinstaller/CA/keys/product/source.zip.

Win11bootarmPASS12:05:43, exactforeignGUID8CE0...exists12:05:37 afterallfaults.
TemporarySCMManualreadback, originalAuto/delayed0journalled; taskVault443-QA-r8-prescm
armedmainf203. Firstrealrebootrequestedafter12:06:45; bootcapture3752N0alreadyactive.
Do NOTStartService/RequestConnectbeforeoriginalstartupreportread; wrapperrestores
Auto andstartsonlyafterpreSCM13. This remainspostBFE/preVault, notpreBFEproof.

Win11 corepacketanalysis SHA436958c15d01f2ec89fc0c2c6e6af58aba80526508552b94082040d6c738d74d
PASS_SCOPED_PHYSICAL_NEGATIVES_AND_SAME_CAPTURE_POSITIVES:61227frames/no trunc,
decode/fragment; SAMEcapture8freshpositives(inclDNS6queryID+ports),38mainwindows
8physicalclasses0,7exactenginekill→completewindows0(inclactualOutlinehelper),
successfulnew.3/::3changed22+old.2/::2restored22all8classes0+encryptedouterfromnew/oldIPs;
SCMStopped0. Route16/9nativefreshpeer4/6+outerflows; noinnerSYN/TLSinfixture0Ethernet
claim. EarlierfailedQAattemptsnotPASS; noearlyboot/inboundclaim. Reportpath
native-win11-r8/r8-win11-packet-analysis.json; separatebootcapturecontinues.

Win11 firstboot nativepreSCM13 PASS: actualboot12:07:21.500, wrapperstarted12:07:42,
completed12:08:16.338, restoredtrue/taskRemovedtrue/inconclusivefalse/noerrors.
BFE/physicaldualstackready, Vault443StoppedPID0/engines0throughprobes; originalAuto
restoredthenSCMstartedbyownedstartupwrapper. Ordinaryboot1realmain+3workverify
launched12:09 afterreadingoriginalreport; noRequestConnect/StartService fromroot.

Win11 boot1 ordinary verification PASS12:14:56.122: main recovery23 + WGmulti/AWG/
OpenVPN actual4/6/DNS + oneGUI/session1; noRequestConnect/StartService. Initial
attempt12:09 failed only QA cachedifIndex11 vs actual13; protected preSCM GUID/MAC
and unchanged IP bytes verified, linklocal scope follows13, positiveUTC retained
11:03:02, newPositiveControlClaimedfalse. Initialfailure/originalcache preserved.
Boot2 normalSCMAuto reboot requested12:18; report+boot1bundle saved BEFOREshutdown;
GuestControl exit1 duringshutdown is not itself a completed boot failure. Native
screen Restarting12:19:48; noforcedreset/manualservice/appconnect. Capture3752N0
stillactive. Hostdisk4.8GiBfree; avoid unnecessary duplicate archives/snapshots.

Win11 boot2 firstordinaryattempt did NOTcompletewithin5min: nativeRestarting,
GAcleanstop12:18:48, VBoxrunning/nohosterror. Evidenceboot2-shutdown-delay/ saved;
controlledcapture3752stop~12:23:40 SHA0c749a6e...b384. RootrequestedisolatedVMreset
~12:23:55 forrecovery, resetcommandstillpending12:24. Not a normalbootPASS;
causalityunknown. Afterrecovery readprivate service.log(.previous)+SCM/System
timeline; no speculativeproductchange. Firstboot1 preSCM13+ordinaryrealverifyremainPASS.

12:29UTC recovery: ResetRPCstalled>2min; documentedSIGUSR1frontendSaveState also
stalled>2min/Saving/no.savcreated. ExactPID330341/startticks709203/UUID10c845...
verified; onlythatQAfrontendforcedstop12:29:16. NoVBoxSVC/fixture/hostservicekill,
noVDIrollback; lastVDIwrite12:18:54. StateAbortedconfirmed, samecurrentdiskcoldstart
succeeded12:29. ThisdoesNOTpassnormalboot2. Fullreceipts+VBoxlogs in
native-win11-r8/boot2-shutdown-delay/. Disposabletmpinstallerduplicatesonly
removedafterSHAverificationagainstpreservedfrozencandidate (~834MB); QA scriptskept.

Reflection12:34UTC readonly≤5min: scope correct; one bounded normal reboot retry,
no thirdloop or VirtualBoxresearch ifrepeatfail; coldbootNOTsubstituteforordinary.
No newproductbuild/settings/frameworkwithoutidentifiedcause. Next13:04UTC.
Attempt2 normalRestartrequested12:33:46.140, actualnewboot12:33:59.500 (13.36s),
SCMAutoRunningPID3312 readback12:34, noRequestConnect/manualStartService.
Ordinaryboot2trafficverify nowrunning; noPASSbeforefinishedreport. Initialattempt
stillretainedasincident: WindowsDiagnosticsShutdownEnd12:18:54.052/9558ms,
Services5012ms/Kernel814ms; exactlaterfreeze/VirtualBoxResetSaveStatereasonunknown.

Win11 ordinaryboot2 attempt2 PASS12:35:32.778: actualboot12:33:59.500, mainrecovery23
+3workrealtraffic+oneGUI8756/session1; noConnect/manualServiceStart. QAifIndex13→12
boundedGUIDMAC/sameIPbytesrebind; originalpositiveUTC11:03 retained/no newcontrol.
Reports exportedboot2/, firstdelayedattempt preserved separately, causestillunknown.
Partial-peer ordinarybaseline launchedaftercompletedbootverify, nooverlapfaults.

Win11 partial baseline29 PASS12:37:09.516, exactSCM3312/creation12:34:07.606880,
mainVLESS+WGmulti/AWG/OVPN realtraffic. Hostorchestrator started12:37:38, exact
ownednftDROPfixture0UDP51822 created12:37:54; blockedphasewaitingpeer2stale,
peer151820 unaffected, noappConnect/Reset/networkchange. Finallytokenownedcleanup
ispartofhostcontroller; one tailcapture4376N0 alreadycoverswindow.

Win11 partial-peer completePASS/restored: baseline29, blocked29, recovered29;
exactUDP51822DROP countersinput22packets/3872bytes, finallytable+ownjournalremoved,
SCM3312/creation+owner/profilecontinuitypreserved/noConnectReset. Token/readable
reports native-win11-r8/r8-outputs/partial/. Newpeer2handshake/recoveredallwork
proved. ThenONLYbuiltinOVPNsplit explicitlydisconnected as externalfixture setup
(sharedtestcert), main/WGmulti/AWGkept; externaldualUACapproved.

Win11 externaldual setupPASS12:43:39, ordinary11PASS12:43:51.615: verifiedmanual
corp-external/fullIPv4+IPv6, mainpaused_external/guardtrue; freshdefaultHTTPS4/6,
corpHTTP4/6+splitDNS andotherworkDNS preserved. IPv6only UACnextapproved; no
productchanges. All9newtailQAcontrollers/wrappers nativePS5parse0errors.

Win11 externalIPv6only ordinary11PASS12:45:19.569: verifiedfullIPv6true/fullIPv4false,
mainpaused_external/guardtrue, freshHTTPS6/corpHTTP4/6/DNS/workDNS, directdefault4
noresponse. UACexactcleanupnextapproved; afterstopautomaticmainverifypending.
LANfixtureendpointdoesnotproveofflinkendpoint-exceptionnecessity; scopequalified.

Win11 externalcleanupPASS12:46:22, afterstop2PASS12:46:45.678 includesmainreal
verify22 auto/noRequestConnect; service+corp-externaladaptergone/bindingremoved.
Fullsanitizedarchiveexportedexternal/. OnlythenoriginalbuiltinOVPNID restored
viaexplicitRequestWorkConnect asoverlapsetup. OverlapbaselinePASS12:47:04.980,
UACownedsecondary198.19.44.22/25SkipAsSource addapproved. NoDocker/HNS/NAT/IPv6
overlapclaim; testonlyactualIPv4connectedprefix andmanualrules.

Win11 overlaprun14PASS/rulesRestoredtrue12:48:52.264; exactownedsecondaryremove
PASS12:49:37.776/noGWchange; recovered6PASS12:50:45.227 main+3workactualtraffic/
canonicaluserpolicyunchanged. Exportedoverlap/. Firstexportcopywasaskedbefore
conditionalarchiveexisted (QAcontrollerpending); noVMstatechange, correctarchive
createdandcopiedONLYafterfinalPASS. ForeignWFPabort/knowncleanup UACapprovednext,
newcontroller14b09f... exactWin11GUID8CE.../nativePS5parsePASS.

Win11 foreignWFPabort13PASS12:52:18.980: exact8CE...GUIDsurvivedallfaults/boots
anduninstallerexit1; 11UID/profileIDs+1769appfilenamesretained. Exactknownhelper57f5
removedONLYjournalreference, readbackGUIDabsent/SCMRunning. Exportforeign-abort/.
ExplicitalloffPASS12:53:39.981: ownmainDisconnected/guardfalse/all6workDisconnected,
no broadforeignresourcechanges. InboundLinuxclientSHA126def...exactlocal; UAC4
ownedFirewallallowrules setupapproved, nativeharnessnotyetstarted.

Win11 inbound nativeharnessPASS (sameSCMPID): baseline8/8 thenactualOutlineguardarm
12:55:46.160, LAN4positive/offlink4noresponses andpreexistingofflinkTCP4/6
noecho/0replypayload; captured329frames, acceptancePassedtrue. PCAP94b77ea8...d34d;
analysisandallinputs copiednative-win11-r8/inbound/ fromlegacyharnessoutputpath.
Scopefixedfixturephysicalpaths only; notwholematrixgloballeakclaim. Exact4
Firewallallowrule cleanupUACapproved; serverbounded180s/expiresautomatically.

Win11 inbound4FirewallrulesexactcleanupPASS12:57:28/bindingabsent. Finalexplicit
alloffPASS12:57:52.862 (guardfalse/all6workoff); previousalloffreceiptarchived.
Tailcontinuouscapture4376/inv7f6...N0 controlledstop~12:57:59, 5805443bytes
SHA7ba08e00f2779f4eb974cfd2a0811e3a113b96e60b2386db0a1ac1ab89fb07c1, exported
r8-win11-tail.pcap; boundedofflineanalysisdelegated/noVM. Rootpreparingnormal
NRPT/uninstall/reinstall lifecycle. QA-NRPTatomicjournalFile.Replace backup
$null→[NullString]::Value (knownPS5bindingissue, BEFOREfirstNRPTexecution), final
SHA d26d7eab01e7ef70288e407c2f88bdedc813da8f640baf8502a23de0e95cd3b4; native
PS5 own2tempfilesReplace/readbackPASS, receipt r8-nrpt-null-backup-preflight.json.
Frozenproduct/sourceunchanged. No NRPTfailurewasrun/claimedPASS.

Reflection13:04UTC≤5min: since12:34 boot2real/partial87/external/overlap20/foreign13/
inboundclosed; scope remainsacceptance. No repeatedcompletedcorecases/newproductbuild.
StopQAframeworkgrowth; nearestnormal lifecycle→ordinaryGUI/OFFcheckpoint→ONLY
remainingWin10rows. Nextreflection13:34UTC. Lifecyclefirstattempt89d0nativePS5
parsePASS butsafe-preflightfailed13:02:49 BEFOREanyNRPT/uninstall: GetSnapshot
retains terminaldisconnectoperation(actiondisconnect/stagedisconnected). Native
rootselectedsnapshotconfirmsmain/workalloffguardfalse; QAconditionnowacceptsONLY
nullorexactterminaldisconnect + stoppedstates + separatestorenoDesiredcheck.
Sourcee4d523ecb171f57dd868c169620b348474dc747bfd70344e12abcc29bcd6904a, oldfailure
retained; no productchange or newappdefectclaimed. One boundedQAretry next.

Win11tailofflineproofPASS_SCOPED_TAIL_WITH_SEPARATE_OUTBOUND_POSITIVES, report
SHA7130476c277794f0d171846e9c0f65d6f9884b2f7e130a38b9f6ffc7ce5c7ebe:17393frames/
0decode/trunc/fragment. Normalboot2retry/partialall3/external/recoveredphysical8
classes0; peer251822flowbaseline36out32in→blocked20out0in→recovered34out31in,
healthy51820bidirectionalthroughout. ActualauthorizedlocalHTTP198.19.44from
192.0.2.2visibleSYN/SYNACK+163/221payloadbytes, overlaprecovered6negatives0.
Freshoutbound8positiveslinkedseparatecoreproof, no inventednewcontrols; inbound
separate329frameproof; firstbootstallcause stillunknown. Lifecyclee4d5retryUAC
approved13:04; noothernewmatrixrows orproductwork.

REALR8normaluninstallfailure13:05:25: Innoexit0/servicegone/5main+6workprofiles
preserved, BUT37manifestownedGUI/Qt/MSVCfilesremain, GUI8756/session1 stillrunning.
Innoexplicitfileinuse(5), NeedRestartWindows?No. Lifecyclefailed atapplication-removed,
finallyexactNRPTremovePASS; normalreinstallNOTattemptedbecauseuninstallrowfailed.
Reportsnormalized lifecycle-failure/; oldpreflight-onlyfailurealsokept. Runtime
proofsremaincomponentPASS, R8fullacceptanceREJECTED/pendinginstallerfix.
ISS-onlyfixfrozend14b22327f8d1971062dd176f9567f34c960c78b18b9d14a4f4f0913f2fc5138:
exactGUIimagepath+PIDcreation→RestartManagergraceful/noForce→boundedabsencecheck;
abortBEFOREservice/networkcleanup ifGUIcannotclose. QtpinnedWM_ENDSESSIONquits,
WM_CLOSEhides; nativecompile/proofpending. NoGUI/backendchanges.
Win11normalpoweroff13:12:37, OFFfailurecheckpoint7c3fab13-34b2-4b8e-969e-582f37be2d72
(name r8-win11-uninstall-failure-2026-11-07), currentVDIkept/serviceabsent/profilesretained.
Win10cleane4ccOFFverifiedbeforebuilderrestore25c4; nativenewR9source9eb63b1cac9b7d1e8afba7fca8134058c2f855b6e5777679905ae76930ef8e9d,
11876473bytes. 295productionruntime-source+5cachedGoPEidenticalR8; newR9controller
05617... gui→package only started13:15, noSDK/core/Go rebuild. Needall113PE/1765payload
recordscompareandnewopenGUIpositive+safeabortuninstallproofbothOS. SourcesR1-R8
immutable; R9notyetfrozencandidate untilnativepackage/exportverificationPASS.

R9nativegui/packagePASS13:15:00.702→13:17:01.570. Frozennewcandidate
candidate-2026-11-07-r9: installer208435592bytesSHA
f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d; manifest
3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a; source9eb63...8e9d.
OfflineverificationPASS: ALL1765payloadrecords/113PE/8productionEXE EXACTR8,
295productionruntime-sourceidenticalR8; onlyISS changed. NoQAEXE/signature/release.
BuildernormalOFF13:19:32/snapshot096ddfd6-f49e-4f72-8761-ce200e31dcef; thenWin10
cleane4ccrestoredOFF. Win11samecurrentfailureVDIstarted13:22 forR9firstinstall.
DisposableQAstaging4oldsetupEXEs reclaimed833757976bytes ONLYafterhashmatchwith
preservedR4/R5/R6/R7candidates; nodisks/snapshots/media/profiledeletion.
R9smallQAZIP295011bytesSHA21af28d27a3d3bb6fd4ab571fcb179f94e4f2f4b7046752bf8dd3f62961018f0,
54PS+publicCA+newmanifest/noinstallerkeysSDK. Newr9-lifecycle1a1a306d... strict
openGUIpreflight/heldnativeHandle/PIDcreation+HasExitedBYuninstallerproof. R9entry
b21c7... SHA-pinnedsourcebootstrap+newinstaller+manifest, nativePS5parsePASS,
UACfirstinstallapproved13:25; no qa-user-bootstrap/password/profile reset.

Win11firstR9install14PASS13:26:57.480; protectedQAbootstrapupdatednewinstaller/
manifestpins(noUserBootstrap/profile/passwordreset), sourceevidenceR9runtimeidenticalR8.
OrdinaryGUIlaunch/renderPASSnativeScreenshot ordinary-gui-first-install.png; hash53bc
unchanged/callerElevatedfalse/session1. R9negativeUI-threadtest e1799762...(QA-only
TrustedInstallerallowedONLYinstalledapptree, privateQAstrict) nativePS5+C#compilePASS.
ActualUIthreadSuspend→uninstallerexit1specificallyGUIshutdownfailure→exactretention
11PASS13:31:22.389: sameSCMPIDRunning, all15UID/profile/subIDs+1768appfilesretained,
GUIoriginalalive, finallythreadResumedtrue/nochildretained/noKill. Nowpositive
r9-lifecycle1a1a... UACapproved13:31: requiresliveexactGUI+heldhandle anduninstaller
HasExitedproof, plusnormalnetworkcleanup/profileretention/foreignNRPT/reinstall.

Win11R9positive lifecycle14PASS13:32:48.462: originalGUI4300/creation13:27:59.100
alivebeforeuninstall thenconfirmedHasExitedBYuninstaller (nativeheldhandle), no
manualquit/kill. Childnormaluninstall/ownedroutesDNSWFPcleanup/allappfilesgone
PASS, exactall15UID/profile/subIDsetpreserved acrossuninstall+reinstall; foreignNRPT
verifiedaftereachthenONLYownrule/journalremoved. ReinstalledR9GUIordinaryrender
PASS screenshotordinary-gui-after-reinstall.png; serviceoffintent/noSDK. Fullnative
entry/safeabort11/lifecycle/childlogs exportednative-win11-r9/installer-proof/.
Reflection13:34UTC≤5min: R9ISSfixnecessaryrealuninstalldefect, minimalpackagingonly,
all113PE/1765payloadidenticalR8 provesbusinesscomponentreuse. Stopnewinstaller
framework/extraVMresearch; Win11finishOFFsnapshot thenONLYremainingWin10rows.
Rootmustshortenanalysis/usecodefindingsbeforebranching; nextreflection14:04UTC.

Win11R9normalOFF13:36:15; finalnoSDKcheckpoint f4cac319-69b6-4f3f-ab58-8836b1c103c3
(r9-win11-acceptance-checkpoint-2026-11-07). FinalstateR9/noSDK/allVPNoff/foreign
WFP+NRPT+inboundbindingsabsent exportedfinal-state.json. Win10cleanR8e4ccstarted
13:37; smallR9QA+f923installerstaged, sourcebootstrap/privateenginepins3b updated
throughsameUACentry -Phaseupgrade approved13:39. NoUserBootstrap/passwordreset.
Win10coreQA0f7d...preparedmissing139+DNS6+OutlineSourceRefresh+coexist; BEFORErun
rootfixedDNS6helperpath(publicExchange notprotectedQA-bootstrap whitelist), final
sourcehashprintedseparately; nativePS5parsePASS/noextraSDK. ContinuousWin10R9
fixture0pcapstartedBEFOREfreshbaseline, RuntimeMax5400; no extra completedR8cases
repeated(boot/fullwork/route/UI/SCM alreadyqualifiedby113PEidentity).

HostcapacityincidentWin10duringR9upgrade: VBoxautoPaused13:40:53 BLKCACHE_IOERR/
VERR_DISK_FULL, guestpreserved/noreset/nosnapshotrollback. Initialduplicatecache
cleanupdidnotfreesufficient/var (/tmp isSEPARATErootfilesystem, not/var). Preserved
allVM/snapshots/artifactsource. RootrelocatedONLYofflineWin11ISO7092807680bytes
from/varmedia into/home/esmirnov/.cache/vault443-windows-media, source+copySHA
a61adeab895ef5a4db436e0a7011c92a2ff17bb0357f58b13bbc4062e535e7b9 verified; symlink
atsameoriginalmediapath keepsVBox/Snapshotreferencesvalid. Receiptnative-build-r9/
media-cache-relocation.json. Now/var6.8GiBfree; originalISObytespreserved, no VDI/
user/profiledeletion. SamepausedWin10resumerequested13:47; upgradeNOTpasseduntil
itsfreshreportafterresume. Capture5507stillrunning; nofaults/baselinetestsbeganbeforepause.

Win10R9upgrade14PASS13:40:28.761 (finishedBEFOREautoIOpause13:40:53). Afterresume
guestclocklaggedminutes; oneboundedUACQASet-Date fromisolatedfixtureHTTPDate
header correctedwithoutpersistenttimeconfig. NativeUTCparseinitialUnspecified
preflightcaughtBEFOREapproval, UACcancelled/AssumeUniversalflagfixed; finalQAclock
65b517... correctionPASS target13:52:56/offset345.7sec. ExistingGAfurtherclock
slewobserved, so freshpacket-time mapping recordedBEFOREcore withnativeHEAD
nonce b5db221e9e444488981b83873672e915: fixtureUTC=guestUTC+offset [0.2081,1.2830]s,
JSON r9-clock-map-before-core; packetproofmustencompassfullmeasuredinterval.
FirstcorepreflightfailedBEFOREprotocols becauseIPCRequestSourceRefresh returns
{operationId:source-N}, notrawService string. QAfixedaccepted.operationId, failed
reportpreserved. DNS6helperExchange-pathfixalsoQAbeforeexecution; noproductchange.
Freshcore restarted14:00:10: SAMEOutlineee9...SourceRefreshPASS/actualtransportoutline,
physicalDNS6UDP+TCPPASS14:00:15, main139PASS14:01:36.922 (all4protocol/import/
subscription/switch/traffic/logs+guard). NowONLYexistingVLESS+WGmulti/AWG/OVPN
setup, realcoexistverificationpending. Continuouscapture5507N0 wasactivebefore
allfreshcontrols; Sourceclockmetadata/copiedQAsource onhostnative-win10-r9/.


## Контроль за14:04UTC, записан14:08UTC: Win10 R9 core завершён

Свежая серия Win10 R9 завершена **14:02:16.704UTC, PASS**. Проверен итоговый
`r9-core\result.json` внутри
[core-export.zip](../dist/windows/native-win10-r9/core-export.zip): восемь шагов
complete/PASS, errorType=null. Тот же Outline source обновлён без нового профиля;
физические DNS6 UDP/TCP positive controls прошли, свежий main-all содержит139
успешных проверок, main recovery23 прошёл. Существующие WireGuard multi, AmneziaWG
и OpenVPN подтвердили реальный трафик IPv4/IPv6/DNS при подключённом VLESS.
Старые отчёты, также лежащие в архиве, не выдаются за свежую серию R9.

Win10 R9 upgrade14 завершился13:40:28, до host disk pause13:40:53. Та же VM
продолжила работу после освобождения места; ни rollback, ни новая runtime сборка
не выполнялись. Пауза и коррекция часов — ограничения стенда, не product failures.
Перед свежим core записан интервал fixtureUTC−guestUTC **[0.2080751,1.2830051]с**;
корреляция capture должна учитывать весь интервал. Наличие native PASS не заменяет
будущий packet proof; continuous capture остаётся отдельным evidence.

Обязательная саморефлексия за14:04 выполнена read-only14:08, менее5мин:

- Работа по-прежнему ведёт к установщику и проверке обеих Windows: R9 исправил
  настоящий uninstall defect, Win11 installer positive/safe-abort завершены,
  Win10 получил свежие недостающие core proofs. Новые исследования или продуктовые
  функции не добавлялись.
- Остановить повтор fresh main139/DNS6/coexistence, Win11 lifecycle и уже
  подтверждённых unchanged-runtime сценариев. Не развивать QA framework и не
  возвращаться к host IPC/capacity исследованию после восстановления рабочего
  состояния. Следующая QA правка допустима только при конкретном blocker.
- Ближайший шаг — закончить текущую six-engine matrix и её final restore,
  затем существующие actual network/partial/external/overlap/native picker+UAC/
  inbound/R9 safe-abort+lifecycle на Win10. На14:08 matrix ещё выполнялась,
  текущий случай — настоящий Outline helper; полного PASS matrix пока не заявлено.
  Root держит анализ между действиями коротким и переходит к следующему tool.

Оставшийся объём не сокращён, общая acceptance pending. Следующий контроль
саморефлексии14:34UTC, если работа продолжается. Этой записью изменён только
progress; VM, runtime, installer и архивы не менялись.


## Win10 R9: core, engine6 и network/UI закрыты; срез14:19UTC

Upgrade14 PASS13:40:28/noSDK, свежий core139/DNS6/recovery23+три work real
PASS14:02:16.704. Экспорт извлечён в `native-win10-r9/core-proof/`; старые
сопутствующие JSON не выдаются за свежие проверки. Engine matrix complete/
passed/restored14:11:20.573: шесть новых случаев, каждый15PASS — XrayVLESS,
Trojan,SS, actual Outline helper, WG multi и AWG. OpenVPN exact15 остаётся отдельным
ранее завершённым R8 proof при byte-identical runtime, без повторного теста.

Actual physical static IPv4/IPv6 .2→.3 и DNS4→DNS6 выполнен14:11:56:
changed22 PASS14:12:26.140, точный finally restore PASS14:16:02.745,
restored22 PASS14:16:45.992. Master/ordinary JSON в `network-ui-proof/`.
Native picker показал existing private OVPN→Already added→Cancel, без commit;
PNG сохранены рядом. Product boot On→Off14:17:20→On через vault443-access/UAC
PASS: те же IDs, SCM1932/creation13:40:22.769415 и trafficSession1794060527651907500-11.
Controller d0effa…, receipt `network-ui-proof/r9-ui-result.json`.

Partial baseline29 PASS14:18:38.705; host process87300 ещё в работе на этом
срезе, blocked/recovered и full partial PASS не заявлены. Win11 R9 installer
проверки завершены, VM OFF/f4cac. Остаток Win10: partial→externaldual/v6→overlap→
inbound→R9hung-UI safe-abort/live-GUI normal uninstall+foreignNRPT+reinstall,
затем packet proof и консолидация. Full matrix readiness по-прежнему pending.
Этой записью обновлены только docs, без VM/product/archive изменений.


## Саморефлексия14:34UTC и подтверждённый Win10 tail

Read-only reflection выполнена менее5мин; implementation/VM не менялись.
Фокус сохранён: partial87checks, externaldual/v6 и overlap закрывают согласованную
Win10 матрицу. Новый offlink test обоснован ранее явным пробелом LAN-only endpoint,
а не расширением продукта. Он ограничен одним exact endpoint и токеном стенда;
дальше этот helper/framework не развивать. Production113PE неизменны.

Host partial metadata complete14:23:44.649 PASS, baseline29/blocked29/recovered29;
DROPinput20packets/3520bytes, точное удаление14:23:08.944, cleanup=true/errors0.
Externaldual11 PASS14:24:53.103, v6only11 PASS14:25:56.098, exact Windows cleanup
PASS и afterstop2/main22 PASS14:27:30 auto/noRequestConnect. Overlaprun14/rules
restored и exactIPremove PASS, recovered6 PASS14:31:03.706. Нормализованные
native JSON проверены в `native-win10-r9/{partial,tail-proof}/`.

Offlink Win10 functional11PASS14:32:58.545, archive `offlink-export.zip`:
93.184.215.14:1194, свой physical hostroute metric444, тот же fixture SCM across
unbound14:32:16.798–37.900 и bound14:32:37.965–53.103. Windows service/adapter/
binding/route exactcleanup; Linux ownDNATtoken967bd… cleanup14:33:45.739,
счётчик1packet/42bytes (conntrack flow hit, не весь traffic volume). QA variant
PEb06c…/controller9ab047… и sources/provenance сохранены в `controllers/`.
Native11PASS не означает готового pcap proof: unbound0/boundpositive ещё проверить.
Post-offlink main22 на этом срезе выполняется, нового PASS не заявлено.

Ближайший шаг: final mainverify+clockmap→controlledstop5507/N0 до15:09:55→packet
correlation; inbound отдельнымcapture→R9hungUIabort/liveGUIlifecycle наWin10.
Затем только узкий новый offlink наWin11/cleanup, остальные её завершённые R9
installer сценарии не повторять. Остановить повтор готовых core/engine/network/
partial/externalLAN/overlap рядов, новую QA архитектуру и host investigations.
Docker/preBFE не заявлены; общие DHCP/RDNSS/NDMLD не добавляют новых требований.
Полная readiness всё ещё pending; следующий контроль15:04UTC при продолжении.
Этой записью изменены только три docs current TOP/append, без VM/product/archive.


## Win10 R9 native/installer закрыты; финальный offlink Win11 pending

Inbound acceptancePassed=true: baseline8positive, LAN4positive/offlink4negative,
pre-existing TCP4/6 без reply payload. Exact4 firewall/binding cleanup PASS
14:38:24.979. Hung-GUI abort11 PASS14:39:48.574; live-GUI lifecycle14 PASS
14:41:18.131, childuninstall14/reinstall14. Исходный GUI388 закрыт самим uninstaller,
точные SID/profile IDs и чужой NRPT сохранены, QA GUID удалён отдельно. Ordinary
GUI6544/session1 после reinstall осмотрен, PNG/receipts в native-win10-r9.
Finalstate14:41:57: OS19045/noSDK/LocalSystem7112Auto, own4main+5work сохранены/off,
guardfalse, externalservice/adapter/offlinkroute/overlapIP absent.

Postofflink main22 PASS14:34:10.749. Capture5507/N0 controlledstop14:35:14.496,
14185frames/no kernel drops. Main packet report d1f3bb3e… clock-change qualified;
offlink ff1d92e4…: unbound0 includingedge0, certainbound113out/23in, firstOUT
14:32:47.704861 >8.25safter latestpossiblebinding. DNS ID/ports causal calibration
связан с clock union[-.6450152,+1.4826]s; stableUTC не заявлен. Первоначальный
INCONCLUSIVE clock-interval report сохранён. Native JSON/pcap/source/provenance
не переписывались этой doc записью.
Win10 штатно выключена через guest shutdown.exe; OFF checkpoint `d4de2a10-95b9-4d9d-8444-49d4694bb32a` подтверждён14:45:07 [receipt](../dist/windows/native-win10-r9/off-snapshot.json).

Остался только новый узкий Win11 offlink native+packet+exactcleanup и OFF;
завершённые R9 LC/runtime повторно не запускать. Финальная консолидация/validated
acceptance-manifest пока не выполнены, frozen candidate acceptancepending
остаётся immutable. Черновик финального отчёта подготовлен отдельно в /tmp,
не опубликован и не упакован в deliverable.


## Завершение native acceptance —14:54:32UTC

Последний узкий Win11offlink native11 PASS14:48:48.035, exactWindows/Linuxcleanup;
post-main4 IPv4/6HTTP/DNS PASS. Packet6e483874… observedclock-envelopequalified:
unbound/ambiguity0, certainbound114out37in, firstOUT14:48:29.025096 на7.60sпосле
latestbindingCALLstart; clockunion[-.4259517,1.2179286]. Capture2461persisted/
2474received/13tailqueuedoutsidecompletedwindow/0kerneldrop. Native/result/packet
и provenance сохранены, stableUTC не заявлен. LinuxNATtoken596cc535… cleaned1/42.

FinalWin11 OS25H2/build26200.6584/UEFI/SecureBoot1/TPMv2_0/noSDK,
ordinaryGUI8852session1/LocalSystem3448Auto; own4main6work retained/off/guardfalse,
no foreignfixture/offlinkroute/overlap. Штатный guestshutdown /s/t0, OFFsnapshot
235e530f-fce4-4567-80c3-127e4d5a3a76. All3VMpoweroff подтверждено14:54:32.454775
в vm-final-state-r9.json; Win10d4de2a10, LinuxOFF/ownedNFTtables+journalsabsent.

Все согласованные native строки завершены. Report перемещён из /tmp в
[docs/WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md](WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md),
TOPcheckpoint/status и вводныйuserguide/R9GUIcloseuninstall обновлены. Pending
маркер последнего Win11case удалён; clock/staticIP/postBFE/IPv4overlap scopes и
исторические host/disk/boot incidents сохранены как ограничения, не новая работа.
FrozenR9candidatebuild-timeacceptancepending НЕ переписан. Validated delivery с
теми же installer/source/build-manifest bytes и отдельным acceptance-manifest
готовитсяroot; подпись/публикация не запрошены. Этой записью не запускались VM,
не менялся продукт и не создавался bundle.


## Очистка виртуального стенда по запросу пользователя

После завершённой приёмки пользователь попросил удалить Windows-окружения, занимавшие 152 ГиБ. Все три VM были выключены; точные UUID и конфигурации проверены до удаления. Через VirtualBox unregistervm --delete удалены Win10, Win11 и Linux fixture вместе с дисками и снимками. Удалены оставшиеся SDK/ISO/staging и временные ключи в /var/www/projects/windows, а также отдельный ISO-кэш Windows 11. Доступное место увеличилось на 151,62 ГиБ в /var и 6,61 ГиБ в /home, всего 158,23 ГиБ. Все 11 файлов готового R9-комплекта проверены по SHA-256 до и после удаления. Замороженные артефакты, их манифесты и исторические отчёты не изменялись. Для повторных VM-прогонов требуется создать стенд заново.

[Акт очистки](../dist/windows/environment-cleanup-20261107T151713Z.json), [сохранённый комплект R9](../dist/windows/validated-2026-11-07-r9/).
