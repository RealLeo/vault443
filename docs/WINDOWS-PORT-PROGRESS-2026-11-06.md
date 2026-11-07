# Windows-порт: текущий прогресс 6 ноября 2026

Работа возобновлена по просьбе пользователя в 07:48 UTC. Это текущая запись,
а `WINDOWS-PORT-CHECKPOINT-2026-11-06.md` сохраняет предыдущую точку остановки.
Полный согласованный объём остаётся обязательным. Приёмка **не завершена**.

## Собранный кандидат

`dist/windows/candidate-2026-11-06/Vault443-1.3.4-windows-x64-setup.exe`
— нативный x64 Inno Setup 7.1.1, 211703672 байт.

SHA-256: `dbfb068f6b6194483d0218ffa10d2be448eb8d0773abd9519b24c552e1c062bd`.

Рядом находятся SHA256SUMS, artifact-manifest.json, build-manifest.json и точный
source.zip. Манифест намеренно содержит `acceptance: pending`. Кандидат включает
backend `1a63e4ce93a5b5245e61cdd469b9077ea2a48006889a20eacbd0ffd8add2db3e`.
Позднее в VM установлен backend `13d18e1d4da68c37fb6112b92710ebe15c0e3ae3c96a27433be02a3355b5b059`
с настройкой DNS собственных TUN; он ещё не переупакован. В рабочем дереве также
сохранена более поздняя правка диагностики Reconcile.

QtCore 6.12.0 с официальным QtBase CVE-2026-105924 patch собран MSVC 2022
17.14.44 / compiler 19.44.35229.0 / SDK 10.0.26100. QtCore SHA-256:
`01052b89dc4de0fddaf96d8445b2c711e89a8038ac6439124d7314eb192579ee`.
Qt/QML, подписанный Wintun, Xray, OpenVPN, собственные Go helpers, x64 CRT DLL,
лицензии/SBOM и соответствующие исходники входят в stage. Приложение не подписано
Authenticode, релиз не опубликован.

## Нативные результаты Windows 10 22H2

- VLESS, Trojan, Shadowsocks и динамический Outline: настоящий HTTPS и UDP через
  VPN по IPv4 и IPv6, проверенный адрес источника на сервере. Переключения всех
  четырёх прошли; импорт и обновление подписки сохранили соединение.
- WG и AWG: настоящее аутентифицированное рукопожатие, IPv4/IPv6 HTTP и split DNS.
- OpenVPN: IPv4/IPv6 HTTP, рабочие A/AAAA DNS; совместная работа с main/WG/AWG.
- Полный WG: IPv4/IPv6 и HTTPS с адресом рабочего туннеля.
- WG multi-peer: оба пира подключились; после выключения второго состояние стало
  `partial`, здоровый пир продолжал IPv4/IPv6 трафик и split DNS. Сохранены state/logs.
- Guard: положительный физический baseline, затем 11 проверок protection.
  Захват 45 секунд содержит 27 пакетов только к разрешённому TCP 192.0.2.1:8388;
  прямых тестовых TCP/UDP IPv4/IPv6 и LAN DNS пакетов не найдено. Это один
  наблюдавшийся сценарий Outline, не вся матрица отказов.
- Настоящий QWindows UI: ordinary token/session 1, EN, OS DPI 96. WM_CLOSE скрывает
  окно; повторный запуск поднимает прежний PID. Физический Ctrl+Q через VBox
  завершает UI. PowerShell SendInput не смог забрать foreground, это отмечено
  в QA отчёте; автоматический quit не объявлен прошедшим.
- Нативная Qt suite: EN 57 PASS/0 FAIL/15 Linux DBus skips. Второй запуск с LANGUAGE=ru
  дал 56 PASS/1 FAIL: тест ошибочно ожидал Unix LANGUAGE от Windows QLocale.
  Проверка исправлена только для Windows; требуется повторный native прогон.
  Явные RU/EN переводные сценарии внутри suite прошли. OS 150/200% ещё не проверены.
- Native DNS contract tests (lease renewal, static priority, main fallback block) PASS.
- Linux Qt EN/RU suite 2/2 PASS после UAC UI изменений. Последняя полная Go/Linux
  регрессия была успешна ранее; итоговую повторить после последних изменений.

Доказательства: `dist/windows/native-win10/` (JSON, pcap/analysis, GUI screenshot,
UI/GUI/package logs). Временные секреты остаются вне Git в приватном VM root.

## Открытые дефекты и ближайшие шаги

1. Windows default Resolve-DnsName -TcpOnly возвращает 10057. Raw TCP и явный
   -Server 127.0.0.1/::1 работают. Настройка owned TUN DNS убрала fec0 placeholders,
   но не исправила default selection. Microsoft документирует per-interface
   binding DNS и отсутствие binding при NRPT-designated server. Следующий шаг —
   минимальный A/B NRPT namespace `.` → loopback, затем production fix по доказательству.
2. Creator Wintun теперь удерживается службой между переключениями; это устранило
   повторное создание при смене профилей. При нормальном restart службы последний
   native запуск ждал ухода старого адаптера до нескольких минут, затем автоматически
   восстановил Outline (09:40:33 UTC). Нужны crash/reboot proof, диагностика задержки;
   слепое удаление/смена GUID не выполнялись.
3. Windows 11 VM создана (UEFI/Secure Boot/TPM2, 4CPU/6GiB/80GiB), установка ОС
   запускается после сохранения и выключения Windows 10. Windows VM строго по очереди.
4. Установка/обновление/удаление на clean-os пока не выполнены. Сохранить builder
   snapshot перед возвратом к чистому состоянию. Затем полный installer lifecycle.
5. Впереди: service/engine/network fault pcaps, boot/recovery, external VPN bindings,
   overlap LAN/container routes, default work pause/resume, два пользователя/UAC/IPC,
   настоящий RU/EN UI при OS 100/150/200%, tray/autostart/native file dialogs,
   полная матрица обеих Windows, финальный installer и отчёт.

## Сборка и управление

`build.py stage` теперь включает OpenVPN runtime (сначала openvpn_runtime.py stage).
Source ZIP детерминирован по SOURCE_DATE_EPOCH. Native extract_sources.py обновляет
файлы по содержимому: фиксированные ZIP timestamps не оставляют устаревший AUTOMOC.
Native GUI и packaging обязаны использовать один и тот же source.zip hash.
После последней Go сборки повторить licenses.py перед финальной упаковкой.

Все VBoxManage/vm.py/fixture_vm.py вызовы выполнять вне sandbox. Пароль и ключи
не печатать. GuestControl не зависит от VPN; CLI без параметров получает `[]` stdin.
PowerShell native Go flags с точкой передавать quoted, например "-test.v".
В VM отключён сон экрана; для актуального framebuffer при необходимости послать
Shift через VBox keyboard. VM должны быть выключены после завершения всей задачи.

Рефлексия выполнена в 08:18, 08:48 и 09:18 UTC; следующий контроль 09:48 UTC.
Посторонней работы не найдено. Ближайшая граница — сохранить Win10 и начать Win11,
продолжая host-проверки во время установки. Объём не сокращать.

## Переключение VM и проверки 09:56 UTC

Windows10 остановлена через безопасный VirtualBox saved state во время штатного
Getting Windows ready; питание не прерывалось. Snapshot `builder-2026-11-06`
UUID `232ae0e0-253f-497e-9852-dcfd2b26b39d` включает это состояние и SDK.
При возврате сначала возобновить и дать Windows завершить подготовку.
Windows11 запущена отдельно; в 09:56 UTC unattended installer показывал77%.

Итоговая на эту точку Linux Go регрессия8пакетов PASS (core/network/worknet/service/
store/workvpn/journal/e2efixture). Linux UI после последнего тестовогоifdef:2/2PASS.
NRPT QAэксперимент и primarysource обоснование находятся в
`tests/windows/dns-nrpt-experiment.ps1` и `docs/WINDOWS-DNS-TCP-EXPERIMENT.md`;
production NRPT ещё не реализован. Рефлексия09:48UTC завершена без измененияобъёма.

## Windows11 10:22 UTC

Windows11 EnterpriseEvaluation25H2 установлена:10.0.26200,4logicalCPU,6425350144bytesRAM,
GuestAdditions7.0.16, ordinaryfilteredvaultqa session1. Чистыйsnapshotclean-os:
609d8e65-27d5-40d9-84fb-95d87ab1f697. MSVC/QtSDK отсутствуют.
Первый запусккандидата черезGuestControlRunAs показалUAC, но установканеподтверждена:
нетжурнала/службы; несколькооставшихсяlauncher/consent requests мешаютнадёжнойавтоматизации.
Повторяется запуск из clean-os черезнастоящийRunDialog/Explorer; непредъявлятькакPASSlifecycle.

ПоследняяобщаяcrossbuildпослеWFPemptyprovider/sublayercleanup иIPC64connections/deadlines:
78e1f13f245384a441561cc42462663d7301f61b925d6e13fe0ebc7887223b97.
Онаещёнеустановлена/неупакована. Подготовленыprotectedqa-bootstrap/qa-runner,
installer-smoke иexternalOpenVPNSCMfixture(неshipping);nativeparser/run впереди.
WindowsDNSNRPTABещёнеисполнен. Рефлексия10:18UTCпроведена; ближайшийшаг—
одиннаблюдаемыйinstallerlaunch+log+SCM+IPCнаcleanWin11, затемNRPTAB.

## Чистая установка Windows 11: 10:50–11:00 UTC

Кандидат dbfb/1a63 установлен на clean Windows11 без SDK. Наблюдаемый UAC принят
через Shift+Tab (фокус Yes), затем Space. GuestControl RunAs нельзя оставлять
ожидающим дольше его60сек: для первого запуска использован настоящий Run/Explorer.
Защищённый QA bootstrap прошёл, read/run выдаётся только console QA controller SID.

installer-inspect:10 проверок PASS — LocalSystem/Running, protected service path,
ProgramData/storeACL, manifest identity,22 runtime hashes, official Wintun signature Valid.
Ordinary GetSnapshot и настоящий QWindows UI из Program Files PASS (EN, OS DPI96).
fixture-network PASS:192.0.2.2/24 и2001:db8:44::2/64, NICindex6.
Импорт4 main profiles PASS; VLESS connected. VLESSverify20checks PASS: IPv4/IPv6
HTTPS/UDP, default DNSA/AAAA TCP/UDP, physical guard probes, traffic counters.

NRPT A/B на Win11: все12 DNS-запросов PASS до/при/после временного NRPT, cleanup
подтверждён. hypothesisSupported=false означает отсутствие исходного дефекта:
SYSTEM baseline TCP уже работает. Отдельные ordinary-user TCP A/AAAA тоже PASS.
Это не доказательство исправления Win10. В QA эксперимент добавлено необязательное
45сек окно для ordinary queries на Win10; production NRPT не добавлен.
Рефлексия10:48UTC завершена: продолжить текущую матрицу и один следующий installer
checkpoint, не возвращаться к уже разрешённой UAC автоматизации/исследованию.

## Windows 11: рабочие туннели и ротация в 11:19 UTC

На том же установленном кандидате `dbfb/1a63` пройдены все 20 проверок основного
VPN для каждого из VLESS, Trojan, Shadowsocks и Outline. Импорт/обновление
подписки также прошли. Эти результаты относятся к старому кандидату, а не к ещё
не упакованным исправлениям IPC/WFP.

WireGuard и AmneziaWG прошли настоящий HTTP IPv4/IPv6 и split DNS одновременно
с Outline. OpenVPN сначала попал в retry из-за management password verification,
затем подключился; HTTP IPv4/IPv6, split A/AAAA и совместная работа прошли.
Обнаружена и исправлена framing race: OpenVPN пишет `ENTER PASSWORD:` без CRLF,
поэтому приглашение могло склеиться с `SUCCESS`. Добавлен тест coalescing,
fragmentation и ложных ответов. Исправление ещё не установлено; Windows test PE
`/tmp/vault443-openvpn-parser.test.exe` необходимо выполнить нативно.

Полный WireGuard прошёл HTTP IPv4/IPv6 и default HTTPS с адреса рабочего пира;
основной VPN перешёл в `paused_external`, защита осталась включена. Первый verify
был слишком ранним (туннель ещё connecting); повторный bounded wait и verify
прошли. Для итогового прогона сценарий должен ждать конечное состояние.

Реальный OS Display Scale 150% выбран через Settings/UIAutomation: Qt window DPI
изменился с 96 на 144, QT_SCALE_FACTOR=1. Выбор 200% пока не прошёл: UIA FindAll
показывает только реализованные пункты до 175%; проверяется виртуализация списка.
Это не засчитывается как OS 200% или полный визуальный RU/EN прогон.

Перед сохранением запрошено явное отключение всех рабочих туннелей и основного
VPN; основной disconnect PASS, OpenVPN disconnected. Обычный GUI остаётся открыт.
Win11 сохранена, Win10 возобновлена последовательно. Отложенное обновление Win10
штатно завершило shutdown; после повторного старта ожидается готовность ОС.
Прерывать обновление и считать saved state окончательно выключенной VM нельзя.

Доказательства сохранены в `dist/windows/native-win11/`: main-results-saved,
ui-results-saved, work-coexistence, openvpn-coexistence-verify, work-full-pause-retry,
OS scale и checkpoint screenshots. Временные ключи в эти отчёты не включены.

Саморефлексия к 11:18 UTC выполнена read-only субагентом: отклонения от плана нет;
ближайший обязательный шаг — Win10 ordinary-user NRPT A/B с Hold45. Затем один
согласованный новый installer и оставшаяся матрица. Следующая рефлексия 11:48 UTC.

## Windows 10: DNS и WFP, 11:30–12:00 UTC

Обновление ОС завершилось штатно: Windows 10 22H2, build 19045.6456. Активная
ordinary console session 1 восстановлена. Защищённый QA bootstrap прошёл.

NRPT A/B/A доказан обычным пользователем и SYSTEM: default A/AAAA UDP проходят,
TCP даёт 10057; при временном catch-all к 127.0.0.1/::1 проходят все четыре
запроса; после удаления TCP снова даёт 10057, UDP продолжает работать. SYSTEM
report: hypothesisSupported=true, cleanupComplete=true, task result 0. Первая
версия ordinary harness с четырьмя холодными Start-Job дала только worker
timeouts и не считается DNS-доказательством; последовательный вариант исправлен.

Production DNS теперь использует собственный NRPT с приватным durable token до
создания, точной проверкой GUID/marker/namespace/server и восстановлением legacy
adapter DNS после подтверждения политики. Новые подключения не меняют physical
DNS; fallback читает живые IP Helper данные, включая DHCP/RDNSS. Нужен native
прогон настоящих cmdlets из службы, конфликтов с чужой политикой, crash/recovery,
удаления и split/full DNS на новом установщике. Нативные focused lifecycle tests
с injected runner прошли; они не заменяют этот прогон.

WFP review выявил отсутствие RECV_ACCEPT и слишком широкое ICMPv6 исключение.
Исправлены оба ALE направления IPv4/IPv6; ICMPv6 ограничен ND/MLD/code 0.
Четыре native composer tests PASS. На старом backend `13d18e...` дефект подтверждён:
baseline TCP/UDP IPv4/IPv6 LAN и off-link 8/8 PASS; после включения Outline все
четыре off-link входящих запроса всё ещё получают прямой ответ с physical
интерфейса. Echo replies закреплены за physical ifIndex, поэтому это не эффект
перенаправления маршрутов. LAN при этом остаётся разрешён намеренно. Сохранены
pcap и журнал уже открытых TCP flows. После исправления повторить тот же сценарий.

Временный inbound QA setup установил только четыре собственных Windows Firewall
правила, с exact ownership token и проверкой фильтров при cleanup. Они требуют
удаления по завершении тестов. PS5 server harness исправлен: File.Replace требует
NullString.Value вместо PowerShell $null в аргументе backup path. Не применять
RedirectStandardOutput к фоновому Start-Process из GuestControl: родитель может
ожидать дочерний процесс до своего 60-секундного timeout. Сервер ограничен 180 с.

RU GUI из native build stage проверен при настоящих OS 100/150/200% (Qt factor 1);
для 150/200 подтверждены DPI 144/192. При 200% окно и русский текст визуально
помещаются. Close/reopen и Ctrl+Q прошли при живом VPN, состояние службы сохранилось,
языковая настройка восстановлена. Это stage UI в builder VM, не clean installed
acceptance; Windows 10 Program Files пока содержит backend без GUI. Native
OpenVPN parser cases и IPC CompileOnly также PASS. Build tree доступен ordinary
пользователю; новую native сборку можно выполнять без SYSTEM build task.

Установщик теперь пропускает console enrollment при SYSTEM/session 0; ordinary
первый запуск при необходимости выполняет UAC. Native Inno compile/upgrade впереди.
Семантика Boot сохранена как в Linux: restart службы восстанавливает Desired;
новая загрузка выбирает Boot, рабочие подключения после неё запускаются вручную.
Autoboot proof должен включать явно выбранный Boot profile.

Рефлексия 11:48 UTC выполнена read-only: не расширять прогон старого кандидата
после готовности DNS. Ближайший шаг — единый новый backend, лицензии, source/native
manifest, installer, затем настоящий upgrade и полная оставшаяся матрица.
Следующий контроль 12:18 UTC. Готовность к приёмке по-прежнему не достигнута.

## Нативная упаковка, 12:15 UTC

Общий backend собран: daemon `3b68bfb4459b212187f8e38280a7a912a7aab6b006c099dcd36a2621ffe6f04d`.
Сборка GUI PASS; новый native EN/RU прогон — по 57 PASS, 0 FAIL, 15 Linux-only skips.
GUI SHA-256 `53bc41422de5c1940a3e486c7d5a6442a2074d94fc22f8d33cfef91e5eb140df`.
Первая упаковка отказала на Inno BOOL/Boolean type mismatch в session check;
условие исправлено через отдельный native if и Boolean-флаг. Требуется повторная
упаковка с новым source identity; C++ тесты из-за изменения только ISS не повторять.
Лицензии повторно собраны для текущих Go PE. Старый installer в builder dist
не использовать до свежего package.result=PASS и проверки manifest/hash.

PCAP before-fix независимо подтвердил 92 off-link reply payload packets после
Arm: IPv4 TCP45/UDP1 и IPv6 TCP45/UDP1. На каждом уже открытом TCP tuple после
Arm найдено 44 полных совпадающих echo records. IPv6 application hold verdict
неверно стал false после раннего timeout; wire proof учитывается отдельно.
Reusable анализатор — tests/windows/analyze-inbound-pcap.py, подробный отчёт
dist/windows/native-win10/inbound-before-fix-analysis.json. На новом пакете
требуется acceptancePassed=true с нулём off-link ответов и положительными
baseline/LAN probes. Побитовая воспроизводимость installer ещё не проверена.

## R2 установлен; блокер reconnect, 12:32–13:18 UTC

R2 находится в dist/windows/candidate-2026-11-06-r2/. Installer 211719547 bytes,
SHA-256 83e34933b985a4fffcb23ca3aed3460ebfcffe78d85ebc9bfb823f263741aaef.
Manifest e59815679dce680aa4d6088eba19335c1e8d07b4e813b28a666070b055b80b07,
source fe7f68384fd4b39672bc9a98151e60b83869b966684f61e84a59e21c901f3980.
Повторная Inno упаковка неизменного stage дала тот же SHA-256. Это доказательство
повторной упаковки; полная clean toolchain rebuild побитово не сравнивалась.

Win10 builder upgrade: 14 checks PASS, LocalSystem Running, protected paths/store,
22 runtime hashes, Wintun signature Valid, 4 main и 5 work profiles сохранены.
После миграции старого 13d main TUN уходил около 6 минут, затем Outline восстановился.
R2 default DNS A/AAAA UDP/TCP PASS; physical DNS снова 192.0.2.1, собственный NRPT
loopback effective. Full verify сначала остановился на старом baseline link-local
IPv6 после OS update; baseline затем обновлён, 7 checks PASS. IPC framing/security,
64-connection admission и 8-second first-frame timeouts PASS.

В 12:45:18 UTC, сразу после RequestConnect, SCM зарегистрировал 7031: daemon PID
4052 сменился на 3216. Следующий after-fix inbound capture НЕ засчитан: main connect
не завершился. После падения старый row мешал восстановлению больше 13 минут.
Read-only IPC review не нашёл доказанного channel/map panic; без стека причина
падения не установлена. Не объявлять её исправленной по одному успешному повтору.

Подтверждён отдельный recovery deadlock: ранний return по GetIfTable не вызывал
CreateAdapter, а официальный Wintun ставит orphan housekeeping в очередь только
через API. Минимальный fix разрешает Create(expectedGUID) для exact own identity
Down/NotPresent/LowerLayerDown; Up/unknown/identity collisions отказываются.
Open/adoption, PnP removal и GUID rotation не добавлялись. Вендорская housekeeping
семантика описана в WINDOWS.md. Native identity/status/collision tests PASS.

Непакетированный диагностический backend de30b2610e91f306b292e8049658315210113a6b2f0f890eb5251fba6a61515f
с recovery fix запускался как SYSTEM --console через fixed protected QA task.
Первый connect и disconnect/reconnect PASS. Повтор после 180-second task expiry
недействителен; task result 267014 означает limit, не новый crash.
Полные stdout/stderr остаются private ProgramData QA; sanitised export task
читает только ограниченные stack frames и metadata. Production код ради console
wrapper не менялся.

Следующий диагностический daemon 2475983d058fbdaf8315b5cbb3ae5fceb22abbe76101b76bcb894d760e18ebc0
добавляет debug.SetCrashOutput в существующий private rotated service.log. Он
не подавляет panic и не меняет бизнес-логику. Готовится возврат к SCM и повтор
reconnect с PID proof; R2 installer больше не соответствует временно заменённому
daemon в Win10. Не запускать installer-inspect как проверку R2 runtime до возврата
пакета или нового согласованного installer. Финальная упаковка ждёт диагностику.

Добавлены, но ещё не выполнены native: user-isolation.ps1, qa-user-bootstrap.ps1
(фиксированный standard vaultqa2), vm.py --username vaultqa2. Аккаунт vaultqa2 пока
не создан, host guest-password-qa2 не генерировался. Win11 остаётся saved с dbfb/1a63;
Win10 running, Linux fixture running. Все VM должны быть выключены в конце задачи.

## SCM повторный сбой, 13:21–13:31 UTC

Непакетированный daemon247 под SCM прошёл три disconnect/connect с тем же
PID1088; каждый Connect/Disconnect=true. Затем в 13:29:20 UTC SCM7031 повторился,
PID стал4804. Первые три успеха не закрывают исходный crash. Служба самостоятельно
вернулась к connected; GetSnapshot после восстановления работает. Последующий
WFP capture не засчитан: connect report failed на RPC во время crash.

Private crash output действительно записал runtime stack. Первый sanitised export
с Tail500 обрезал начало fatal/current goroutine; получаем ограниченный расширенный
export. Application1000/1001 для daemon за этот интервал отсутствуют. Не выводить
причину по стеку другой goroutine, ожидающей mutex Guard.Set.

Offline backend/licensing повторены для247, пять PE hashes стабильны. Обнаружен
и исправлен packaging defect: stage ранее включал worknet-windows.test.exe.
Теперь whitelist пяти production Go EXE и package reject *.test.exe; два focused
Python checks PASS. Старые кандидаты сохранены; exact mutable exchange leftover
удалён, native stage leftover требует удаления перед следующим package.

## Причина SCM crash установлена; WFP wire proof PASS, 13:38–13:46 UTC

Расширенный sanitised stack показывает running goroutine: runtime.throw →
bulkBarrierPreWrite (mbitmap.go390) → wbMove → wf.toFilter0 compose.go104 →
Session.AddRule → Guard.apply/Remove → Manager.FetchSource sourceConn.Close.
В pinned Go1.27.3 строка390 проверяет невыровненные аргументы bulk barrier.
Аллокатор pinned tailscale/wf после byte/string allocations не выравнивал память.
Отдельно подтверждён неправильный layout FWPM_FILTER0: union был двумя полями.

Минимальный локальный fork third_party/wf исправляет alignment/slab padding и
16-byte/8-aligned union. Upstream version/h1, точный diff, original/patched tree
hashes и BSD license зафиксированы в packaging/windows/wf-patch.json и SBOM.
Другие Go replacements по-прежнему отвергаются. Пять backend PE пересобраны;
новый непакетированный daemon c077627ff35fbaf283b6fa0a06190f4ea26f4081647018de871d7046df84ac26.

Официальный MSVC SDK probe PASS: sizeof200, action128, union152, reserved168,
filterId176, effectiveWeight184. Native TestVault443FWPMFilter0ABI и
TestVault443ArenaAlignment PASS, testExit0. Доказательства в native-win10.

After-fix inbound proof на c077/PID1948 PASS: 203 captured packets, baseline8/8,
после connected+guardArmed четыре LAN positives, все четыре off-link попытки,
ZERO off-link reply payload packets. Уже открытые IPv4/IPv6 TCP tuples также
имеют zero echoes после Arm, application hold failures подтверждены отдельно.
PCAP SHA3df9d5a29069ffd147d42b6b986b0256512cd629e00238503efcd81a5b0f7ad7;
report dist/windows/native-win10/inbound-c077-analysis.json acceptancePassed=true.
PID не сменился. Это конкретный inbound path proof, не полная fault/leak матрица.
Повторяемый host controller сохранён в tests/windows/run-inbound-proof.py.

После after-fix capture ещё три SCM disconnect/connect c077 PASS с неизменным
PID1948 (13:46:23, :35, :48). Независимый read-only review allocator/ABI и строгих
provenance gates за ≤5 минут не нашёл блокирующих дефектов. Linux Go regression
после root replace: все пакеты кроме IPC PASS; три private-D-Bus integration
сценария не смогли создать bus socket в sandbox. Повторяем только IPC с разрешением
локальных Unix sockets; не исправлять продукт по этой средовой ошибке.

Саморефлексия 13:48 UTC, ≤5 минут: текущий путь прямо приближает к installer и
native acceptance. За интервал получены конкретный crash stack, минимальный fork
fix, SDK/Go ABI proof и успешный WFP pcap; это обязательные исправления, не смена
задачи. Дополнительный exporter churn остановлен после достаточного native export.
Дальнейший speculative audit не нужен. Ближайший шаг — единый R3 installer и
возврат к оставшейся матрице обеих Windows. Scope не сокращён. Следующий контроль
14:18 UTC. Production source snapshot заморожен e71524ed590eb2109185de2886132e994c7b940f75133166e0b61caacc956593;
последующие записи прогресса сами по себе не требуют новой упаковки.
Linux IPC rerun с разрешённым private socket PASS (0.214s), остальные пакеты
прошли предыдущий общий прогон. C++ GUI после последнего native EN/RU не менялся.

## Автоподключение и подготовка двух пользователей, 13:56 UTC

В процессе подготовки native two-user сценария подтверждён UI readback defect:
обычный Windows клиент имеет Caller.Admin=false; прежний GetSnapshot скрывал
даже собственный BootProfileID после успешного UAC сохранения. Минимальное
исправление убирает только elevated gate для чтения собственного UID. Права
SetBootProfile и CanAdmin не менялись. Новый тест с одинаковым profile ID двух
UID подтверждает owner read, foreign ordinary/admin hide, write denial и clear.
Три relevant service теста pinned Go offline PASS. Нужна одна обновлённая
backend/licensing/source/native упаковка; WFP fork не менялся.

Host credential guest-password-qa2 с mode0600 создан, значение не выводилось;
идёт отдельный явный UAC bootstrap fixed standard vaultqa2. PS5 File.Replace
в account harness исправлен на NullString.Value; source SHA d83077954e26a14224dae4b1b4619aeb7d010ba0c889e7aad26f4b49358fed2c.

## R3 и готовность QA2, 14:01–14:16 UTC

R3 сохранён отдельно: dist/windows/candidate-2026-11-06-r3/. Installer208426967bytes,
SHAaf592ded2a9d85404ff3a225504f1e73c4dd1a068de9df8f76a834756b837b6d;
manifestb65dda56aac9ae8a992098206e0703857dd14908d67e0e01179082a5d11dc7ce,
source98a64e26ccd4897493cc8dab197dc58927f21b7e2a4c8d2a795df9eccbcdb64b.
Daemonbc9792b81d882797aa2d88bf366b6d529829d11201fb9e5a91940e44dc1f9024.
1765 runtime files validated; QA testEXE absent. Source/binary/SBOM identity checked.
Полный Linux service suite после Boot readback fix PASS4.144s. GUI53bc не менялся.
R3 ещё НЕ установлен; приёмка pending. Последние doc/QA изменения после snapshot
предоставляются отдельно и не меняют production payload этого installer.

В Win10 создан стандартный vaultqa2, SID заканчивается1001, StandardUser=true,
credential input удалён. Первый bootstrap отказал на Description length64 при
native ValidateLength48; ничего не создал, секрет удалил. Префикс ownership token
сокращён до47chars, добавлены безопасные ErrorCommand/ErrorLine, повтор PASS.
Финальный QA harness SHA45ddaf822e5c3de598e5d6b9515fb2d76ec3eb6c330ee61c1e4ef4071eb90ac9.

Подготовка реального Switch User задержана navigation sign-in. Встроенный Python
VirtualBox API падает на native import ДО VM/session вызовов; это host tooling,
не app crash. Повторных Python/ABI догадок не делать. Проверяется готовый Java
binding с bounded probe; никаких новых служб/RDP/пакетов не устанавливается.
Пока Win10 active user vaultqa (locked), qa2 ещё не вошёл; actual isolation не PASS.

Саморефлексия 14:18 UTC: навигация sign-in заняла избыточное время. Speculative
keyboard/Python/C ABI исследования прекращены. Готовый установленный Java21 +
VirtualBox JNI binding проверен: shared console, absoluteSupported=true, native
mouse click delivered, cleanup PASS. Новых служб/RDP/пакетов нет. Helper
/tmp/Vault443Mouse.java и .class; classpath SDK vboxjxpcom.jar, librarypath
/usr/lib/virtualbox. Команда input: VBOX_USER_HOME=... /usr/lib/jvm/java-21-openjdk-amd64/bin/java
-Djava.library.path=/usr/lib/virtualbox -cp /tmp:/usr/lib/virtualbox/sdk/bindings/xpcom/java/vboxjxpcom.jar
Vault443Mouse vault443-win10 X Y (zero-based screenshot pixels, helper+1).
Первый click закрыл Network flyout, sign-in QA1 password focus восстановлен.
Ближайший обязательный шаг — установить сохранённый R3, дальше матрица; больше
source/архитектуру не улучшать без конкретного native failure. Scope сохранён.
Следующий контроль 14:48 UTC.

## Установлен R3; source route recovery blocker, 14:25–14:45 UTC

R3 Win10 upgrade PASS14checks: exact manifestb65/source98/daemonbc979, LocalSystem,
22 runtime hashes, WintunValid, 4main+5work сохранены. IPC basic+Admission PASS,
report ipc-r3-results/ipc-security-20261106T142743121Z.json (guest), outer log
native-win10/r3-ipc-security.txt. Настоящий основной all matrix начат14:29:36,
18checks, overallFAILED на первомHTTPS VLESS. Runtimeconnected+guardArmed,
PID7212, DNS A93.184.215.14; native SocketError10013. Не объявлять протокол PASS.

Причина исследована до private ledger: route93.184.215.14/32 if4 metric443
обходит TUN и WFP закономерно блокирует ordinary PowerShell socket. В private
windows-routes.json это owner source-570ddb2a40d5602b LUID1689399632855040,
gateway192.0.2.1. Guard ledger имеет другой source-4e3d23dab8b0eedf. Тестовый
source HTTPS и web находятся на одном fixture publicIP, поэтому дефект заметен.
Полный fixture health: все9serverunits active, HTTPS443+VLESS8443 слушают.

Source code review подтверждает: startup не prune exact temporary source owners;
Routes.Set не записывает ref второго owner существующего ownroute, удаляетбезrefs,
при lookup failure может потерять ledger. FetchSource игнорирует cleanup errors.
FetchDocument уже DisableKeepAlives/CloseIdleConnections — его не менять.
Два узких исправления делаются параллельно: winplatform refs+durable failure+
startup prune exactsource16hex, и network FetchSource leases/Close/error handling.
Только эти подтверждённые defects; R3 окончательную приёмку не прошёл. Новый
installer потребуется после native proof; не переупаковывать speculative changes.

UAC Boot helper был показан и подтверждён, однако ordinaryBoot покаempty, после
пробного child script output отсутствует. Причина ещё проверяется с явно
сохраняемым test error report; readbackfix unitPASS не заменяет nativePASS.

Саморефлексия14:48UTC, ≤5мин: работа остаётся на native acceptance failures.
R3 upgrade/IPC доказаны; firstHTTPSпоказалконкретный ephemeralroute defect,
privateownership подтверждён. Scope правок ограничен refs/durablecleanup/startup
иFetchSourceleases; большеархитектуру/fixture/GUI не расширять. Ближайший шаг:
nativefocusedtests→одинbackend→тотжеimport+HTTPSсценарий, затем общаяматрица.
UACBoothelperdiagnostic должен датьявный error/pass, не начинатьповторныеprobe
безновогодоказательства. Следующийконтроль15:18UTC.

Native UAC Boot proof14:48:21 PASS: установленный vault443-access.exe показал
unsigned application UAC, после разрешения ordinary GetSnapshot вернул собственный
VLESS BootProfileID f20323689b53095e2d630206726c0af6 приCanAdmin=false. Совпадает
requestedID; report native-win10/r3-boot-uac-readback.json. Перед reboot не забыть,
что Boot теперь установлен; главныйDesired всёещёVLESSconnected. Первый пробный
harnessбезafterreportнеучитывать. Добавленныйcatchзавершённогоrepeat далPASS.

## Source recovery готов к native runtime, 14:54–15:00 UTC

Нативно прошли9focusedtests:3sourceClose/finalize/lateDial,4routeops(refsharing,
foreignrows, transientcleanup, metricconflict),2startuprecovery. Последняяunion
правка повторноPASS: обаpasses используютsortedunion изобоихjournals, сначала
всеguards, затемвсеroutes. FinalPE SHA d25c814730a3ffc6ed8a6c27f5a1e39c284ef49339e8449adf566c4bd29b0db2.
FetchSource helper exactsource Linux-race3tests PASS1.019s; Windowsnative3PASS.
ПовторныйCloseкэшируетsocket+cleanup result; finalizercancel/dial admission и
ожидание уже вошедших callbacks гарантируют cleanup до возврата.

Новыйнепакетированныйdaemon b07bbf991fd214c4aa36aaee4b149d1215e8127a4bc14f7064b4249f45fa9497;
CLI7143661afb5a509ae61e228c1b1d5adcb29aaae357c2d245392d8bef96d129c4,
access802a7c1921a1f7e6085e2205ad5270d9a52e2d377736649d2ada6c2089f44f8e.
Licenses59modules+wf33sources proofPASS, SBOM6fe5c8d180647e156e078894b60063d5acd767fd6393c8457dc690ab6b8ed2e0.
Source stage пока не обновлялся, native runtime proof новый ещё впереди.

QA2 настоящийвходсостоялся. Phase unauthorized PASS наR3, activeconsoleQA2;
полныйreport native-win10/user2-r3-reports/20261106T145412389Z-unauthorized.json.
Enrollment/изоляцияпослеразрешенияещёвпереди; QA2профилиещёпусты, operatorневыдан.
ПолныйR3IPCJSONтакжеэкспортированвnative-win10/ipc-r3-results.

## Native b07: main all129PASS, 15:10 UTC

ПослеUACdevdeployb07 stalephysical93.184.215.14/32 исчез при startup. НовыйPID7100,
serviceinitiallyStartPending, затемготов. Exacthashb07 проверен передтестом.
DisconnectPASS, полныйmainAll начат15:08:54.4966082, закончен15:10:09.7025695:
completed=true/overallpassed=true/129checks. VLESS/Trojan/Shadowsocks/Outline,
HTTPS+UDP4/6, systemDNSA/AAAAUDP/TCP, forcedphysicalTCP/UDP/DNSnegatives,
trafficcounters, subscriptions/import/switch/explicitdisconnect PASS. Физический
source/32 во времяпрогонаотсутствовал. Это доказывает устранение failingimport+
HTTPS и source recovery. Rawreportnative-win10/b07-main-all-report.json.

Identityграница: толькоdaemon заменён b07; установленныеCLI/access ещёR3,
network engines/QtGUI имеют тежеhash. Полный coherentb07installer сейчас
nativepackage; acceptance на обеихОС/fault/work/security/UI ещёне завершена.
BootVLESSUID1 остаётсязадан, mainAll закончилявнымdisconnect (Desirednil).
QA2неenrolled, первыйunauthorizedPASS; обаuserprofileruntimeWindows созданы.

R4 archive dist/windows/candidate-2026-11-06-r4/:208438592bytes, SHA
 ae5d8b7ddcbee4ad928522fb0e0ac009a313d6dab6f52f062f0c17c352309cf3,
manifest2abefae2bd92ebf728cb01329f3abfc6b762f4ad48958eff2bbdb6ced48eac8b,
source18dbea68101ed87a8e99d4548f1cffc21d7ba45bdb0e19dc27fc8c120830a6d7.
Exacthashи1765runtimevalidationPASS. ИдётR4QAbootstrap/upgrade, ещёнеPASS.

Саморефлексия15:18UTC read-onlyагентом≤5мин: отклоненияотцели нет; пересборки
обоснованыnativefailures, большеresearch/архитектура/packingне нужныбезнового
сбоя. ЗакончитьR4Win10exactinstall, mainAllодинразнаcoherentнаборе, затемwork/
coexistence/security/fault/Win11. Source-download interruption+SCMrestart
обязательныйпрямойregression устранённогосбоя. Доктаблицуобновлятьпослеcheckpoint,
не превращатьвсамостоятельнуюзадачу. Scopeне сокращён; следующийконтроль15:48UTC.

R4Win10 coherent upgrade PASS14checks (taskready/result0, report15:20:53UTC):
manifest2abefae2/source18db/daemonb07 exact,4main+5work profiles preserved,
LocalSystem+protectedpaths+22runtimehashes+WintunValid. Native JSON
native-win10/upgrade-r4-result.txt. Передlaunchupgrade раннийreadbootstrap
файлаотсутствовал, не запускалinstaller; послефактическогоbootstrapPASS
сcorrectae5hash taskзапущен15:19:36UTC, выполненуспешно. MainAllcoherentR4
начатпослеupgrade15:22UTC (одинраз), ждёмрезультат; дальшеworkcoexistence/security.

## R4 coherent mainPASS; work DNS identity failure, 15:24–15:34 UTC

Coherent R4 mainAll report native-win10/r4-main-all-report.json:129PASS,
completed15:23:43UTC. ПослеэтогоOutlineconnectPASS, WireGuardbeginсоздалoperation.
Verify30sFAILED: runtime.error/retry_wait 'DNS coordinator configuration requires
an owned Wintun adapter'. WorkingVPNнеPASS. WireGuardиAmneziaWG запрошенына
явноеdisconnect; mainOutlineостаётсяconnected. AWGbeginвбылзапущенраньшечемroot
проверилWGverifyexit—этоневалидныйcoexistenceproof, обатуннеляостановлены.

Sourceboundary: ConfigureOwnedDNS требует exactownedalias иDescriptionсwintun;
GoWG/AWGupstreamCreateTUN используетdefaultWintunTunnelType='WireGuard',
OpenVPNcreator uses 'Vault443 OpenVPN'. Aliashelper ужеenforcev443w8hex иprivateGUID,
ноdescriptionне совпадает. Минимальныйfix унифицируетcreationtype='Wintun',
оставляяDNSidentitygate/GUID/tokenchecks. Nativeworkidentitiesснимокпослеclose
непоймалкороткоживущиеadapters; actualprotocolproofпослеfixобязателен.
НеупаковыватьследующийcandidateпокаWG/AWG/OpenVPNнепрошлиреальныепроверки.

## Owned adapter type:3workfamiliesPASS,15:42–15:51UTC

Непакетированныйdaemonf569f8fc864c4b64dde88aec791a6a8a4d3a70f3c247b1dc5e44ccb6762ac39a
+helper29d0ce8d54c2b400d947a0f9b1eb1a1d7e5734330995bd71ca69a7dc387cc73a
установленыоднимUAC. СтарыйR4manifest/CLI/accessостались, coherentinspectнеPASS.
Sourcefixтолько3TunnelTypevaluesвдвухfiles, gates/GUID/SIDнеослаблены.

WireGuardPASS: peer198.19.44.2/2001:db8:80::2, splitDNS, handshakeconnected,
actualadapterv443w3afb56c2 DescriptionWintunTunnel GUIDc7f0d322... privateexpected.
AmneziaWGPASS: peer198.19.45.2/2001:db8:81::2, splitDNS, handshakeconnected.
OpenVPNPASS: peer10.77.0.2/fd77:443::1000, corpDNSA10.77.8.10/AAAAfd77:443:8::10,
MainStateconnected+WorkStateconnected. Все3рабочихтуннеляодновременноактивны;
mainOutlineverifyполногоtrafficповторяетсясейчас. Nativeevidence owned-type-*-verify.txt.
ИсторическийlastFailureDNSmessageвWG/AWGdiagnosticsостался, currentstateconnected;
его невыдаватьзановуюошибку.

Саморефлексия15:48UTC (выводзафиксирован15:51),≤5мин: sourcefixes/nativeproof
прямоприближаюткматрице. СпекулятивнуюProvider.ServiceName/migrationостановили:
MicrosoftFWPM_FILTER0/PROVIDER0 описанияDISABLEDпротиворечатProviderAdd/ObjectManagement,
которыеразрешаютproviderбезserviceName. ПредыдущийROвывод'bootblocker'отозван;
самоотсутствиеServiceNameнеNativeFAIL. СначаланативныйbootBFEprobe, безновойmigration.
НуженROinspectorс INCLUDE_BOOTTIME|INCLUDE_DISABLED (обычныйwf.Rulesпропускаетих).
Отдельныйownershipdefectsourceconfirmed: mustOwnRulesусыновляетлюбойruleснашимprovider,
включаяforeignref. Удаляемтолькокnownjournal/currentIDs(write-before-WFPcoverscrash),
неизвестныессылкидолжнывызватьIN_USEприcleanup, безудаленияforeignrules.
Новаяупаковкаждётэтойузкойправки+work/nativeproof; лишниесборкине запускать.
Следующийконтроль16:18UTC.

FourVPNcoexistencePASS15:52:56: mainOutlineverify20checksPASS (HTTPS/UDP4/6,
DNSUDP/TCP, guardnegatives,counters), WG+A WGтрафик4/6/splitDNS повторноPASS,
OpenVPN остаётсяconnected. Snapshotmainconnected/guardtrue и3workconnected.
Полныйлогowned-type-four-vpn-coexistence.txt; mainrawreportguest
main-results/20261106T155256341Z-verify-outline.json. ТеперьпроверяетсяfullWG
pause/resume, затемpartialpeer. Новаяупаковкаещёне запускалась.

FullWireGuardPASS15:58: HTTP4peer198.19.44.2, HTTP6peer2001:db8:80::2,
defaultHTTPSpeer198.19.44.2 (доказанfullpath), runtimefullconnected,
mainState/mainStagepaused_external иguardtrue. AWG/OpenVPNостаютсяактивны.
Evidence owned-type-full-wg-verify.txt; проверяетсяAAAADNS+disconnect/resume.


## Partial WireGuard, восстановление и e58: checkpoint 16:18 UTC

На Df569 частичный отказ multi-peer WireGuard функционально PASS в 16:15:47 UTC:
состояние `partial`, healthy peer44 сохраняет HTTP IPv4/IPv6, назначения peer46
недоступны в обоих семействах. Основной VPN, AmneziaWG и OpenVPN остаются
`connected`, guard=true. После восстановления в 16:16:33 UTC оба пира connected,
все четыре HTTP-пробы успешны. Evidence:
`native-win10/multi-peer-partial-check.json` и `multi-peer-recovery-check.txt`.
Исправления peer3 IPv6, source ACL и FIB относились к тестовому стенду;
production code для этого результата менять не потребовалось.

Захват `/tmp/vault443-multi-partial.pcap` ограничен IPv4 фильтром
`host 192.0.2.2`. Это функциональная проверка partial/recovery и частичное
packet evidence, а не полная IPv4/IPv6/DNS leak acceptance.

Development daemon e58 установлен в 16:17 UTC. Read-only WFP inspector видит
134 persistent и 20 boot-time фильтров, disabled=0 (снимок 16:17:42 UTC в
`native-win10/wfp-ownership-native-result.txt`). Полный foreign-resource/
uninstall-abort сценарий пока не засчитан: требуется исправление QA helper gate.
Само наличие boot-time фильтров не доказывает фактическую защиту ранней загрузки.

Рефлексия 16:18 UTC выполнена read-only, отклонения от плана не выявлены.
Остановить повторные normal-main прогоны на неизменённых файлах. Ближайшие
обязательные шаги: native foreign-reference/cleanup-abort proof, затем coherent
R5 и полная приёмка Win11. Итоговая сборка по-прежнему не признана готовой.


## Foreign WFP / uninstall-abort PASS; startup остаётся открытым, 16:29:55 UTC

`native-win10/wfp-ownership-native-result.txt` содержит native foreign/uninstall
результат passed=true (пока combined PowerShell output). Чужой filter GUID E76B…
сохранился после service restart и после abort удаления с exit1; сохранены служба,
1769 application files и 9 профилей. Точная очистка QA foreign resource PASS.
Это подтверждает preservation/abort сценарий, но не общую SCM stability.

Ранее startup в 16:24:52 и 16:25:18 завершился SCM7024/7031; причина потеряна
из-за уже закрытого private log. Daemon d333 с минимальным startup logging fix
сейчас устанавливается для получения реальной ошибки; его успешный startup ещё
не засчитан. R5 source stage c1e6 — исторический pre-logfix, не упакован.

Native inspector видит пустой provider ServiceName, provider enabled,
disabled filters=0. Это runtime inventory; early boot enforcement не проверен,
и выводов о его успехе или отказе по одному ServiceName делать нельзя.


## D333 SCM stop/start и crash/recovery, 16:44–16:55 UTC

`startup-log-runtime.json` подтверждает установленный daemon d333 Running в
16:44:42 UTC. Перед остановкой main, WG multi-peer, AmneziaWG и OpenVPN connected.
SCM stop exit0 в 16:47:54; защита при stopped service — 11 PASS в 16:48:43.
Start exit0/Running в 16:49:35; recovery 21 PASS и все четыре multi-peer HTTP
IPv4/IPv6 PASS к 16:50. Evidence: `startup-log-stop-task.json`,
`startup-log-stopped-protection.txt`, `startup-log-start-task.json`,
`startup-log-recovery.txt`.

Forced crash PID4300 в 16:53:46 завершён QA result0. Новые ordinary-user пробы
main-matrix SHA `2bc99bacb614841ec387143367de9e016100d23a0a4bafddbeeb2dcd6d086393`
подтвердили protection11 PASS; recovery21 PASS, все четыре multi-peer HTTP,
три рабочих VPN и main connected/guard=true — в 16:55:13. Evidence:
`startup-log-crash-protection.txt`, `startup-log-crash-recovery.txt`,
`startup-log-after-crash-snapshot.json`.

Stop/start pcap `scm-restart-d333.analysis.json`: 78 IPv4 и 37 IPv6 packets,
ноль прямых ответов по всем шести TCP/UDP/DNS probe classes. Crash pcap на этой
точке ещё собирается/анализируется и не засчитан. Прежние два startup7024/7031
не воспроизведены на d333, но не объяснены. Новая загрузка ОС/boot protection
остаются отдельными незакрытыми сценариями.

Рефлексия16:48 UTC: read-only оценка сохранила фокус на обязательном lifecycle
и packet proof; повторные normal-main проверки неизменённого кода не нужны.
После этих сценариев подготовить новый coherent R5 stage d333+helper29d и
актуальный QA script, без повторной backend сборки; native package и Win11
матрица следуют отдельно. Полная приёмка не объявлена завершённой.


## R5 coherent builder и переход на clean Win10, checkpoint 17:26 UTC

Immutable R5 installer SHA `8076f589071e96b98e9fa0296abb925240f97866116062d8bef4202d0c4e7939`
прошёл coherent Win10 upgrade14 PASS в17:08; после подключения main и все три
рабочих VPN connected. Полный main-all завершён139/139 PASS в17:18:31
(начало17:17:06), `native-win10/r5-main-all-report.json`. До guard проверен
положительный IPv6 DNS: UDP88bytes/TCP90bytes PASS17:17:04,
`r5-dns6-positive.json`, main-matrix fc633. IPv6 DNS listener добавлен в QA fixture
после build (QA-only source c1088…); immutable source f4b5 и runtime R5 не менялись.
`r5-main-pcap-analysis.json` имеет пробелы корреляции: не засчитывать как полный
four-protocol/DNS6 capture или всю leak matrix.

WG multi cleanup получил `cleanup_failed` в17:13; явный retry в17:16 сработал.
Дефект остаётся открытым для целевого clean repro; исправленным не объявлен.
В17:21 все VPN отключены, builder штатно выключен. Snapshot
`updated-builder-r5-2026-11-06` UUID `ead81b93-e12e-4265-b77b-be276155ce3f`
сохраняет SDK, R5, профили и текущие тестовые данные. Восстановлен исходный
clean-os: NAT, Windows10 build19045.2006, безSDK/приложения, обычный токен Admin=false.

Настоящий clean install того же R5 через наблюдаемый UAC —14PASS17:25:40,
`native-win10-clean/install-result.txt`; `guiProbeSkipped=true`, GUI этим не проверен.
Ordinary IPC GetSnapshot SUCCESS после installer grant-console. На checkpoint
clean VM выключается для переключения NIC в intnet. Далее: clean fixture,
целевой WG cleanup repro, matching13checks fault/capture, boot и lifecycle,
затем Win11 на том же installer SHA. Новых product/VM действий при записи нет.

## Clean WG cleanup: причина, исправление и подготовка R6, 18:11–18:26 UTC

На clean Win10 повторён R5 `cleanup_failed`. Диагностический daemon fd31 записал
в приватный журнал точную ошибку `work markDown: work routes.set: Element not found.`
(`native-win10-clean/cleanup-private-diagnostic.json`). Goroutine отмены контекста
успевала закрыть WG TUN до перестановки маршрутов. Минимальный Windows fix задаёт
порядок markDown routes/DNS → EOF/stop helper → finishSession; существующий
bounded15s watchdog сохранён. Исходник `wireguard_windows.go` SHA
`cef60cd65e39dafe81ed0100c96d63f69793dc711d68f2315b8793a0a6e836d5`.

Отдельный daemon `9cedea599af02f8afe3434f2b7a56aa167075be4cd7ced21ef3dea924140bf25`
на clean Win10 прошёл два подключения/отключения всех трёх work VPN:
disconnect8326ms и8753ms в18:19:38–18:20:24 UTC, completed/passed=true,
`native-win10-clean/cleanup-order-regression.json`. После отключения0managed
routes/work adapters/NRPT. Native core EOF test PASS0.02s (`core-eof-test.txt`).
Реальный WG helper crash PID3312 при daemon5744 в18:26:08 дал QA passed=true;
автоматическое восстановление двух пиров, HTTP IPv4/IPv6 и split DNS PASS —
`helper-fault-recovery.txt`. Сохранённый lastFailure относится к убитому helper,
текущее состояние connected.

Это целевые native проверки отдельно заменённого daemon, не полная приёмка R6.
Backend9ced и лицензии/SBOM f772e756… готовы; повторная Go сборка не нужна.
Стабильный QA `cleanup-order-regression.ps1` получил обязательный expected daemon
SHA guard для повторов на обеих Windows. Далее R6 source stage и native package:
сохранить clean-testbed безSDK, временно восстановить updated builder snapshot
ead81b93… для упаковки, вернуть clean-testbed для R6 lifecycle и Win11.
Immutable R5 installer8076… и его sourcef4b5 не меняются. Полная fault/capture,
boot, двухпользовательская и Win11 матрица остаются открытыми.

## R6 packaged и clean Win10 interactive upgrade, 18:36–19:08 UTC

Native package PASS18:36:32. Immutable `candidate-2026-11-06-r6`:
installer208434301bytes SHA `0cd92b64b464b7b429be85691ba2fac0008f72fb673c6d53642872f703e5a3cb`,
manifest `392faa05130ab32278b4d64cec0f51e452fc947f412b1841fcfa517dc2766ee7`,
source `07043a2d106bfc9a783858ed2a4a0f63c82cb6bc5753eda0db2b53b6b5efd1f2`.
Stage/offline validation PASS: пять backend PE9ced, GUI53bc, официальный Wintun,
Qt/QML/CRT и wf patch/source provenance; 1765payload files,0QA EXE.

Первая SYSTEM task/session0 upgrade попытка18:52 завершилась exit5. Inno log
прямо записал `Can use RestartManager to avoid reboot? No (2: Session Mismatch)`:
GUI оставался в session1, `msvcp140.dll` был занят, выполнен rollback.
Evidence `native-win10-clean/r6-upgrade-error.json`. Код/ACL/DLL flags ради этого
не менялись. Фактический повтор через интерактивный UAC в session1 прошёл
14/14 PASS, exit0 в19:08:46: exact manifest392faa/source07043/daemon9ced,
22runtime hashes, официальный Wintun Valid,4main+3work сохранены, noSDK=true.
`r6-interactive-upgrade-result.json` содержит два соседних JSON объекта:
summary/checks и отдельный file list; его не следует читать как один JSON document.

Послеустановочный протокольный прогон запущен, результат ещё pending.
Полная готовность R6 не объявлена; lifecycle/fault captures/boot и Win11 впереди.
Предыдущий контроль саморефлексии18:48UTC, следующий19:18UTC. При этом обновлении
менялись только два отчёта; immutable candidate, source archive и VM не менялись.


## R6 clean Win10: протоколы, IPC и второй пользователь, 19:11–19:33 UTC

После интерактивного R6 upgrade coherent main-all завершён 139/139 PASS в
19:12:38 (начало 19:11:13). Затем VLESS reconnect и реальные WG multi, AmneziaWG,
OpenVPN подключены одновременно; main verify 22 PASS, HTTP IPv4/IPv6 и split DNS
работают. Evidence: `native-win10-clean/r6-protocols/`. IPC/admission — 25 PASS,
`r6-ipc/ipc-security-20261106T191438578Z.json`.

В реальном active-console сеансе vaultqa2 unauthorized — 9 PASS, затем после
явного UAC grant isolated — 34 PASS (`user2-r6/`). Возврат первого владельца:
фактический console login в 19:33 выполнен, capture comparison запущен, результат
пока pending. Full-tunnel проверки также не засчитаны до отдельного evidence.
QA logins заняли около десяти минут из-за 30-second idle reset lock screen;
это задержка управления тестовым стендом, не подтверждённый дефект приложения.

Рефлексия 19:19 UTC подтвердила фокус. Остановить повторные main прогоны,
session0 debugging и пересборки без нового product defect. Приоритет — закончить
isolation owner return/full tunnel и перейти к R6 Win11. Следующий контроль
19:49 UTC. Полная приёмка, fault captures/boot/lifecycle остаются открытыми;
при записи изменены только progress и acceptance, VM/code/candidate не менялись.


## R6 Win10 owner/full PASS, Win11 upgrade и Linux regression, 19:33–19:55 UTC

Owner return на Win10 в 19:33:40 —4 PASS: сохранены точные PID, creation time и
traffic session (`native-win10-clean/user1-r6-return/`). Full-work сценарий
19:33:41–19:35:41 —10/10 PASS, restored=true: full WireGuard и OpenVPN дают
IPv4/IPv6, main paused_external/guard=true, после disconnect основной VPN
восстанавливается и проходит verify; исходные split-соединения восстановлены.
Evidence `r6-full-work/result.json`. В 19:36:44 main и все пять work profiles
явно disconnected, guard=false (`r6-before-windows11.json`). Win10 штатно
выключен; snapshot `r6-clean-protocols-users-full-2026-11-06`, UUID
`b7c15b10-f315-4c79-b455-3ad61892dea2`.

Тот же immutable R6 установлен на Win11 интерактивным UAC upgrade:14 PASS
19:47:39, exit0, exact manifest392faa/source07043/daemon9ced,22runtime hashes,
официальный Wintun Valid,4main+4work сохранены, noSDK=true. Evidence
`native-win11-r6/upgrade-result.json` и `interactive-upgrade/`. Win11 protocol
matrix и pcap выполняются root; их результаты на этом checkpoint pending.
Рефлексия 19:50 UTC: отклонения от цели нет, следующий контроль20:20UTC.

Независимый Linux regression выполнен ровно один раз вне D-Bus sandbox:
`toolchain.ensure(offline=True)`, pinned Go1.27.3, GOPROXY=off, HOME не менялся;
`go test -mod=readonly ./...` —exit0, 19:55:38–19:55:44 UTC. Использован обычный
Go test cache, повторных прогонов не было. 231 Go/mod/sum файл совпал с R6
source07043; production source не менялся. Лог `dist/windows/linux-regression-r6.txt`
SHA `c0b3e570daf6e2c81fbdbe8e7d8e17acdf0ff1b16df899331d861f266dc6562e`,
компактная identity —`linux-regression-r6.json`. Полная Windows acceptance
остаётся pending; при этой работе VM/candidate/production files не менялись.


## R6 Win11: main/full/IPC и scoped fault captures, 19:53–20:14 UTC

Main-all139 PASS, затем реальные WG multi/AWG/OpenVPN с main coexistence verify22
PASS (`native-win11-r6/r6-protocols/`). Full WG и OpenVPN10/10 PASS, restored=true,
19:57:01–20:00:19 (`r6-full-work/result.json`); IPC/admission25 PASS (`r6-ipc/`).
Main pcap SHA f5247f8a…:5262frames,0truncated, пять verify окон (VLESS/Trojan/SS/
Outline/Outline-after-subscription), все8 direct classes0 и positive baseline8/8,
включая DNS6 UDP88/TCP90. Unit PID11556/Invocationf80b… без restart покрывает окна
с19:51:36 до controlled stop19:58:32; stop не выведен из последнего packet.
Полный scope/limits —`r6-main-pcap-analysis.json`.

SCM/NIC sequence —10steps+11checks PASS, restored=true,20:02:43–20:07:57:
SCM explicit stop/protection13/start recovery23, forced crash PID2496/protection13/
recovery23, NIC6down13/up recovery23; после каждого восстановления real verify
всех трёх work VPN. Xray PID980 реально остановлен20:11:06; protection13/recovery23
PASS20:11:39. Evidence `r6-service-faults/result.json`, `r6-xray-fault/`.

Fault pcap SHA `de39c3077943b7f8346aa0d2fde719e818db060fa3b358a12a70330c480dab94`:
9250frames (8861IPv4/336IPv6),0truncated/malformed/decodeerrors; все8 direct physical
classes0 во всём capture и20отдельных fault/protection/recovery окнах. Тот же
PID12015/Invocation72ebe383…/NRestarts0: start20:02:09, controlled stop20:14:28.364838.
Анализ `r6-faults-pcap-analysis.json` SHA
`53c177079c07be8036ba902ffb2ac14b9c7a82da4d80d6296b246522b93e47e9`.
Использованы прежние8positive controls на том же physical6/globalIPs.

Ограничения сохранены: только explicit SCM stop monitored-through-probes
подтверждает защиту без работающей службы; отсутствие owned engines проверено
до/после. SCM/Xray crash probes могли выполняться уже после автовосстановления;
link-down negatives сами не доказывают фильтрацию. Нет kernel drop counter и
независимого clock-offset measurement. Это не boot/other-work-engine/inbound/
полная leak acceptance. Boot-profile UAC и pre-SCM boot setup root пока выполняет,
не PASS. Следующий контроль саморефлексии20:20UTC. VM/product/candidate не менялись.


## R6 Win11 UI и две реальные boot проверки, 20:33–21:00 UTC

Все шесть installed UI кейсов EN/RU × OS100/150/200 PASS с реальными HWND DPI
96/144/192, QtFactor1/AppScale0.5, active VPN persistence и screenshots:
r1 EN100 PASS; EN150 после QA Settings HWND recreation завершён вручную тем же
harness20:36:59, без повторного case. Controller-r2 remaining4 PASS20:42:02.
RU200 visual status/PNG192 получен20:47; после actual GUI LaunchAtLogin checkbox
HKCU exact path readback PASS20:48:45. Evidence `native-win11-r6/r6-ui/`.
Settings HWND/PID recreation относилось к QA controller; product не менялся.

Boot attempt1 —inconclusive QA ZoneMismatch: Auto/restored сохранены, но probes
не запускались. Его pcap0selected outgoing не засчитывается. Attempt2 после
canonical scope/index comparison (6→9→13, sameGUID/MAC/globalIPs) проверил новую
загрузку20:49:54.5:13 PASS при41 sampled facts PID0/engines0/SCMStopped/BFERunning,
20:50:19–20:50:46. Physical up, IPv4/IPv6 globals и оба gateways подтверждены.
Finally Auto/restored/taskRemoved=true (`r6-boot-attempt2/result.json`). Затем
ordinary recovery23, main+три work connected, GUI8104/S1 (`r6-boot2-after.json`).

Отдельная штатная Auto загрузка20:56:20.5 без ручных RequestConnect/ServiceStart
PASS20:58:51: main recovery23, real4/6/DNS smokes трёх work VPN, guard=true,
ordinary canAdmin=false. Новый GUI7308/S1 запущен после boot, HKCU Run exact path.
Evidence `r6-normal-boot-after.json`, `normal-boot-*.txt` и main recovery reports.
Это отдельное shipping autostart proof, а не результат временной delayed-SCM task.

Pcap `r6-boot2-and-normal.pcap` SHA
`a2ca6da4b35a9a379879b424cbbdd4eec8c1a38805bbcdf8ad7222aad3d54d8b`:
6610frames (6327IPv4/245IPv6),0truncated/malformed/decodeerrors; все8 direct
physical classes0 во всём capture и6 early/normal/recovery окнах. SamePID12854,
Invocation849c1722…/NRestarts0, start20:48:47 → controlled stop21:00:31.175345
(точная метка файла, не lastpacket). Во время sampled no-Vault443/BFERunning
интервала наблюдаются4ND NS/NA code0 и6ARP с guestMAC. Анализ
`r6-boot2-pcap-analysis.json` SHA
`157e70dd6a82f2fe7c73a760f52af9ba54cb72d641b94674c79e6e379a4ca1f0`.
Прежние8positive baseline использованы по globalIP/GUID/MAC, не ifIndex.

Это post-BFE/pre-Vault443 protection proof; независимое pre-BFE/boot-time-filter
исполнение не изолировано. Нет независимого clock-offset и kernel-drop counter.
Рефлексия20:51 подтвердила фокус, следующая21:21. Остальные ownership/lifecycle/
UI Win10/route-DNS/security сценарии полной матрицы остаются pending.
При этой работе VM/production/candidate не менялись, обновлены только анализ и2docs.


## R6 Win11: два active-console пользователя, checkpoint21:16 UTC

По экспортированным `native-win11-r6/user1-r6`, `user2-r6` и `user1-r6-return`:
user1 capture3 PASS21:03:50; qa2 unauthorized9 PASS21:09:04; после явного grant
isolated34 PASS21:11:55; owner return4 PASS21:16:12. Проверены unenrolled IPC/admin
и private-file deny, UID-isolated stores/import, скрытие foreign metadata,
foreign logs/diagnostics и busy-owner connect/disconnect deny. Sessions1→2→1;
один PID3436, exact creation time/traffic session/active profile сохранены.
Таким образом named двухпользовательские сценарии R6 пройдены на обеих ОС.

Root сейчас выполняет partial WireGuard; результата ещё нет, PASS не засчитан.
Ближайший остаток: partial/recovery wire proof; current-R6 inbound/remaining
engine faults, routes/externalVPN/DNS conflicts; foreign/uninstall lifecycle;
Win10 current boot/fault/UI и оставшиеся native-dialog/tray сценарии. Новых
исследований и прогонов при этой сверке не было. Изменены только два отчёта;
VM/installer/candidate/source ZIP не менялись. Следующий контроль21:21UTC.


## R6 Win11 partial/recovery и native picker/tray, checkpoint21:51 UTC

`r6-partial-host-20261106T213915Z.json`: complete/passed/cleanup=true, по29PASS
в baseline21:30:32–21:30:59, blocked21:39:35–21:43:06, recovered21:43:21–21:43:50.
Exact fixture DROP21:39:26.656652→21:43:11.429136 удалён, input21packets/3696bytes.
Healthy peer сохраняет HTTP4/6 и DNS, failed peer blocked; после cleanup оба
authenticated/connected и трафик восстановлены автоматически, без RequestConnect
или app reset. Основной VPN, AWG и OpenVPN сохранялись, daemon3436 не менялся.

`r6-partial-pcap-analysis.json` —scoped PASS: положительный encrypted WG transport
и native HTTP4/6/DNS reports скоррелированы, selected direct classes0. Оба captures
имеют только IPv4 frames; actual unfiltered argv сохранён в
`r6-partial-capture-provenance.json`. Прежние8physicalpositivecontrols reused,
свежего guard-off physical IPv6 baseline в partial case нет. Это не inbound,
all-destination IPv6 или full leak acceptance.

`r6-file-dialog/result.json` и3PNG подтверждают actual Windows OpenVPN picker,
already-added preview и Cancel без duplicate commit. Фактический import Commit
ранее проверялся CLI protocol matrix. Реальный tray context показан; close скрыл
окно (HWND0), настоящий tray icon вернул HWND66206 при том же GUI PID7308/creation,
main connected/guardtrue и3work connected. Это дополняет6DPI/language cases.

IPv6 route-conflict case сейчас FAIL, диагностика root продолжается; не PASS и
причина не объявлена ни product, ни QA ошибкой до evidence. Inbound setup UAC
21:51:17 создал binding+4rules, но сам inbound proof ещё pending. Lifecycle
команды подготовлены read-only; старый Win10/e58 controller не подходит R6.
Рефлексия21:51 выполнена, следующий контроль22:21. Только2docs изменены;
VM/installer/candidate/source ZIP/production code не трогались.

## R6 Win11 inbound PASS и воспроизводимый IPv6 conflict, 22:05 UTC

`native-win11-r6/r6-inbound/r6-win11-inbound-analysis.json`: acceptancePassed=true.
Guard armed21:57:49; baseline8/8, после arm четыре LAN controls положительны,
четыре off-link TCP/UDP4/6 отрицательны. Оба TCP flows, открытые до arm, перестали
возвращать payload. Capture361packets, offlink reply payload0, daemon3436 тот же.
Это fixed physical paths, не полная матрица утечек. UAC cleanup22:00:46 PASS:
inbound binding удалён, осталось0из4rules. Затем main явно отключён, guardfalse,
все work disconnected, GUI штатно завершён; `r6-before-r7-builder.json` сохранён.

Два route-conflict прогона FAIL с успешным finally restoration. Full WG отдельно
передаёт HTTPS4/6. После full OpenVPN equal default conflict показан для4/6,
IPv4 остаётся рабочим, IPv6 HTTPS timeout. В attempt2 сохранены native FIB и pcap:
`2001:db8:66::14` выбирает OpenVPN if9/source `fd77:443::1000`, effective route
`2001:db8:40::/42`; API дополнительно показывает server `2000::/4` active.
`r6-route-conflict-attempt2-packet-facts.json` подтверждает WG6 positive до
конфликта и отсутствие нового SYN в failed window. Это не доказывает конкретный
WFP drop или OpenVPN userspace rejection.

Закреплённый OpenVPN2.6.23 синтезирует IPv6 redirect pieces `::/3`, `2000::/4`,
`3000::/4`, `fc00::/7`. Их нормализация не должна сохранять автоматически
созданный более специфичный маршрут поверх выбранного default, но должна
сохранять явно заданные client/PUSH prefixes. Узкое исправление и regression
готовит openvpn agent. После native unit проверки нужен отдельный кандидат R7;
R6 installer/source/evidence остаются неизменными. Qt/MSVC/SDK переустанавливать
или пересобирать QtCore не требуется; используется существующий builder cache.
