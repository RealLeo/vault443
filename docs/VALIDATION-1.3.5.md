# Vault 443 1.3.5 — validation / проверка

**English:** Vault 443 1.3.5 maintenance acceptance is **PASS with documented
scope**. The exact R2 installer below passed on Windows 10 22H2 and Windows 11;
five Linux packages completed their recorded checks. Application/setup are
**unsigned**. ARM64 was tested under QEMU, not physical ARM64 hardware.
Publication and temporary-environment cleanup are tracked separately in the
[progress record](RELEASE-1.3.5-PROGRESS.md).

**Русский:** согласованная приёмка Vault 443 1.3.5 **ПРОШЛА с указанными границами
проверки**. Один и тот же R2 проверен на Windows 10 22H2 и Windows 11; проверки
пяти Linux-пакетов завершены. Приложение и установщик **без Authenticode-подписи**.
ARM64 проверен через QEMU, не на физическом устройстве. Публикация и очистка
временного окружения фиксируются отдельно в [журнале](RELEASE-1.3.5-PROGRESS.md).

Evidence archive for the release / Архив доказательств для релиза:
[Vault443-1.3.5-validation-evidence.zip](https://github.com/RealLeo/vault443/releases/download/1.3.5/Vault443-1.3.5-validation-evidence.zip).
Paths below identify its logs, JSON and screenshots / Пути ниже указывают на
журналы, JSON и скриншоты комплекта проверки.

## Final Windows candidate / Итоговая Windows-сборка

| Identity / Идентификатор | Value / Значение |
| --- | --- |
| Installer / Установщик | `Vault443-1.3.5-windows-x64-setup.exe` |
| Packaging revision and size / Ревизия упаковки и размер | R2 · 208904505 bytes |
| Installer SHA-256 | `2eb010b25b06b2441aeedf56f5cafddb65e4c077486a8302a15ccccaf75b600a` |
| Source commit / Коммит исходного снимка | `f931aeececa6eb65bf0fa1f0a32ece8162074b32` |
| Source archive SHA-256 / SHA-256 архива исходников | `0f990f9d6eef2b02e8fc58925d6949462145fba200ec4263a508b602740d2361` |
| Build manifest SHA-256 / SHA-256 манифеста сборки | `641c3e2ca8da08c39e853a16b2dd2d03576c474ca4b966daef7d63c8eba2dcb5` |
| Backend revision / Ревизия backend | `565044affd540f91fad2f3f0266bb7aa67cfd233` |
| Daemon SHA-256 | `21d13fada51d8a5310c8bf57a87ffc0898953efa18030d4bfb2af00484378205` |
| GUI/Qt provenance / Происхождение GUI/Qt | Unchanged native R0 payload; exact `runtime-source-r0.zip` and `runtime-build-manifest-r0.json` retained / Неизменённый native R0 payload; исходники и манифест сохранены |
| Windows 10 evidence / Результаты Windows 10 | PASS · `test-results/release-1.3.5/windows/win10/final-{lifecycle,protocols,main,ui,completion}/`, `final-ui-en100-clean/`, `boot-final-verify.json` |
| Windows 11 evidence / Результаты Windows 11 | PASS · `test-results/release-1.3.5/windows/win11/final-{lifecycle,protocols,ui,completion}/` and native screenshots / и native-скриншоты |

| Check / Проверка | Windows 10 22H2 x64 | Windows 11 x64 |
| --- | --- | --- |
| Default/custom folder, other disk, Unicode, protected ACLs, unsafe-path rejection / Каталог, другой диск, кириллица, права и отказ на небезопасном пути | PASS | PASS |
| Upgrade from 1.3.4, preserved profiles and install location / Обновление с 1.3.4, сохранение профилей и каталога | PASS | PASS |
| SYSTEM service, ordinary-user GUI, UAC, reboot/autostart / Служба SYSTEM, обычный пользователь, UAC, перезагрузка и автозапуск | PASS | PASS |
| All six protocol families, imports/subscriptions, switching, traffic/logs, IPv4/IPv6 TCP/UDP/DNS / Шесть семейств протоколов, импорт, подписки, переключение, трафик, журналы и сеть | PASS | PASS |
| Main/work coexistence, routing/split DNS, guard and recovery / Совместная работа VPN, маршруты, split DNS, защита и восстановление | PASS | PASS |
| Native shell icons and publisher / Иконки Windows и издатель | PASS | PASS |
| EN/RU at 100%, 150%, 200%; tray, closing and reopening / Языки, масштабирование, трей, закрытие и повторный запуск | PASS | PASS |
| Normal uninstall/reinstall, hung-GUI safe refusal, profile retention / Удаление, переустановка, безопасный отказ при зависшем GUI, сохранение профилей | PASS | PASS |

Both operating systems used the exact R2 installer SHA-256 listed above. Earlier
R0/R1 attempts and diagnostic-only executables are not final acceptance. The
[1.3.4 R9 report](WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md) remains historical evidence.

Обе ОС проверены с точным SHA-256 установщика R2, указанным выше. Попытки R0/R1 и
диагностические EXE не являются итоговой приёмкой. Отчёт 1.3.4 R9 сохраняется как
историческая база.

**Windows 11 R2 lifecycle evidence:** connected R9 → R2 upgrade preserved four
profiles and passed VLESS IPv4/IPv6 TCP/UDP/DNS/guard checks; `/DIR` relocation was
refused. Normal live-GUI removal and fresh default-folder install/removal passed.
`removed-wfp-r2.json` independently confirmed zero remaining owned filters/parts
and no provider/sublayer before the next install (92 filters observed). An earlier
QA controller failure is retained: the runner copied stale harness `0b937…`
instead of repository version `1541d357…`; product R2 and its source were correct.
After refreshing protected inputs, `final-default-extra-*/result.json` passed,
including unsafe-user-folder refusal (exit 7, no folder/service, parent ACLs
unchanged). Custom `V:\Программы VPN\Vault443` installation passed at 15:32:28 UTC.
`final-protocols/controller.json` passed all 15 stages: four main variants and
WireGuard/AmneziaWG/OpenVPN with main/work coexistence and split DNS. Final reboot,
hung-GUI refusal and connected uninstall also passed as detailed below. All
Windows 10 completion evidence is summarized below.

**Жизненный цикл R2 на Windows 11:** обновление с подключённой R9 сохранило
четыре профиля, VLESS проверен по IPv4/IPv6 TCP/UDP/DNS и guard; перенос через
`/DIR` отклонён. Штатное удаление с работающим GUI, свежая установка в стандартный
каталог и повторное удаление прошли. Независимый WFP-наблюдатель подтвердил очистку
до следующей установки. Исходный QA-отказ сохранён: причиной была копия устаревшего
сценария в runner, затем защищённые входные файлы обновлены и повторная проверка
прошла. На V: с кириллицей прошли все 15 протокольных этапов: четыре основных
варианта и WireGuard/AmneziaWG/OpenVPN с совместной работой и split DNS.
Перезагрузка, автозапуск, отказ удаления зависшего GUI и последующее штатное
удаление при активных VPN также прошли. Windows 10 также завершила ту же согласованную матрицу R2.

**Windows 11 visual/UI review:** `final-ui/controller-result.json` passed all six
EN/RU cases with actual OS scaling at 100/150/200% and HWND DPI 96/144/192; the
last case restored 150%. Independent visual review of all 12 status/reopen PNGs
(RU200 uses `ru200-at200/`) found legible labels and controls without overlap.
Long profile names use the intended ellipsis. EXE, Start shortcut and installer
icons, live window icons and the native taskbar/Alt+Tab screenshots show the
Vault emblem. PE and installed-app metadata report publisher `Vault 443`;
installer SHA-256 and GUI/backend hashes match R2. Close/reopen and quit/language
restoration passed while the active VPN remained unchanged.

**Визуальная/UI-проверка Win11:** все шесть EN/RU случаев прошли с реальным
масштабом ОС 100/150/200% (DPI окна 96/144/192), последний случай вернул 150%.
Просмотрены все 12 status/reopen PNG, для RU200 — сохранённые снимки при 200%:
надписи читаемы, кнопки и данные не перекрываются; длинные имена штатно сокращены.
Иконки EXE, ярлыка «Пуск», установщика, окна, панели задач и Alt+Tab соответствуют
эмблеме Vault. Издатель в PE и списке приложений — `Vault 443`; проверены точные
идентификаторы R2. Закрытие/повторное открытие, выход и восстановление языка
прошли без изменения активного VPN.

**Windows 11 completion:** `final-completion/boot-final-verify.json` passed after
the actual 15:51:57.500 UTC reboot: LocalSystem/Auto service, main connected with
guard armed and active profile equal to boot profile, unelevated console-user
GUI; verification made no Connect/StartService calls. Subscription preview,
commit, refresh and connection preservation passed 4/4, followed by BootOff.
The successful hung-GUI leaf at `1.3.5-gui-close-abort/20261108T155912262Z/`
passed 11 checks: exact thread suspension/resumption, uninstall exit 1, same
service PID, files and profiles retained. Earlier QA precondition failures while
disconnect settled remain recorded. All four VPNs were reconnected before the
final custom-folder uninstall at 16:01:48 UTC. Its native leaf passed 14/14 with
the exact R2 hash: service/files/routes/DNS/WFP removed, **4 main + 3 work profiles
retained**. Recovery here covers the actual reboot/autoconnect and reconnection
after the safe refusal; the historical R9 fault matrix remains separate evidence.
Additional screenshots confirm unsigned UAC, Explorer/Start icons and
Programs and Features publisher `Vault 443`, version 1.3.5.

**Завершение Win11:** после настоящей перезагрузки в 15:51:57.500 UTC подтверждены
LocalSystem/Auto, подключённый основной VPN с guard и загрузочным профилем,
обычный GUI без повышения прав; проверка сама не подключала VPN и не запускала
службу. Подписка прошла 4/4, загрузочное подключение затем отключено. Зависший GUI
проверен 11 пунктами: поток штатно возобновлён, удаление отказало с кодом 1,
служба, файлы и профили сохранены. После повторного подключения основного VPN и
трёх рабочих туннелей штатное удаление с V: прошло 14/14; очищены служба, файлы,
маршруты, DNS и WFP, сохранены **4 основных и 3 рабочих профиля**. Предыдущие
QA-отказы до выполнения предусловия отключения сохранены отдельно. Проверка
восстановления здесь — перезагрузка/автоподключение и повторное подключение после
безопасного отказа; полная fault-матрица R9 остаётся исторической базой.
Дополнительные скриншоты подтверждают unsigned UAC, иконки Проводника/«Пуска»
и издателя `Vault 443` с версией 1.3.5 в списке программ.

## Windows 10 — completed R2 / завершённая приёмка R2

Final packaging leaves in `final-lifecycle/` identify the exact R2 SHA-256 and
pass connected upgrade, `/DIR` refusal, profile preservation, live-GUI removal,
clean path security, unsafe-path refusal, fresh default install/removal and
custom V: installation. The initial clean-path precondition correctly rejected
an existing R9 installation; QA ordering was corrected after uninstall.
`final-protocols/controller.json` passes 15 stages, and the four individual main
verify leaves at 16:16:02/18/33/48 UTC each pass 22 checks, including IPv6 UDP.
WireGuard/AmneziaWG/OpenVPN coexistence and split DNS also pass.

The initial post-upgrade default-folder VLESS leaf at 16:10:56 UTC failed one
three-second IPv6 UDP probe; its preceding TCP4/TCP6/UDP4 passed. It is retained
as a qualified incident with **no established cause**. The earlier controller
ignored LASTEXITCODE, so its overall=true is not used as network proof; the
subsequent individual custom-path leaves are the successful evidence.

`final-ui/controller-result.json` passes all six EN/RU/DPI cases and exact R2
pins; shell EXE/Start/installer icons and publisher metadata were inspected and
match Vault 443. All six status/reopen pairs are visually clear using the clean
EN100 replacement below. The original EN100 status/reopen/launch captures were
obscured by a native certificate “Security Alert” and remain recorded. With No
selected, Enter declined the alert; no invalid certificate was accepted.
`final-ui-en100-clean/` then passed one additional case at real DPI 96; its clean
status/reopen PNGs were independently reviewed as legible without overlap.
An earlier quit failure occurred while the administrative cmd held foreground;
closing that console normally allowed the unchanged `ui-native-smoke.ps1` to
quit successfully. No product rebuild or input-attachment workaround was used.
`boot-final-verify.json` passed after the actual 16:27:20.500 UTC reboot:
LocalSystem/Auto service, main connected with guard and matching boot profile,
unelevated console GUI, no Connect/StartService calls by the verifier.
`final-completion/final-teardown.json` completed successfully at 16:36:13.481
UTC. Its independently checked leaves passed subscription 4/4 and BootOff,
hung-GUI refusal 11/11 (thread resumed, exit 1, service/files/profiles retained),
then reconnect of the main and all three work tunnels with guard enabled and
final connected custom uninstall 14/14. The uninstall began at 16:36:00.538 UTC,
removed service/GUI/files/routes/DNS/WFP and retained **4 main + 3 work profiles**.
The actual R2 UAC screenshot shows Unknown publisher, as expected for unsigned
setup; the GUI and installed-app metadata still identify publisher Vault 443.

Листовые отчёты R2 подтверждают установку, обновление и безопасность пути Win10.
Пятнадцать протокольных этапов прошли; каждый из четырёх основных вариантов
прошёл 22 проверки, включая IPv6 UDP, рабочие VPN работают совместно со split DNS.
Первый post-upgrade UDP6 timeout сохранён без утверждения о доказанной причине;
overall=true контроллера с проигнорированным LASTEXITCODE не считается сетевым
доказательством. Автоматические UI-случаи прошли 6/6, иконки и издатель правильные.
Первый EN100 закрывал certificate-диалог; он отклонён кнопкой No без принятия
сертификата, исходные снимки сохранены. Дополнительный EN100 прошёл 1/1 с DPI 96;
чистые status/reopen просмотрены, текст читаем и перекрытий нет. После настоящей
перезагрузки в 16:27:20.500 UTC подтверждены SYSTEM/Auto, подключённый загрузочный
профиль с guard и обычный GUI; проверка сама не запускала службу или VPN.
Итоговый `final-teardown.json` завершился успешно в 16:36:13.481 UTC:
подписка 4/4 и BootOff, безопасный отказ удаления зависшего GUI 11/11, повторное
подключение основного и трёх рабочих VPN с guard, удаление из пользовательской
папки 14/14. Поток GUI возобновлён, при отказе exit 1 служба, файлы и профили
сохранены; штатное удаление очистило службу/GUI/файлы/маршруты/DNS/WFP и сохранило
**4 основных + 3 рабочих профиля**. Реальный UAC R2 показывает Unknown publisher,
как и ожидается без подписи; метаданные GUI и списка программ — Vault 443.

## Linux — English

Five installers were built: Ubuntu 24.04/26.04 x64, Debian 13 x64, Fedora 44 x64,
Arch x64 and Ubuntu 24.04 ARM64. Their hashes and build manifests accompany the
release assets. Completed Linux evidence is recorded in
`test-results/release-1.3.5/linux/acceptance-manifest.json`; detailed lifecycle
logs and installed screenshots are under `test-results/linux-1.3.5/`.

- All five x64 OS targets passed isolated systemd installation, connected upgrade
  from 1.3.4, reinstall, private per-user state, guard/crash recovery and removal.
  Local fixtures exercised VLESS, Outline, OpenVPN, WireGuard and AmneziaWG.
- Ubuntu 24.04, Debian, Fedora and Arch passed the native EN/RU Qt suite:
  57 passed and 15 fixture-only skips per language. Selected private D-Bus GUI
  scenarios ran separately: 8 passed, no skips, per language and distribution.
  Debian/Fedora/Arch also passed clean runtime dependency/package checks.
- ARM64: the exact DEB payload ran through QEMU user-mode emulation; all five
  executables were AArch64, dynamic dependencies resolved, daemon diagnostics
  reported 1.3.5 without network changes, and EN/RU GUI screenshots succeeded.
  Physical ARM64 and ARM64 kernel/systemd VPN acceptance were not performed.
- Pinned Go 1.27.3 unit tests and the vulnerability gate passed for the recorded
  Linux build sources. The subsequent WFP AppID fix is confined to Windows-only
  `*_windows.go` files excluded from Linux builds; no Linux runtime code changed.

Container checks share the host kernel. Physical desktop integration,
boot/suspend and Fedora enforcing SELinux/firewalld remain outside these results.
The Fedora GUI test correction changed keyboard activation in the test only;
the original failure and subsequent passing evidence are retained. Unchanged
Xray binaries were recovered from checksum-verified retained packages after an
upstream download failed; the embedded Xray lock matched exactly.

## Linux — Русский

Собраны пять установщиков: Ubuntu 24.04/26.04 x64, Debian 13 x64, Fedora 44 x64,
Arch x64 и Ubuntu 24.04 ARM64. Контрольные суммы и манифесты поставляются рядом
с файлами релиза. Итоговые Linux-результаты находятся в
`test-results/release-1.3.5/linux/acceptance-manifest.json`, подробные журналы
и скриншоты установленного приложения — в `test-results/linux-1.3.5/`.

- На пяти Linux x64 окружениях прошли установка под systemd, обновление с 1.3.4
  при активном соединении, переустановка, разделение данных пользователей,
  защита и восстановление после сбоев, удаление. Локальные стенды проверяли
  VLESS, Outline, OpenVPN, WireGuard и AmneziaWG.
- Нативные Qt-проверки на Ubuntu 24.04, Debian, Fedora и Arch прошли на двух
  языках: 57 успешных и 15 пропущенных проверок, требующих отдельного стенда.
  Выбранные GUI/D-Bus сценарии запускались отдельно: по 8 успешных без пропусков
  на язык и дистрибутив. Debian/Fedora/Arch также прошли проверки зависимостей
  и установленного пакета в чистом runtime-окружении.
- Точный ARM64 DEB проверен через QEMU: пять исполняемых файлов имеют архитектуру
  AArch64, зависимости разрешаются, диагностика службы показывает 1.3.5 без
  изменения сети, интерфейс запускается на русском и английском. Физическое
  ARM64 и работа ARM64 VPN со службами systemd/ядром отдельно не проверялись.
- Модульные Go-проверки и проверка уязвимостей прошли с закреплённым Go 1.27.3
  для зафиксированных Linux-исходников. Последующее исправление WFP AppID
  ограничено файлами `*_windows.go`, исключёнными из Linux-сборок; код Linux
  runtime не менялся.

Контейнеры используют ядро хоста. Физический рабочий стол, загрузка/сон и
Fedora с SELinux enforcing/firewalld не входят в эти результаты. Исправление
Fedora касалось только клавиатурной активации в GUI-тесте; исходный сбой и
успешная повторная проверка сохранены. Неизменённый Xray восстановлен из
сохранённых пакетов с проверенными суммами после сбоя скачивания; встроенный
lock-файл Xray совпал точно.

## Public installer inventory / Публичные установщики

| Platform / Платформа | Asset name / Имя файла |
| --- | --- |
| Windows x64 | `Vault443-1.3.5-windows-x64-setup.exe` |
| Ubuntu x64 | `vault443_1.3.5-1ubuntu24.04_amd64.deb` |
| Ubuntu ARM64 | `vault443_1.3.5_arm64.deb` |
| Debian 13 x64 | `vault443_1.3.5-1debian13_amd64.deb` |
| Fedora 44 x64 | `vault443-1.3.5-1.fc44.x86_64.rpm` |
| Arch x64 | `vault443-1.3.5-1-x86_64.pkg.tar.zst` |

`scripts/release-manifest.py` verifies both README download tables, the installer
hashes and build manifests, then writes `SHA256SUMS`, individual `.sha256` files,
build manifests and `release-manifest.json`. Supply the final Windows directory
explicitly and use `--require-all` for the complete six-installer inventory.
The inventory records artifacts; this separate report records acceptance.

Скрипт проверяет имена загрузок в обоих README, хеши установщиков и манифесты,
затем создаёт общие и отдельные контрольные суммы и `release-manifest.json`.
Итоговый Windows-каталог указывается явно; `--require-all` требует все шесть
установщиков. Манифест перечисляет файлы, а этот отчёт фиксирует приёмку.
