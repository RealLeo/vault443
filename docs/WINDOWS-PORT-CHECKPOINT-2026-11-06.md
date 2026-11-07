# Windows-порт Vault 443: точка продолжения 6 ноября 2026

Работа остановлена по просьбе пользователя. Полный согласованный объём сохраняется. **Готового установщика пока нет, приёмка Windows-порта не завершена.**

## Проверенная логическая точка

В настоящей VirtualBox VM Windows 10 Enterprise Evaluation 22H2 (10.0.19045.2006), с включённым UAC:

- Служба установлена в `C:\Program Files\Vault443` и работает от LocalSystem; данные в защищённом `C:\ProgramData\Vault443`.
- Обычный, не elevated процесс пользователя `vaultqa` вызывает JSON-RPC через named pipe. `GetSnapshot` работает; доступ к приватному `state.json` запрещён.
- Проверена новая аутентификация сервера по SYSTEM-владельцу и DACL pipe. Клиентам запрещено `FILE_CREATE_PIPE_INSTANCE`; токен службы обычному пользователю читать не требуется.
- Временный VLESS TLS профиль импортирован через PrepareImport/CommitImport. Xray 26.9.30 создал Wintun, служба настроила маршруты, DNS и persistent/boot WFP-фильтры.
- Состояние достигло `connected`; HTTP и HTTPS вернули `vless-e2e-ok` с тестового сервера. Сервер видит источник самого VPN-сервера, а не `192.0.2.2` клиента.
- Явное отключение завершилось `disconnected`, `guardArmed=false`; маршрутов с метрикой приложения 443 не осталось, DNS вернулся к исходному тестовому `192.0.2.1`.
- Windows затем возвращена к NAT/DHCP: `10.0.2.15`, gateway `10.0.2.2`.

Это первый сценарий подключения, **не подтверждение всей матрицы или отсутствия утечек**. Pcap содержит также исходный прямой трафик до включения защиты. Для анализа нужно учитывать временные интервалы.

## Сохранённые результаты

- `dist/windows/checkpoint-2026-11-06/`: диагностика Windows, журнал подключения, таблицы маршрутов/DNS, состояние службы, сведения MSVC, подпись Wintun, pcap и скриншот.
- `win10/tested-backend-build.json` в checkpoint описывает именно установленную и проверенную сборку.
- `build-windows/backend-build.json` описывает более позднюю текущую сборку исходников. После выделения общей логики она заново кросс-собрана, но ещё не установлена в VM.
- Образы, диски, закрытые временные ключи, SDK и пароль гостя находятся **вне Git** под `/var/www/projects/windows`.
- Итоги рефлексии проведены в 22:30, 23:00 и 23:30 UTC. Отклонения от задачи не обнаружены; приоритетом был реальный путь служба → IPC → VPN → HTTPS → отключение. Новая работа остановлена по просьбе пользователя.

## Что сделано в исходниках

- Windows SCM-служба, установка/обновление/maintenance удаления, recovery, LocalSystem и Job Objects для дочерних процессов.
- Платформенное приватное хранение, DACL, отсутствие reparse points, блокировки и атомарная замена. Linux-поведение сохранено отдельной реализацией.
- JSON-RPC 2.0 named pipes, SID → сохраняемый внутренний UID, проверка console session, узкий UAC helper. Linux D-Bus сохранён.
- Windows IP Helper маршруты/адреса/счётчики/уведомления, DNS-координатор, WFP-манифест владения и транзакции, основной Xray runtime.
- Qt transport abstraction, Windows single instance, tray и autostart. **Windows C++ ветка ещё не скомпилирована.** Linux GUI собирался и проходил тесты.
- Собственные кросс-собираемые Go helper'ы Outline и WG/AWG.
- Общая логика выбора рабочих маршрутов, DNS и здоровья пиров выделена из Linux-файлов: `selection.go`, `availability.go`, `peer_health.go`, `uapi.go`. Общая модель сети — `network/snapshot.go`.
- **`worknet/manager_windows.go` — незавершённая заготовка**, не подключена к Windows-службе. Windows WorkRuntime пока отсутствует: нет `Run`, OpenVPN-supervision и полного WG/AWG цикла.
- Сценарии VM, fixture, lock/fetch зависимостей, кросс-сборки, передачи исходников, provisioning и начала native build.

Все изменения остаются в текущем рабочем дереве; git commit и публикация не выполнялись. Исходный HEAD: `4de7e56`, версия продукта 1.3.4.

## Окружение VM

Приватный реестр: `VBOX_USER_HOME=/var/www/projects/windows/virtualbox`.

| VM | Состояние подготовки |
|---|---|
| `vault443-win10` | Windows 10 22H2 установлена; 4 vCPU, 6 GiB, динамический 80 GiB; UEFI/Secure Boot; чистый snapshot `clean-os` UUID `9cca1b49-cc56-43d0-b853-517fd75d1c1f` до приложения/SDK; текущий диск используется также как builder |
| `vault443-fixture` | Ubuntu 24.04 cloud; 2 vCPU/2 GiB; management SSH только `127.0.0.1:22221`; intnet `vault443-test`, `192.0.2.1/24`, `2001:db8:44::1/64`; Xray/DNS/HTTP/HTTPS fixture |
| `vault443-win11` | VM ещё не создана. Официальный ISO Enterprise Evaluation 25H2 уже скачан и хеширован. `vm.py create win11` настраивает UEFI/Secure Boot/TPM 2.0 |

Все VM должны оставаться выключенными после остановки. Windows VM запускаются последовательно, Linux fixture может работать вместе с одной Windows.

**Важно для управления:** выполнять ВСЕ VBoxManage/vm.py вызовы вне sandbox (`require_escalated` в Codex). Один VBoxManage внутри sandbox заменил IPC socket и временно отрезал управление живыми VM. Процессы были штатно сохранены/возобновлены, данные сохранены. Не запускать VBoxManage без нужного доступа даже ради `--help`.

GuestControl работает независимо от VPN и использует обычный filtered пользовательский токен session 1. Не рассчитывать на доступ shared folders: надёжный путь — `vm.py put/get`. При копировании директории VBox копирует её **содержимое** в target.

Длинный `keyboardputstring` может терять символы. При необходимости UAC запускать короткую команду через GUI, вводить порциями по 5 символов с задержкой 150 мс. Для PS через GuestControl использовать `vm.py ps`: UTF-16 EncodedCommand предотвращает ошибки quoting.

QA-only задачи `Vault443-QA-service`, `Vault443-QA-fixture-network`, `Vault443-QA-nat-network` и `Vault443-QA-build-{compiler,core,gui,package}` зарегистрированы после одобренного UAC и запускаются по запросу. В продукт и чистый снимок они не входят.

## Нативный toolchain и точка остановки сборки

Установлены и проверены:

- fixed-version MSVC 2022 **17.14.44**, installationVersion **17.14.37827.9**, `C:\Vault443BuildTools`;
- Windows SDK 10.0.26100;
- Inno Setup 7.1.1, `C:\Vault443Inno`.

Все внешние архивы закреплены SHA-256 в `packaging/windows/dependencies-lock.json`, включая Qt 6.12.0 MSVC2022, Xray 26.9.30, официальный Wintun 0.14.1, Python embedded 3.12.10 и QtBase CVE-2026-105924 patch. Используется существующий закреплённый Go проекта 1.27.3.

Host SDK `/var/www/projects/windows/sdk`: Qt распакован, официальный QtBase-патч применён; готовые `qt-sdk.zip` и `qtbase-source.zip` переданы в `C:\Users\Public\Vault443Exchange`.

QA `build-core` была запущена, **остановлена при подготовке/распаковке SDK, успешной сборки QtCore ещё нет**. В `native-build.ps1` добавлены completion markers распаковки, поэтому прерванный каталог не будет ошибочно считаться готовым. Актуальный скрипт передан гостю перед выключением.

Скрипт native build пока содержит рабочие этапы compiler/core/gui, **package ещё заглушка**. Проверить пути CMake/Ninja после vcvarsall, совместимость feature flags собранного QtCore с prebuilt Qt SDK и применённый CVE регрессионным тестом. Далее собрать Windows UI, выполнить windeployqt и реализовать Inno package.

## Ближайшие шаги завтра

1. Прочитать эту запись и `git status`; не начинать исследование с нуля. Запустить Windows10 и при необходимости fixture. Пароль/SSH ключ уже созданы, не печатать их.
2. Возобновить native `core`, затем `gui`; проверить C++ Windows transport и обычный пользовательский IPC. Подготовить действительный Inno installer. До приёмки сохранить current builder state и восстановить `clean-os` для установки без инструментов разработки.
3. Закончить Windows WorkRuntime и прикрепить work store/runtime в `cmd/vault443d/main_windows.go`, включая Initialize/RetainDesired/release и `StopWork` при остановке службы.
4. WG/AWG helper: привязать UDP bind к физическим интерфейсам; обеспечить активные аутентифицированные проверки пиров (доступны `Device.LookupPeer` + `Peer.SendHandshakeInitiation` в обоих закреплённых Go движках), обновление endpoint по приватному stdin и восстановление при смене uplink. Существующие общие `updateWGHealth`/`wgKeyLifetime` сохраняют Linux-семантику. Не считать созданный TUN успешным handshake.
5. Реализовать OpenVPN с официальным Windows runtime и Wintun, контролем management/events, безопасным конфигом, маршрутами и DNS; закрепить версию/хеши/лицензии и добавить сервер fixture.
6. Довести маршрутизацию/приоритеты/partial peers/split DNS/полный work VPN и паузу основного. Windows route draft ещё не проверен: нужно проверить disjoint CIDR и перекрытия LAN/Docker, метрики/совпадающие `/32`, отсутствие вмешательства в чужие маршруты и восстановление после сбоев. Не устанавливать draft в production.
7. Реализовать применение внешних VPN bindings: текущая `VPNCompatibility` лишь отображает адаптеры и ручные GUID-привязки; исключения и pause ещё не применяются. Проверка владельца либо явная admin binding обязательна.
8. Важная следующая security-проверка: прямой DNS в физическую LAN при main VPN. Сейчас `GuardPart.Local` разрешает LAN, что может пропустить raw DNS на LAN resolver. Добавить адресованные физическим LUID запреты 53/853 с узкими исключениями DNS-координатора и затем доказать pcap. Также убрать неизвестные VPN-подсети из списка Local. Это ещё не исправлено и не проверено.
9. Завершить лицензии/SBOM, воспроизводимый native manifest, install/update/uninstall с сохранением профилей, документацию и сценарий полной приёмки.

Примеры команд из корня репозитория (VM-команды требуют доступа вне sandbox):

```sh
python3 scripts/windows/vm.py status
python3 scripts/windows/vm.py start win10
python3 scripts/windows/fixture_vm.py start
python3 scripts/windows/vm.py ps win10 'Start-ScheduledTask -TaskName Vault443-QA-build-core'
python3 scripts/windows/vm.py ps win10 'Get-Content C:\Vault443Build\core.log -Tail 20'
python3 scripts/windows/build.py backend
python3 scripts/windows/build.py stage
```

После изменений host `native-build.ps1`/`provision.ps1`/source.zip передавать их в VM явно через `put`. `stage` обновляет host exchange, но не guest-копии.

## Обязательная оставшаяся приёмка

Обе Windows, настоящие соединения всех шести семейств; install/update/uninstall, UAC/SCM/boot-connect/crash recovery; импорт/подписки/переключения/журналы; main + work + external VPN; route conflicts и Docker/LAN; split DNS, partial peer failure; IPv4/IPv6 TCP/UDP/DNS и pcap при каждом отказе; два пользователя и неавторизованные IPC/admin вызовы; русский/английский GUI, 100/150/200%, tray/single instance/autostart. Полная Linux-регрессия. Windows11 ещё не установлена, её матрица полностью впереди.

Результат завершённой задачи: настоящий installer в `dist/windows/`, SHA-256, манифест, инструкция и отчёт с доказательствами. Локально, без Authenticode приложения и без публикации. Не объявлять сборку готовой до прохождения всей матрицы.

## Последние проверки перед остановкой

- Все 5 Windows Go PE x64 бинарников снова успешно собраны после форматирования и выделения общей логики.
- Linux: `internal/core`, `network`, `worknet`, `service`, `store`, `workvpn`, `journal` — PASS. Тесты с локальными сокетами запускать вне sandbox; внутри sandbox они падают из-за EPERM.
- Linux Qt приложение и UI test executable пересобраны; CTest EN/RU — **2/2 PASS**, 32 секунды при параллельном запуске.
- Ранее в этой же работе private D-Bus GUI regression — **17 PASS**, без изменения хостового VPN/системного D-Bus.
- `git diff --check` и Python syntax check — PASS.
- Официальная подпись установленного Wintun DLL проверена Windows: `Signature verified`, WireGuard LLC.
