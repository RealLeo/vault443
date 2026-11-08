# Vault 443 1.3.5

[English](#english) · [Русский](#русский) · [Downloads](https://github.com/RealLeo/vault443/releases/tag/1.3.5)

## English

Vault 443 is available for Windows 10 22H2 / Windows 11 x64 and Linux. This
maintenance release improves Windows installation and makes the cross-platform
installation instructions visible in the main README.

### Changes

- Fresh Windows installations offer a local disk and folder choice, with
  `C:\Program Files\Vault443` as the default. Paths may contain spaces and
  Unicode. Setup protects application files and refuses unsafe parent
  permissions, network paths and junction/symlink traversal before installing
  the SYSTEM service.
- Fixed WFP AppID matching in Unicode installation paths using Windows invariant
  casing, so IPv6 checks and VPN transport endpoint exceptions apply correctly.
- Updates keep the existing installation location. To move the application,
  uninstall and reinstall in the new location; private profiles and journals in
  `%ProgramData%\Vault443` remain by default.
- The application EXE and installer contain the existing Vault 443 emblem as a
  multi-size native Windows icon. Explorer, Start, taskbar and uninstall entries
  can use the same identity as the Qt interface and tray.
- The Windows publisher is **Vault 443** in installer metadata, executable
  properties and the installed-app entry. The application and setup are still
  **unsigned**; this is not an Authenticode-verified UAC publisher.
- Both README languages now include Windows downloads, installation, updating
  and removal, plus platform-specific service, privilege and VPN-engine details.
- Linux packages use the common 1.3.5 version, including the Ubuntu ARM64 build.
  Profile formats and the IPC contract are unchanged.

### Downloads

| System | Installer | Checksum |
| --- | --- | --- |
| Windows 10 22H2 / Windows 11 · x64 | [EXE](https://github.com/RealLeo/vault443/releases/download/1.3.5/Vault443-1.3.5-windows-x64-setup.exe) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/Vault443-1.3.5-windows-x64-setup.exe.sha256) |
| Ubuntu 24.04 / 26.04 · x64 | [DEB](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5-1ubuntu24.04_amd64.deb) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5-1ubuntu24.04_amd64.deb.sha256) |
| Ubuntu 24.04 · ARM64 | [DEB](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5_arm64.deb) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5_arm64.deb.sha256) |
| Debian 13 · x64 | [DEB](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5-1debian13_amd64.deb) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443_1.3.5-1debian13_amd64.deb.sha256) |
| Fedora 44 · x64 · initial port | [RPM](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443-1.3.5-1.fc44.x86_64.rpm) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443-1.3.5-1.fc44.x86_64.rpm.sha256) |
| Arch Linux · x64 · initial port | [PKG](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443-1.3.5-1-x86_64.pkg.tar.zst) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.5/vault443-1.3.5-1-x86_64.pkg.tar.zst.sha256) |

[All assets and build manifests](https://github.com/RealLeo/vault443/releases/tag/1.3.5)
· [SHA256SUMS](https://github.com/RealLeo/vault443/releases/download/1.3.5/SHA256SUMS)
· [Windows guide](WINDOWS-USER-GUIDE.md)
· [Linux prerequisites](linux-packages.md).

Windows bundles Qt/QML, the VPN engines and official signed Wintun. Linux
packages use distribution Qt and OpenVPN plus their declared system dependencies.
Own source code, documentation and original artwork remain under [MIT](../LICENSE);
third-party components retain their separate licenses and notices.

## Validation

Use the SHA-256 build manifests and validation report accompanying the
[release artifacts](https://github.com/RealLeo/vault443/releases/tag/1.3.5)
for executed results and their exact package identities. The following describes
the maintenance validation scope; it does not substitute for those results.

The maintenance checks cover both Windows versions: default/custom locations,
another local disk, Unicode and unsafe-path rejection; installation and update
from 1.3.4, reboot/autostart, safe GUI shutdown/removal/reinstall, publisher and
shell icons, all six protocol families from the custom path, and EN/RU at
100%, 150% and 200%. Linux x64 checks cover the installed runtime, GUI/D-Bus,
package lifecycle and updates from 1.3.4. ARM64 is checked under emulation for
architecture, dependencies, EN/RU GUI startup and service diagnostics; physical
ARM64 hardware is outside that validation.

The [1.3.4 R9 report](WINDOWS-ACCEPTANCE-REPORT-2026-11-07.md) is the historical
Windows port baseline, not evidence for the changed 1.3.5 installer. Container
checks share the host kernel and do not certify physical desktop, suspend or
Fedora enforcing SELinux/firewalld behavior. Previous release assets are retained.

## Русский

Vault 443 выпускается для Windows 10 22H2 / Windows 11 x64 и Linux. В этой версии
улучшена установка Windows, а основной README содержит инструкции для обеих
платформ.

### Что изменилось

- При первой установке Windows можно выбрать локальный диск и папку, в том числе
  с пробелами и кириллицей. По умолчанию используется
  `C:\Program Files\Vault443`. Перед установкой службы SYSTEM проверяются путь
  и права: сетевые и небезопасные каталоги, junction и символические ссылки
  отклоняются, файлы приложения защищаются от подмены обычным пользователем.
- Исправлено сопоставление AppID в WFP для Unicode-путей: инвариантное приведение
  регистра Windows корректно применяет исключения для проверки IPv6 и
  транспортных соединений VPN-движков.
- Обновление сохраняет прежний каталог. Для переноса удалите приложение и
  установите его в новую папку; приватные профили и журналы в
  `%ProgramData%\Vault443` сохраняются по умолчанию.
- В EXE и установщик встроена существующая эмблема Vault 443 в нескольких
  размерах: она доступна Проводнику, меню «Пуск», панели задач и записи удаления.
- Издатель **Vault 443** указан в метаданных установщика, свойствах основного EXE
  и списке приложений. Приложение и установщик остаются **без цифровой подписи**;
  подтверждённый Authenticode-издатель в UAC не добавляется.
- README на русском и английском содержит Windows-загрузки, установку,
  обновление и удаление, а также различия платформ в службах, правах и движках.
- Linux-пакеты, включая Ubuntu ARM64, используют общую версию 1.3.5.
  Форматы профилей и IPC не изменены.

Установщики и SHA-256 приведены в [таблице загрузок](#downloads).
[Руководство Windows](WINDOWS-USER-GUIDE.md) ·
[требования Linux](linux-packages.md) · [статус проверок](#validation).

Выполненные результаты и точные идентификаторы пакетов приведены в отчёте
проверки и SHA-256-манифестах, сопровождающих
[релиз](https://github.com/RealLeo/vault443/releases/tag/1.3.5). Описание
[объёма проверки](#validation) не заменяет эти результаты. ARM64 проверяется в
эмуляции, не на физическом устройстве. Исторический отчёт Windows 1.3.4 и
ограничения Linux-портов сохранены отдельно.
