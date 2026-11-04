# Vault 443 1.3.4

**Vault 443 — a Linux VPN client with a Fallout-inspired retro interface.**

Import your own VLESS, Trojan or Shadowsocks/Outline profiles and manage supported
OpenVPN, WireGuard and AmneziaWG work connections from one native desktop app.
Bring your own server or subscription; no Vault 443 account is required.

[English](#english) · [Русский](#russian)

<a id="english"></a>
## English

### Download and install

Linux x86-64 (amd64) packages:

| Distribution | Installer | Checksum |
| --- | --- | --- |
| Ubuntu 24.04 / 26.04 | [Download .deb](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443_1.3.4-1ubuntu24.04_amd64.deb) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443_1.3.4-1ubuntu24.04_amd64.deb.sha256) |
| Debian 13 | [Download .deb](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443_1.3.4-1debian13_amd64.deb) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443_1.3.4-1debian13_amd64.deb.sha256) |
| Fedora 44 · initial port | [Download .rpm](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443-1.3.4-1.fc44.x86_64.rpm) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443-1.3.4-1.fc44.x86_64.rpm.sha256) |
| Arch Linux · initial port | [Download .pkg.tar.zst](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443-1.3.4-1-x86_64.pkg.tar.zst) | [SHA-256](https://github.com/RealLeo/vault443/releases/download/1.3.4/vault443-1.3.4-1-x86_64.pkg.tar.zst.sha256) |

Download the installer and its matching checksum file into one folder. Open a
normal desktop user's terminal there. For Ubuntu:

```sh
sha256sum -c vault443_1.3.4-1ubuntu24.04_amd64.deb.sha256
# Continue only when the package reports OK.
sudo apt install ./vault443_1.3.4-1ubuntu24.04_amd64.deb
sudo vault443-access "$USER"
```

Then open **Vault 443** from the application launcher and import your profile.
[Installation for all distributions](https://github.com/RealLeo/vault443#install) ·
[Requirements, updates and removal](https://github.com/RealLeo/vault443/blob/main/docs/linux-packages.md).
On a fresh Fedora/Arch install, prepare systemd-resolved and explicitly enable
`vault443-guard.service` and `vault443.service` before connecting. Run the GUI as
your regular user in an active local desktop session.

### Packaging and license

The application binaries are unchanged from tag
[`1.3.4` / `64cff2b`](https://github.com/RealLeo/vault443/commit/64cff2b4216b4378cd5c455532667b134f4f75b9).
The packages have been repacked to include English/Russian README files and the
MIT license, and to declare the project license in distribution metadata.
The original tag is retained. Vault 443's own source code, documentation and
original artwork, including version 1.3.4, are available under
[MIT](https://github.com/RealLeo/vault443/blob/main/LICENSE). Third-party components
and fonts retain their respective licenses; their notices remain bundled.

[SHA256SUMS](https://github.com/RealLeo/vault443/releases/download/1.3.4/SHA256SUMS)
uses flat filenames for downloaded assets. Per-package `.sha256` and `.build.json`
files accompany the installers. These are unsigned project packages.

### Compatibility

Ubuntu is the established desktop target. Fedora/Arch are initial ports. The
supported network stack requires systemd, D-Bus/logind and systemd-resolved with
NetworkManager or systemd-networkd, plus `/dev/net/tun` and kernel WireGuard.
The installer does not migrate DNS configuration. OpenVPN import accepts
self-contained certificate-based TUN profiles; passwords, MFA/SSO, encrypted
private keys, TAP and user scripts/plugins are unsupported. Split work routes
can run alongside the main internet connection; a full-tunnel work VPN pauses it.

Container tests share the host kernel. Physical desktop, boot/suspend and Fedora
enforcing SELinux/firewalld acceptance remain pending. Xray 26.9.30 is a pinned
upstream prerelease. See the [validation record](https://github.com/RealLeo/vault443/blob/main/docs/VALIDATION.md).

### Interface changes

Profile drag handles are now three vertical brass dots to the left of each VPN
emblem. They fit the existing left strip with a transparent 14×32 logical-pixel
hit area at the default scale, without moving the emblem, screen or buttons.

- No handle frame, background, focus outline or hover tooltip. Hover changes only
  the cursor to an open hand; dragging uses a closed hand. A single profile's
  handle stays subdued and inactive.
- Remove Ctrl+Up/Down reordering and its shortcut hints. Handles do not enter the
  Tab sequence or take keyboard focus when pressed. Their English/Russian
  accessible names remain available.
- Keep drag threshold, translucent preview, insertion line, edge scrolling,
  cancellation, per-user order persistence and the permanent themed scrollbar.
  Mouse reordering retains the viewport without moving focus to a handle.

The 472×480 layout, service API, stored profile IDs and network behavior are
unchanged. The OpenVPN/NetworkManager fixes from 1.3.2 and stable-list behavior
from 1.3.3 are retained. Xray, AWG, Outline SDK and locked Go are unchanged.

Packages: x86-64 Ubuntu 24.04/26.04, Debian 13, Fedora 44 and Arch Linux.
See [installation and checksums](https://github.com/RealLeo/vault443/blob/main/docs/linux-packages.md), [profile ordering](https://github.com/RealLeo/vault443/blob/main/docs/profile-order.md)
and the [validation record](https://github.com/RealLeo/vault443/blob/main/docs/VALIDATION.md). Container tests share the host kernel;
physical desktop and Fedora enforcing SELinux acceptance remain separate.
Development does not install the application or switch the workstation's network.

<a id="russian"></a>
## Русский

**Vault 443 — VPN-клиент для Linux с ретро-интерфейсом, вдохновлённым Fallout.**

Импортируйте свои профили VLESS, Trojan и Shadowsocks/Outline, управляйте
поддерживаемыми рабочими подключениями OpenVPN, WireGuard и AmneziaWG.
Нужен ваш сервер или подписка; аккаунт Vault 443 не требуется.

### Что изменилось

- Профили можно упорядочивать перетаскиванием трёх латунных точек слева от эмблемы.
  Порядок сохраняется для каждого пользователя; постоянная полоса прокрутки
  помогает работать с длинным списком.
- Убраны сочетания Ctrl+Up/Down для перестановки профилей. Сохраняются исправления
  OpenVPN/NetworkManager и стабильного списка предыдущих обновлений.
- Теперь доступны четыре установщика с английским и русским README и лицензией
  MIT внутри. Исполняемые файлы приложения и движков сохранены от тега 1.3.4;
  сам тег не переносился.

### Скачать и установить

Выберите пакет своей системы в таблице выше. Все четыре пакета — **x86-64**;
для Ubuntu 24.04/26.04 и Debian 13 нужны разные `.deb`.
Скачайте установщик и его `.sha256` в один каталог. Пример для Ubuntu:

```sh
sha256sum -c vault443_1.3.4-1ubuntu24.04_amd64.deb.sha256
# Продолжайте только после результата OK.
sudo apt install ./vault443_1.3.4-1ubuntu24.04_amd64.deb
sudo vault443-access "$USER"
```

Откройте **Vault 443** из меню приложений и импортируйте профиль.
[Установка на всех системах, обновление и удаление](https://github.com/RealLeo/vault443/blob/main/README.ru.md#install).
При первой установке на Fedora/Arch подготовьте systemd-resolved и явно включите
`vault443-guard.service` и `vault443.service`. Интерфейс запускается обычным
пользователем в активном локальном сеансе.

### Лицензия и ограничения

Собственный код, документация и оригинальная графика проекта, включая 1.3.4,
доступны под MIT. Сторонние компоненты и шрифты сохраняют свои лицензии.
К пакетам приложены индивидуальные контрольные суммы, манифесты и общий
`SHA256SUMS` с плоскими именами файлов. Пакеты не подписаны.

Основной настольный вариант — Ubuntu; Fedora/Arch пока первоначальные порты.
Нужны systemd, D-Bus/logind, systemd-resolved, NetworkManager либо
systemd-networkd, `/dev/net/tun` и WireGuard в ядре. Установщик не меняет DNS-стек
автоматически. OpenVPN поддерживает самодостаточные TUN-профили с сертификатами,
без паролей, MFA/SSO, зашифрованных ключей, TAP и пользовательских скриптов.
Рабочие маршруты могут использоваться вместе с основным интернет-подключением;
полный рабочий туннель приостанавливает его.

Контейнерные проверки используют ядро хоста; приёмка физических рабочих столов,
загрузки/выхода из сна, SELinux enforcing и firewalld на Fedora остаётся отдельной
работой. Закреплённый Xray 26.9.30 помечен upstream как prerelease.
[Полный русский README](https://github.com/RealLeo/vault443/blob/main/README.ru.md).
