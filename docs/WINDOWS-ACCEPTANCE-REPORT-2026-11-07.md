# Vault 443 1.3.4: приёмка Windows, 7 ноября 2026

**Приёмка согласованной матрицы завершена 7 ноября 2026 в 14:54:32 UTC
(17:54:32 МСК).** Локальная сборка R9 готова к передаче. Native runtime/UI и
installer positive/safe-abort проверки обеих Windows выполнены, включая
последний offlink case Win11. Все три VM штатно выключены.

## Установщик

Локальный x64 установщик для Windows 10 22H2 и Windows 11. Приложение не имеет Authenticode-подписи; релиз не публиковался. Qt/QML/CRT, VPN-движки и официальный подписанный Wintun включены. На приёмочных VM инструменты разработки отсутствуют.

| Артефакт | SHA-256 |
| --- | --- |
| Installer, 208 435 592 байта | `f923f16fff693112fc1d53a167d49565475f15dfe29141b7f4316dbc2a978e2d` |
| build-manifest.json | `3b39812785f9441b33ac02ced564f30bbc918253b27edbbaed4ef4bb1c65c09a` |
| source.zip | `9eb63b1cac9b7d1e8afba7fca8134058c2f855b6e5777679905ae76930ef8e9d` |

[Installer и SHA256SUMS](/var/www/projects/ubuntu/vless-terminal/dist/windows/validated-2026-11-07-r9/).

R9 изменяет только Inno script. [Проверка сборки](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-build-r9/offline-verification.json) подтверждает полное совпадение 1765 payload records, 113 PE/8 production EXE и 295 runtime-source файлов с R8. Поэтому прежние R8 component proofs привязаны к тем же runtime hashes; они не выдаются за свежий полный R9 прогон. Новая installer логика проверена отдельно на обеих ОС.

MSVC 2022, Qt 6.12.0 с QtBase patch, Go 1.27.3, Xray 26.9.30, Inno 7.1.1, Wintun 0.14.1, точные зависимости, контрольные суммы и лицензии записаны в build manifest и licenses/. SDK/QtCore/Go при R9 не пересобирались.

## Проверки

Win10: Enterprise Evaluation 22H2/build 19045. Win11: Enterprise Evaluation 25H2/build 26200. Использованы изолированные серверы, временные ключи и сертификаты.

| Сценарий | Windows 10 | Windows 11 |
| --- | --- | --- |
| Установка/обновление без SDK, LocalSystem service и ordinary GUI | R9: 14 проверок обновления PASS | R9: 14 проверок установки PASS |
| VLESS/Trojan/Shadowsocks/Outline, импорт/подписки/переключение, IPv4/IPv6 TCP/UDP/DNS | Fresh R9: 139 main проверок PASS | Exact-runtime R8: 139 main проверок PASS |
| Основной+WG multi/AWG/OpenVPN, full tunnels и split DNS | PASS; full-work: 10 шагов | PASS; full-work: 10 шагов |
| Выбор владельцев маршрутов/DNS и connected IPv4 overlap | Route: 16 проверок/9 шагов, overlap: 14+6 PASS | Route: 16 проверок/9 шагов, overlap: 14+6 PASS |
| Отказы движков, SCM/NIC | 6 family cases по 15 PASS; отдельный OpenVPN: 15; SCM/NIC: 10/11 | 6 family cases по 15 PASS; OpenVPN: 15; SCM/NIC: 10/11 |
| Boot/автозапуск, сохранённая защита | R8 exact-runtime pre-SCM: 13 и normal boot PASS | pre-SCM: 13 и normal boot2 на ограниченном повторе PASS |
| IPC/два пользователя, права и SID/profile isolation | IPC: 25, qa2 reuse: 53, owner return: 4 | IPC: 25, qa2 reuse: 55, owner return: 4 |
| RU/EN, реальные OS 100/150/200%, трей/single instance/picker/product UAC | PASS | PASS |
| Реальная статическая смена dual-stack IP и DNS4→DNS6 с exact restore | changed: 22/restored: 22 PASS | changed: 22/restored: 22 PASS |
| Partial WireGuard peer |29/29/29 PASS |29/29/29 PASS |
| External dual/IPv6-only и auto main resume |11/11 и afterstop: 2 PASS |11/11 и afterstop: 2 PASS |
| Новый offlink transport exception | Native: 11 и qualified packet proof PASS | Native: 11 и qualified packet proof PASS |
| Inbound/pre-existing TCP4/6 | PASS; четыре QA firewall rules сняты | PASS; четыре QA firewall rules сняты |
| Hung-UI safe abort и live-GUI uninstall/reinstall |11+14 PASS, child uninstall: 14/reinstall: 14 |11+14 PASS, child uninstall: 14/reinstall: 14 |

Точные отчёты и снимки: [Win10 R9](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win10-r9/), [Win11 component R8](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r8/), [Win11 R9 installer](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/installer-proof/). [Консолидированная матрица](/var/www/projects/ubuntu/vless-terminal/docs/WINDOWS-ACCEPTANCE-STATUS-2026-11-06.md) содержит точные пути и исторические неуспехи. Linux regression PASS до installer-only R9; применимый production код неизменён: [receipt](/var/www/projects/ubuntu/vless-terminal/dist/windows/linux-regression-r8.json).

## Installer fix и packet proof

R8 normal uninstall вернул 0, но оставил работающий GUI и 37 owned файлов. R9 закрывает точный GUI через Restart Manager без force и проверяет его отсутствие до очистки. На обеих ОС прошли отрицательный hung-UI abort и положительный open-GUI uninstall/reinstall. Исходный GUI закрыт самим uninstaller; 0 app files/owned routes/DNS/WFP после удаления, точные SID/profile IDs и чужой NRPT сохранены; QA GUID очищен отдельно. Первоначальный R8 FAIL сохранён.

Win10 [main packet proof](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win10-r9/r9-win10-packet-analysis.json) содержит восемь fresh positives и 0 прямых пакетов в проверенных main/fault/network/partial/external окнах. [Offlink proof](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win10-r9/r9-offlink-packet-analysis.json): unbound: 0, включая expanded edges; certain bound: 113 исходящих/23 входящих. Первый OUT 14:32:47.704861 позже latest possible binding более 8.25с.

После host pause guest UTC менялся. Использованы измеренные интервалы, causal DNS ID/ports и консервативный union [-.6450152,+1.4826]с; стабильный UTC не заявляется. Первоначальный inconclusive анализ сохранён. [Provenance](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win10-r9/packet-proof-provenance.json). Inbound подтверждён отдельными captures обеих ОС; проверены LAN positive/offlink negative и pre-existing TCP4/6 без ответного payload.

Overlap — connected IPv4 prefix и ручные владельцы маршрутов, а не установка Docker/HNS/NAT или IPv6 overlap. Network change — статические IP/DNS. Boot proof — post-BFE/pre-Vault443; независимое исполнение до BFE не доказано. Это пределы приведённых сценариев, а не новые DHCP/RDNSS/NDMLD требования.

Последний Win11 offlink: native11 PASS 14:48:48.035 с точной очисткой, post-main4
IPv4/IPv6 HTTP/DNS PASS. [Native result](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/offlink-proof/20261107T144748340Z/result.json),
[post-main](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/offlink-proof/r9-offlink-post-main.json),
[packet proof](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/r9-offlink-packet-analysis.json).
Unbound и ambiguity0; certain bound114out/37in. Первый OUT 14:48:29.025096
на 7.60с позже latest binding CALL start. Clock-before/after интервалы перекрываются,
observed union[-.4259517,+1.2179286]с; стабильный UTC не утверждается.
2461 persisted/2474 received: 13 queued tail вне завершённого тестового окна,
0 kernel drops. Linux NATtoken596cc535… exactcleanup=true/counter1packet42bytes.

## Сохранённые инциденты

- Host IPC был утрачен при живых VM; исходный Win10 сохранён через exact-version SaveState, введён project IPC namespace. VDI/профили не откатывались ради PASS.
- Host disk-full поставил Win10 на паузу после завершённого upgrade. Только ISO cache перемещён с проверкой SHA и исходной ссылкой; та же VM продолжила работу. Clock variation учтена в анализе.
- Первый Win11 normal restart завис после Windows ShutdownEnd; Reset/SaveState также зависли. Evidence сохранён, выполнена точная остановка frontend и coldboot того же VDI. Ограниченный штатный повтор прошёл; причина первого зависания неизвестна. Он не объявлен normal PASS.

## Финальное состояние и доставка

Win10 final state: OS 19045/noSDK, LocalSystem service 7112/Auto, ordinary GUI 6544/session1; 4 main+5 work владельца сохранены, VPN off/guardfalse, external service/adapter, offlink route и overlap IP отсутствуют. VM затем выключена, snapshot `d4de2a10-95b9-4d9d-8444-49d4694bb32a`: [OFF receipt](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win10-r9/off-snapshot.json).

Win11 final: Windows 11 25H2/build 26200.6584, UEFI/SecureBoot1/TPMv2_0, noSDK;
ordinary GUI 8852/session1, LocalSystem 3448/Auto, четыре main и шесть work IDs
сохранены/off/guardfalse, нет foreign fixture/offlink route/overlap IP.
[Final state](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/final-state-after-offlink.json),
[ordinary GUI](/var/www/projects/ubuntu/vless-terminal/dist/windows/native-win11-r9/ordinary-gui-after-offlink.png).
Штатный guest shutdown /s /t0; current snapshot
`235e530f-fce4-4567-80c3-127e4d5a3a76`. Обе Windows: 4 vCPU/6144 MiB/80 GiB dynamic,
Linux fixture также OFF, owned NFT test tables/journals отсутствуют:
[all-VM final state](/var/www/projects/ubuntu/vless-terminal/dist/windows/vm-final-state-r9.json).
Предыдущий f4cac checkpoint сохранён отдельно. Тестовая CA истекает 7 ноября 23:11:28 UTC;
при повторении после срока обновлять временный стенд/trust inputs, не приложение.

Frozen candidate artifact-manifest сохраняет build-time acceptance=pending:
это исходные immutable метаданные сборки. Текущая приёмка подтверждается этим
отчётом, native receipts и отдельным [acceptance-manifest](/var/www/projects/ubuntu/vless-terminal/dist/windows/validated-2026-11-07-r9/acceptance-manifest.json) в validated delivery
`dist/windows/validated-2026-11-07-r9/`. Installer/source/build-manifest bytes
остаются прежними. Authenticode-подпись и публикация релиза не запрошены.
