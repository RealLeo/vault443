#include "language.h"

#include <QCoreApplication>
#include <QDebug>
#include <QLocale>
#include <QSettings>
#include <QRegularExpression>

namespace {
QString normalizedPreference(const QString &value) {
    return value == "en" || value == "ru" ? value : QStringLiteral("system");
}
}

LanguageController::LanguageController(bool persistent, QObject *parent)
    : QObject(parent), m_persistent(persistent) {
    if (persistent) m_preference = normalizedPreference(QSettings().value("ui/language", "system").toString());
    apply();
}

LanguageController::~LanguageController() {
    QCoreApplication::removeTranslator(&m_translator);
}

QString LanguageController::resolveLanguage(const QStringList &preferences) {
    for (auto candidate : preferences) {
        candidate.replace('_', '-');
        const auto language = candidate.section('-', 0, 0).section('.', 0, 0).section('@', 0, 0).toLower();
        if (language == "en" || language == "ru") return language;
    }
    return QStringLiteral("en");
}

void LanguageController::setPreference(const QString &value) {
    const auto preference = normalizedPreference(value);
    if (m_preference == preference && preference != "system") return;
    m_preference = preference;
    if (m_persistent) {
        QSettings settings;
        settings.setValue("ui/language", preference);
        settings.sync();
        if (settings.status() != QSettings::NoError) qWarning("Could not save the interface language preference");
    }
    apply();
    emit languageChanged();
}

void LanguageController::apply() {
    QCoreApplication::removeTranslator(&m_translator);
    m_language = m_preference == "system" ? resolveLanguage(QLocale::system().uiLanguages()) : m_preference;
    if (m_language == "ru") {
        if (m_translator.load(QStringLiteral(":/i18n/vault443_ru.qm")))
            QCoreApplication::installTranslator(&m_translator);
        else {
            m_language = "en";
            qWarning("Russian translation is unavailable; using English");
        }
    }
}

QString LanguageController::serviceMessage(const QString &message) const {
    static const QRegularExpression lineError(QStringLiteral("^OpenVPN line ([0-9]+): (.+)$"));
    const auto lineMatch = lineError.match(message);
    if (lineMatch.hasMatch()) return QCoreApplication::translate("ServiceMessages", "OpenVPN line %1: %2").arg(lineMatch.captured(1), serviceMessage(lineMatch.captured(2)));
    // Compatibility replies from pre-localization daemons retain their wire
    // format. Translate only known, fixed UI messages; unknown diagnostics pass
    // through untouched. Neither the service data nor logs are rewritten.
    struct Alias { const char *legacy; const char *source; };
    static const Alias aliases[] = {
        {"Проверка других VPN уже выполняется. Повторите через несколько секунд.", QT_TRANSLATE_NOOP("ServiceMessages", "Other VPNs are already being checked. Try again in a few seconds.")},
        {"Состояние VPN меняется. Проверка повторится через несколько секунд.", QT_TRANSLATE_NOOP("ServiceMessages", "VPN state is changing. The check will run again in a few seconds.")},
        {"Сохранённая ручная привязка повреждена. Проверьте диагностику.", QT_TRANSLATE_NOOP("ServiceMessages", "The saved manual binding is damaged. Check diagnostics.")},
        {"Не удалось прочитать интерфейсы и маршруты. Проверьте диагностику и доступность службы.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not read interfaces and routes. Check diagnostics and service availability.")},
        {"Интерфейс отсутствует; проверка повторится после его появления.", QT_TRANSLATE_NOOP("ServiceMessages", "The interface is absent; it will be checked when it appears.")},
        {"Не удалось подтвердить активное подключение.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify an active connection.")},
        {"Неизвестный VPN", QT_TRANSLATE_NOOP("ServiceMessages", "Unknown VPN")},
        {"Не подтверждена связь туннеля с доверенным процессом и транспортом OpenVPN или метаданными WireGuard. Нужна диагностика или ручная привязка.", QT_TRANSLATE_NOOP("ServiceMessages", "The tunnel could not be linked to a trusted OpenVPN process and transport or WireGuard metadata. Check diagnostics or add a manual binding.")},
        {"Проверка других VPN не завершилась вовремя. Повторите попытку.", QT_TRANSLATE_NOOP("ServiceMessages", "The other VPN check timed out. Try again.")},
        {"Интерфейс ручной привязки больше не является VPN-туннелем.", QT_TRANSLATE_NOOP("ServiceMessages", "The manually bound interface is no longer a VPN tunnel.")},
        {"Не удалось подтвердить системную службу, которой принадлежит туннель.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify the system service that owns the tunnel.")},
        {"NetworkManager не подтверждает активное подключение этого туннеля.", QT_TRANSLATE_NOOP("ServiceMessages", "NetworkManager did not confirm an active connection for this tunnel.")},
        {"Не удалось прочитать транспортные соединения OpenVPN. Проверьте права службы.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not read OpenVPN transport connections. Check service permissions.")},
        {"Не удалось проверить владельцев процессов VPN. Проверьте права службы.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify VPN process owners. Check service permissions.")},
        {"Для транспорта OpenVPN не подтверждена системная служба или группа процессов.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify a system service or process group for the OpenVPN transport.")},
        {"Не удалось подтвердить метку транспорта WireGuard.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify the WireGuard transport mark.")},
        {"Не удалось подтвердить UDP-порт транспорта WireGuard.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not verify the WireGuard transport UDP port.")},
        {"У WireGuard нет подтверждённых адресов транспортного соединения.", QT_TRANSLATE_NOOP("ServiceMessages", "WireGuard has no verified transport endpoints.")},
        {"Не удалось безопасно прочитать сохранённые ручные привязки. Проверьте диагностику.", QT_TRANSLATE_NOOP("ServiceMessages", "Could not safely read saved manual bindings. Check diagnostics.")},
        {"Проверка туннеля не пройдена. Откройте диагностику для проверки настроек службы.", QT_TRANSLATE_NOOP("ServiceMessages", "Tunnel verification failed. Open diagnostics to check service settings.")},
        {"Используется другим пользователем", QT_TRANSLATE_NOOP("ServiceMessages", "In use by another user")},
        {"Проверка совместимости недоступна в этой службе.", QT_TRANSLATE_NOOP("ServiceMessages", "Compatibility checks are unavailable in this service.")},
    };
    for (const auto &alias : aliases) {
        if (message == QString::fromUtf8(alias.legacy) || message == QString::fromUtf8(alias.source))
            return QCoreApplication::translate("ServiceMessages", alias.source);
    }
    // Known fixed daemon errors are presentation aliases only. Never rewrite
    // wire data, journal entries, or unknown/dynamic technical diagnostics.
    static const char *const runtimeMessages[] = {
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot clear prior work tunnel IPv4 lease"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot clear prior work tunnel IPv6 lease"),
        QT_TRANSLATE_NOOP("ServiceMessages", "local route must be contained in an existing connected network"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN event helper requires the system service"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN event supervisor unavailable"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN exited during startup; see the profile log"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN helper route metadata did not arrive"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN management listener closed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN network setup failed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot deliver OpenVPN event"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot prepare persistent work tunnel"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot read work network recovery state"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot select work VPN server securely"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot verify installed work routes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate OpenVPN route event"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate pushed Internet routing policy"),
        QT_TRANSLATE_NOOP("ServiceMessages", "empty pushed OpenVPN option"),
        QT_TRANSLATE_NOOP("ServiceMessages", "event directory is not private"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid IPv4 route gateway"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid IPv6 route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid IPv6 route gateway"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN IPv4 route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN event destination"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN lifecycle message"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN pushed policy notification"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN route mask"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid full-tunnel route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid managed tunnel identity"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid protected work route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid pushed DNS server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid pushed DNS suffix"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid tunnel IPv6 prefix"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid tunnel MTU"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid tunnel address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid work network recovery state"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid work recovery tunnel"),
        QT_TRANSLATE_NOOP("ServiceMessages", "managed name is occupied by a foreign interface"),
        QT_TRANSLATE_NOOP("ServiceMessages", "managed tunnel name belongs to another interface"),
        QT_TRANSLATE_NOOP("ServiceMessages", "missing tunnel IPv6 prefix length"),
        QT_TRANSLATE_NOOP("ServiceMessages", "noncontiguous OpenVPN route mask"),
        QT_TRANSLATE_NOOP("ServiceMessages", "pushed DNS settings exceed limits"),
        QT_TRANSLATE_NOOP("ServiceMessages", "stop the OpenVPN process before releasing its routes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "too many OpenVPN routes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "too many pushed OpenVPN options"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported OpenVPN Internet routing flag"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported OpenVPN lifecycle event"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported pushed DHCP option"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported pushed network option"),
        QT_TRANSLATE_NOOP("ServiceMessages", "untrusted OpenVPN lifecycle sender"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work VPN interface disappeared; reconnect required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work VPN requests IPv6 Internet but supplies no IPv6 tunnel address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work recovery state belongs to another user"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work state directory must be private"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Network cleanup is incomplete; retry disconnection"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Several work VPNs claim the same route; select a target"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Another VPN owns Internet routing; choose its owner explicitly"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Several work VPNs claim this DNS zone; select a target"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Work VPN routes take priority over this local network"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Choose the work route owner in Routes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Configuring work tunnel addresses"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Resolving work VPN server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Starting OpenVPN"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Connecting to work VPN server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Verifying work VPN certificate"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Receiving work VPN configuration"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Applying work routes and DNS"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Connected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot inspect work firewall"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work routing priority is occupied by another service"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work routing table contains foreign routes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid selected work route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot install work VPN protection"),
        QT_TRANSLATE_NOOP("ServiceMessages", "too many work transport endpoints"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot configure work split DNS"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot clear obsolete work DNS"),
        QT_TRANSLATE_NOOP("ServiceMessages", "expired OpenVPN session"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot activate work tunnel"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot assign work tunnel IPv4"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot assign work tunnel IPv6"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN network event"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid pushed work route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work profile has no server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work runtime path is too long"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN 2.6 or newer is not installed securely"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN executable is not root-owned"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN 2.6 or newer is required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "at most 32 work VPNs may be requested"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work tunnel identity collision"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work VPN endpoint is not a usable network address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work VPN server address family does not match transport"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work management socket path is too long"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot create private OpenVPN management socket"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot start OpenVPN"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN management connection timed out"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN management peer identity mismatch"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot start OpenVPN management session"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN stopped; reconnect required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN exited; see the profile log"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN connection timed out"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN management connection closed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "this work profile requires unsupported interactive authentication"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN reported a fatal error; see the profile log"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN transport interrupted; reconnect required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN connection ended"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN ownership is changing; wait for cleanup"),
        QT_TRANSLATE_NOOP("ServiceMessages", "at most 16 work VPN connections may run simultaneously"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid profile icon"),
        QT_TRANSLATE_NOOP("ServiceMessages", "managed OpenVPN is unavailable; update the system service"),
        QT_TRANSLATE_NOOP("ServiceMessages", "network cleanup is in progress; retry disconnection if cleanup failed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "remove this profile's DNS rules first"),
        QT_TRANSLATE_NOOP("ServiceMessages", "remove this profile's route rules first"),
        QT_TRANSLATE_NOOP("ServiceMessages", "work VPN cleanup is incomplete; retry disconnection"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN import exceeds 8 MiB"),
        QT_TRANSLATE_NOOP("ServiceMessages", "choose between 1 and 32 OpenVPN files"),
        QT_TRANSLATE_NOOP("ServiceMessages", "import contains no usable profiles"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN import document"),
        QT_TRANSLATE_NOOP("ServiceMessages", "DNS rule not found"),
        QT_TRANSLATE_NOOP("ServiceMessages", "enter a DNS domain"),
        QT_TRANSLATE_NOOP("ServiceMessages", "local rules require a directly connected subnet"),
        QT_TRANSLATE_NOOP("ServiceMessages", "route rule not found"),
        QT_TRANSLATE_NOOP("ServiceMessages", "route rule requires a unicast IP address or CIDR"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid work VPN route target"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid DNS routing domain"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid work VPN DNS target"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Another user owns the VPN"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile must be valid UTF-8 and at most 1 MiB"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile contains unsupported control characters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported inline block"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate inline credential block"),
        QT_TRANSLATE_NOOP("ServiceMessages", "nested or mismatched inline block"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unterminated inline credential block"),
        QT_TRANSLATE_NOOP("ServiceMessages", "directive exceeds 16 KiB"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid quoting or escape sequence"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid or unsupported directive"),
        QT_TRANSLATE_NOOP("ServiceMessages", "only the data-ciphers compatibility hint is supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate directive"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate client metadata variable"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid remote server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid remote port"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported OpenVPN transport"),
        QT_TRANSLATE_NOOP("ServiceMessages", "at most 16 remote servers are supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unexpected directive arguments"),
        QT_TRANSLATE_NOOP("ServiceMessages", "only TUN client profiles are supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid cipher setting"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported or insecure data cipher"),
        QT_TRANSLATE_NOOP("ServiceMessages", "expected one cipher"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported packet authentication algorithm"),
        QT_TRANSLATE_NOOP("ServiceMessages", "server certificate validation is required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid certificate name constraint"),
        QT_TRANSLATE_NOOP("ServiceMessages", "only TLS 1.2 or newer is supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid TLS cipher setting"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid TLS key direction"),
        QT_TRANSLATE_NOOP("ServiceMessages", "only bounded UV_ client metadata is supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "supported log verbosity is 0–4"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid log repetition limit"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid renegotiation interval"),
        QT_TRANSLATE_NOOP("ServiceMessages", "interactive authentication is unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid connection timeout"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid retry interval"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid retry limit"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid resolver retry setting"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid socket buffer size"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid TUN MTU"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid MSS setting"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid exit notification setting"),
        QT_TRANSLATE_NOOP("ServiceMessages", "active compression is unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported TUN topology"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported redirect flag"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid numeric IPv4 route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid numeric IPv6 route"),
        QT_TRANSLATE_NOOP("ServiceMessages", "route gateway must be a numeric IPv4 address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "route gateway must be a numeric IPv6 address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid route metric"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid route delay"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid DNS option"),
        QT_TRANSLATE_NOOP("ServiceMessages", "DNS server must be numeric"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid DNS domain"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported DHCP option"),
        QT_TRANSLATE_NOOP("ServiceMessages", "credentials must be embedded inline; external file references are unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "passwords, MFA and external credential providers are unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported directive; scripts, plugins, includes and runtime overrides are forbidden"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile requires client and dev tun"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile requires remote-cert-tls server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile has no remote server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "OpenVPN profile requires embedded CA, client certificate and private key"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid embedded CA certificate"),
        QT_TRANSLATE_NOOP("ServiceMessages", "encrypted or invalid private keys are unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid embedded client certificate or mismatched private key"),
        QT_TRANSLATE_NOOP("ServiceMessages", "tls-auth and tls-crypt cannot be combined"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid embedded TLS control-channel key"),
        QT_TRANSLATE_NOOP("ServiceMessages", "key-direction requires an embedded tls-auth key"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid OpenVPN profile identity"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported credential block"),

        QT_TRANSLATE_NOOP("ServiceMessages", "VPN server DNS lookup timed out; DNS and HTTPS fallback did not complete"),
        QT_TRANSLATE_NOOP("ServiceMessages", "DNS returned no IPv4 address for the VPN server"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN server DNS name does not exist"),
        QT_TRANSLATE_NOOP("ServiceMessages", "DNS HTTPS fallback certificate or TLS verification failed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN server DNS lookup failed; protected DNS and HTTPS fallback are unavailable"),
        QT_TRANSLATE_NOOP("ServiceMessages", "DNS HTTPS fallback returned an invalid response"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN DNS did not return an IPv4 address; Internet remains protected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN DNS works, but HTTPS through the tunnel timed out; Internet remains protected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN DNS works, but HTTPS certificate verification failed; Internet remains protected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN DNS works, but the HTTPS connectivity check returned an unexpected response; Internet remains protected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "VPN DNS works, but HTTPS through the tunnel failed; Internet remains protected"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported import kind"),
        QT_TRANSLATE_NOOP("ServiceMessages", "import exceeds 1 MiB"),
        QT_TRANSLATE_NOOP("ServiceMessages", "import preparation canceled"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot create import draft"),
        QT_TRANSLATE_NOOP("ServiceMessages", "too many pending imports; cancel an earlier preview"),
        QT_TRANSLATE_NOOP("ServiceMessages", "import draft not found or expired"),
        QT_TRANSLATE_NOOP("ServiceMessages", "icon selection exceeds size limit"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid icon selection"),
        QT_TRANSLATE_NOOP("ServiceMessages", "import contains no usable profiles or an invalid subscription"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid icon or profile selection"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription already exists"),
        QT_TRANSLATE_NOOP("ServiceMessages", "a user may keep at most 32 subscriptions"),
        QT_TRANSLATE_NOOP("ServiceMessages", "a user may keep at most 1024 profiles"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unknown profile icon"),
        QT_TRANSLATE_NOOP("ServiceMessages", "profile not found"),
        QT_TRANSLATE_NOOP("ServiceMessages", "disconnect the profile before removing it"),
        QT_TRANSLATE_NOOP("ServiceMessages", "disable boot autoconnect before removing the profile"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription contains unsupported or invalid profiles; nothing changed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription not found"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription contains unsupported or invalid profiles"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription no longer exists"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription would exceed 1024 profiles"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Refresh failed; existing profiles were preserved"),
        QT_TRANSLATE_NOOP("ServiceMessages", "a unique authenticated D-Bus sender is required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot authenticate the caller"),
        QT_TRANSLATE_NOOP("ServiceMessages", "cannot resolve caller group membership"),
        QT_TRANSLATE_NOOP("ServiceMessages", "caller must belong to the vault443 operator group"),
        QT_TRANSLATE_NOOP("ServiceMessages", "an active local login session is required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "administrator membership is required"),
        QT_TRANSLATE_NOOP("ServiceMessages", "another user owns the VPN; explicitly take control first"),
        QT_TRANSLATE_NOOP("ServiceMessages", "network cleanup is in progress; wait until disconnection completes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "network cleanup is incomplete; see diagnostics"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Network cleanup is incomplete; protection may remain enabled. Retry disconnection."),
        QT_TRANSLATE_NOOP("ServiceMessages", "Connection failed; see the profile journal"),
        QT_TRANSLATE_NOOP("ServiceMessages", "binding exceeds size limit"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid VPN binding; use the documented manager/interface format"),
        QT_TRANSLATE_NOOP("ServiceMessages", "missing system boot identity"),
        QT_TRANSLATE_NOOP("ServiceMessages", "boot guard profile is missing"),
        QT_TRANSLATE_NOOP("ServiceMessages", "network release failed; protection may remain armed; inspect system journal and retry --release-network"),
        QT_TRANSLATE_NOOP("ServiceMessages", "startup profile is missing"),
        QT_TRANSLATE_NOOP("ServiceMessages", "boot network protection could not be armed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "name contains unsupported control characters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "name must contain 1–80 characters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "profile link exceeds 16 KiB"),
        QT_TRANSLATE_NOOP("ServiceMessages", "expected a vless://UUID@host:port link"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid VLESS UUID"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid server hostname or IP address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "server port must be 1–65535"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid percent-encoded profile parameters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported profile parameter; no parameters were silently ignored"),
        QT_TRANSLATE_NOOP("ServiceMessages", "duplicate profile parameter"),
        QT_TRANSLATE_NOOP("ServiceMessages", "control characters in profile parameter"),
        QT_TRANSLATE_NOOP("ServiceMessages", "only encryption=none with TLS or REALITY is supported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported transport; supported: tcp, ws, grpc, xhttp"),
        QT_TRANSLATE_NOOP("ServiceMessages", "TLS or REALITY is required; unencrypted VLESS is unsupported"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported VLESS flow"),
        QT_TRANSLATE_NOOP("ServiceMessages", "Vision requires the tcp transport"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid TLS server name"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported TLS fingerprint"),
        QT_TRANSLATE_NOOP("ServiceMessages", "REALITY is unsupported with this transport"),
        QT_TRANSLATE_NOOP("ServiceMessages", "REALITY requires a valid 32-byte public key"),
        QT_TRANSLATE_NOOP("ServiceMessages", "REALITY short ID must be 0–16 hexadecimal digits in byte pairs"),
        QT_TRANSLATE_NOOP("ServiceMessages", "REALITY parameters require security=reality"),
        QT_TRANSLATE_NOOP("ServiceMessages", "support-x25519mlkem768 must be a boolean"),
        QT_TRANSLATE_NOOP("ServiceMessages", "support-x25519mlkem768=false is unsupported: the pinned Xray does not expose an ML-KEM disable switch"),
        QT_TRANSLATE_NOOP("ServiceMessages", "support-x25519mlkem768=true requires fp=chrome, firefox or safari with the pinned Xray"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported ALPN value"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported tcp transport parameters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported WebSocket transport parameters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported gRPC transport parameters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported gRPC mode"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported XHTTP transport parameters"),
        QT_TRANSLATE_NOOP("ServiceMessages", "unsupported XHTTP mode"),
        QT_TRANSLATE_NOOP("ServiceMessages", "transport path must start with / and fit 4096 bytes"),
        QT_TRANSLATE_NOOP("ServiceMessages", "transport parameter exceeds size limit"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription URL is too long"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription requires an HTTPS URL without user info or fragment"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription address must be publicly routable"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid subscription endpoint"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription DNS lookup failed"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription DNS returned no addresses"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription resolved to a non-public address"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription endpoint unavailable"),
        QT_TRANSLATE_NOOP("ServiceMessages", "too many subscription redirects"),
        QT_TRANSLATE_NOOP("ServiceMessages", "invalid subscription request"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription download failed (HTTPS, DNS, or timeout)"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription server returned an unsuccessful response"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription download was interrupted"),
        QT_TRANSLATE_NOOP("ServiceMessages", "subscription exceeds 1 MiB"),
    };
    for (const auto *source : runtimeMessages) {
        if (message == QString::fromUtf8(source))
            return QCoreApplication::translate("ServiceMessages", source);
    }
    // UI-generated messages are stored in source form so changing language
    // never changes a network snapshot or replays an operation/error signal.
    const auto source = message.toUtf8();
    return QCoreApplication::translate("Bridge", source.constData());
}
