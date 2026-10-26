#include "language.h"

#include <QCoreApplication>
#include <QDebug>
#include <QLocale>
#include <QSettings>

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
