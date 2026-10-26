#include "bridge.h"
#include "language.h"
#include "tray.h"

#include <QApplication>
#include <QDBusArgument>
#include <QDBusConnectionInterface>
#include <QDBusContext>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusPendingCallWatcher>
#include <QDBusVariant>
#include <QEventLoop>
#include <QProcess>
#include <QSignalSpy>
#include <QTest>
#include <cstdio>

static constexpr auto watcherService = "org.kde.StatusNotifierWatcher";
static constexpr auto watcherPath = "/StatusNotifierWatcher";
static constexpr auto itemInterface = "org.kde.StatusNotifierItem";

// A separate process implements the public host contract. The application under
// test still uses Qt's real native tray plugin and exported D-Bus menu.
class Watcher final : public QObject, protected QDBusContext {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.kde.StatusNotifierWatcher")
    Q_PROPERTY(QStringList RegisteredStatusNotifierItems READ items)
    Q_PROPERTY(bool IsStatusNotifierHostRegistered READ hasHost)
    Q_PROPERTY(int ProtocolVersion READ protocolVersion)
public:
    explicit Watcher(bool hostReady) : m_hostReady(hostReady) {}
    QStringList items() const { return m_items; }
    bool hasHost() const { return m_hostReady; }
    int protocolVersion() const { return 0; }
public slots:
    void RegisterStatusNotifierItem(const QString &requested) {
        const auto service = requested.startsWith('/') ? message().service() : requested;
        const auto path = requested.startsWith('/') ? requested : QString("/StatusNotifierItem");
        const auto id = service + path;
        if (!m_items.contains(id)) { m_items.append(id); emit StatusNotifierItemRegistered(id); }
        m_addresses.append(service + "|" + path);
    }
    void RegisterStatusNotifierHost(const QString &) { emit StatusNotifierHostRegistered(); }
    QStringList GetAddresses() const { return m_addresses; }
    void SetHostReady() { m_hostReady = true; emit StatusNotifierHostRegistered(); }
signals:
    void StatusNotifierItemRegistered(const QString &service);
    void StatusNotifierItemUnregistered(const QString &service);
    void StatusNotifierHostRegistered();
    void StatusNotifierHostUnregistered();
private:
    QStringList m_items, m_addresses;
    bool m_hostReady;
};

struct MenuLayout {
    int id = 0;
    QVariantMap properties;
    QList<QDBusVariant> children;
};
Q_DECLARE_METATYPE(MenuLayout)
QDBusArgument &operator<<(QDBusArgument &argument, const MenuLayout &layout) {
    argument.beginStructure();
    argument << layout.id << layout.properties << layout.children;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, MenuLayout &layout) {
    argument.beginStructure();
    argument >> layout.id >> layout.properties >> layout.children;
    argument.endStructure();
    return argument;
}

static QDBusMessage remoteCall(const QString &service, const QString &path, const QString &interface,
                              const QString &method, const QVariantList &args = {}) {
    auto message = QDBusMessage::createMethodCall(service, path, interface, method);
    message.setArguments(args);
    QDBusPendingCallWatcher call(QDBusConnection::sessionBus().asyncCall(message, 3000));
    if (!call.isFinished()) {
        QEventLoop loop;
        QObject::connect(&call, &QDBusPendingCallWatcher::finished, &loop, &QEventLoop::quit);
        loop.exec();
    }
    return call.reply();
}

class ItemSignals final : public QObject {
    Q_OBJECT
public:
    int toolTips = 0, icons = 0;
public slots:
    void toolTipChanged() { ++toolTips; }
    void iconChanged() { ++icons; }
};

class TrayHostTests final : public QObject {
    Q_OBJECT
private:
    std::unique_ptr<LanguageController> m_language;
    QProcess m_watcher;
    QString m_service, m_path;
    bool startHost(bool ready = true) {
        m_watcher.start(QCoreApplication::applicationFilePath(), {ready ? "--watcher" : "--watcher-wait"});
        if (!m_watcher.waitForStarted(3000)) return false;
        return m_watcher.waitForReadyRead(3000) && m_watcher.readAllStandardOutput().contains("READY");
    }
    void stopHost() {
        m_watcher.terminate();
        if (!m_watcher.waitForFinished(3000)) { m_watcher.kill(); m_watcher.waitForFinished(); }
    }
    bool findRegistration() {
        const auto reply = remoteCall(watcherService, watcherPath, watcherService, "GetAddresses");
        if (reply.type() == QDBusMessage::ErrorMessage || reply.arguments().isEmpty()) return false;
        const auto entries = qdbus_cast<QStringList>(reply.arguments().first());
        if (entries.isEmpty()) return false;
        const auto address = entries.last().split('|');
        if (address.size() != 2) return false;
        m_service = address[0]; m_path = address[1];
        return true;
    }
    QVariant property(const QString &name) {
        const auto reply = remoteCall(m_service, m_path, "org.freedesktop.DBus.Properties", "Get", {itemInterface, name});
        if (reply.type() == QDBusMessage::ErrorMessage || reply.arguments().size() != 1) return {};
        return qvariant_cast<QDBusVariant>(reply.arguments().first()).variant();
    }
    QString tooltip() {
        const auto value = property("ToolTip");
        if (!value.canConvert<QDBusArgument>()) return {};
        const auto argument = qvariant_cast<QDBusArgument>(value);
        QString iconName, title, description;
        argument.beginStructure();
        argument >> iconName;
        argument.beginArray();
        while (!argument.atEnd()) {
            int width, height; QByteArray pixels;
            argument.beginStructure(); argument >> width >> height >> pixels; argument.endStructure();
        }
        argument.endArray();
        argument >> title >> description;
        argument.endStructure();
        return title + "\n" + description;
    }
    QList<MenuLayout> menu() {
        const auto path = qvariant_cast<QDBusObjectPath>(property("Menu")).path();
        const auto reply = remoteCall(m_service, path, "com.canonical.dbusmenu", "GetLayout", {0, -1, QStringList{}});
        QList<MenuLayout> result;
        if (reply.type() == QDBusMessage::ErrorMessage || reply.arguments().size() != 2) return result;
        const auto root = qdbus_cast<MenuLayout>(reply.arguments()[1]);
        for (const auto &child : root.children) result.append(qdbus_cast<MenuLayout>(child.variant()));
        return result;
    }
    bool validIcon(const QColor &badge) {
        const auto value = property("IconPixmap");
        if (!value.canConvert<QDBusArgument>()) return false;
        const auto argument = qvariant_cast<QDBusArgument>(value);
        bool icon16 = false, icon32 = false, large = false;
        argument.beginArray();
        while (!argument.atEnd()) {
            int width, height; QByteArray pixels;
            argument.beginStructure(); argument >> width >> height >> pixels; argument.endStructure();
            if (width != height || pixels.size() != width * height * 4 || pixels.count('\0') == pixels.size()) return false;
            const int offset = (int(height * .8) * width + int(width * .8)) * 4;
            // StatusNotifierItem pixmaps are ARGB32 in network byte order.
            if (uchar(pixels[offset]) != 255 || uchar(pixels[offset + 1]) != badge.red()
                || uchar(pixels[offset + 2]) != badge.green() || uchar(pixels[offset + 3]) != badge.blue()) return false;
            if (width == 16) icon16 = true;
            if (width == 32) icon32 = true;
            if (width >= 48) large = true;
        }
        argument.endArray();
        return icon16 && icon32 && large;
    }
private slots:
    void initTestCase() {
        QVERIFY2(qEnvironmentVariableIsSet("VAULT443_PRIVATE_TRAY_TEST"), "Only run via the isolated private-bus wrapper");
        QVERIFY(QDBusConnection::sessionBus().isConnected());
        qDBusRegisterMetaType<MenuLayout>();
        QVERIFY(!QDBusConnection::sessionBus().interface()->isServiceRegistered(watcherService).value());
        m_language = std::make_unique<LanguageController>(false);
    }
    void nativeRegistrationStatusMenuAndRestart() {
        Bridge bridge(true);
        TrayController tray(&bridge, true);
        // No window exists: these changes must be exported with the GUI hidden.
        QVERIFY(!bridge.trayAvailable());
        QVERIFY(startHost(false));
        // The watcher can exist before the panel host registers with it. A first
        // Qt 6.4 probe here would permanently cache a negative availability.
        QTest::qWait(100);
        QVERIFY(!bridge.trayAvailable());
        QVERIFY(!findRegistration());
        QCOMPARE(remoteCall(watcherService, watcherPath, watcherService, "SetHostReady").type(), QDBusMessage::ReplyMessage);
        QTRY_VERIFY_WITH_TIMEOUT(findRegistration(), 10000);
        QTRY_VERIFY_WITH_TIMEOUT(bridge.trayAvailable(), 5000);
        QVERIFY(validIcon(QColor("#64e875")));
        ItemSignals itemSignals;
        QVERIFY(QDBusConnection::sessionBus().connect(m_service, m_path, itemInterface, "NewToolTip", &itemSignals, SLOT(toolTipChanged())));
        QVERIFY(QDBusConnection::sessionBus().connect(m_service, m_path, itemInterface, "NewIcon", &itemSignals, SLOT(iconChanged())));
        const auto cases = QList<QPair<QString, const char *>>{
            {"disconnected", "Disconnected"}, {"connected", "Connected"},
            {"connecting", "Connecting…"}, {"reconnecting", "Reconnecting…"},
            {"paused_external", "Paused — another VPN provides Internet access"},
            {"error", "Connection error"}, {"foreign", "In use by another user"},
            {"offline", "Service unavailable — VPN state unknown"}};
        const auto profileName = bridge.profiles().first().toMap().value("name").toString();
        for (const auto &[state, source] : cases) {
            const auto text = QCoreApplication::translate("QObject", source);
            const auto previousToolTips = itemSignals.toolTips;
            const auto previousIcons = itemSignals.icons;
            const auto previousColor = trayPresentation(bridge.snapshot(), bridge.online(), bridge.busy()).color;
            bridge.setDemoState(state);
            const auto nextColor = trayPresentation(bridge.snapshot(), bridge.online(), bridge.busy()).color;
            QTRY_VERIFY_WITH_TIMEOUT(itemSignals.toolTips > previousToolTips, 5000);
            if (previousColor != nextColor) QTRY_VERIFY_WITH_TIMEOUT(itemSignals.icons > previousIcons, 5000);
            QTRY_VERIFY_WITH_TIMEOUT(tooltip().contains(text), 5000);
            QVERIFY(validIcon(nextColor));
            QList<MenuLayout> entries;
            QTRY_VERIFY_WITH_TIMEOUT(!(entries = menu()).isEmpty() && entries.first().properties.value("label").toString().contains(text), 5000);
            QCOMPARE(entries.first().properties.value("enabled").toBool(), false);
            const auto own = state != "foreign" && state != "offline" && state != "disconnected";
            bool foundDisconnect = false;
            for (const auto &entry : entries) {
                if (entry.properties.value("label").toString() != QCoreApplication::translate("TrayController", "Disconnect VPN")) continue;
                foundDisconnect = true;
                // D-Bus Menu's absent enabled property means the default, true.
                QCOMPARE(entry.properties.value("enabled", true).toBool(), own);
            }
            QVERIFY(foundDisconnect);
            QCOMPARE(tooltip().contains(profileName), own);
        }
        bridge.setDemoState("connected");
        stopHost();
        QTRY_VERIFY_WITH_TIMEOUT(!bridge.trayAvailable(), 5000);
        QVERIFY(startHost());
        QTRY_VERIFY_WITH_TIMEOUT(findRegistration(), 10000);
        QTRY_VERIFY_WITH_TIMEOUT(bridge.trayAvailable(), 5000);
        QTRY_VERIFY_WITH_TIMEOUT(tooltip().contains(QCoreApplication::translate("QObject", "Connected")), 5000);
        QVERIFY(validIcon(QColor("#64e875")));
        const auto originalLanguage = m_language->language();
        m_language->setPreference(originalLanguage == "en" ? "ru" : "en");
        QTRY_VERIFY_WITH_TIMEOUT(tooltip().contains(QCoreApplication::translate("QObject", "Connected")), 5000);
        QVERIFY(tooltip().contains(profileName));
        m_language->setPreference(originalLanguage);
        QTRY_VERIFY_WITH_TIMEOUT(tooltip().contains(QCoreApplication::translate("QObject", "Connected")), 5000);
        // A real host sends Activate over D-Bus when the icon is clicked.
        QSignalSpy raised(&bridge, &Bridge::raiseRequested);
        QCOMPARE(remoteCall(m_service, m_path, itemInterface, "Activate", {0, 0}).type(), QDBusMessage::ReplyMessage);
        QTRY_COMPARE(raised.count(), 1);
        const auto menuPath = qvariant_cast<QDBusObjectPath>(property("Menu")).path();
        int disconnectId = -1, openId = -1;
        for (const auto &entry : menu()) {
            if (entry.properties.value("label").toString() == QCoreApplication::translate("TrayController", "Disconnect VPN")) disconnectId = entry.id;
            if (entry.properties.value("label").toString() == QCoreApplication::translate("TrayController", "Open Vault 443")) openId = entry.id;
        }
        QVERIFY(openId >= 0 && disconnectId >= 0);
        const auto clickMenu = [&](int id) {
            return remoteCall(m_service, menuPath, "com.canonical.dbusmenu", "Event",
                              {id, "clicked", QVariant::fromValue(QDBusVariant(0)), uint(0)});
        };
        QCOMPARE(clickMenu(openId).type(), QDBusMessage::ReplyMessage);
        QTRY_COMPARE(raised.count(), 2);
        QCOMPARE(clickMenu(disconnectId).type(), QDBusMessage::ReplyMessage);
        QTRY_COMPARE(bridge.snapshot().value("runtime").toMap().value("state").toString(), QString("disconnected"));
        QTRY_VERIFY_WITH_TIMEOUT(tooltip().contains(QCoreApplication::translate("QObject", "Disconnected")), 5000);
    }
    void cleanupTestCase() { stopHost(); }
};

int main(int argc, char **argv) {
    if (argc == 2 && QByteArray(argv[1]).startsWith("--watcher")) {
        QCoreApplication app(argc, argv);
        Watcher watcher(QByteArray(argv[1]) == "--watcher");
        auto bus = QDBusConnection::sessionBus();
        if (!bus.registerObject(watcherPath, &watcher, QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllSignals | QDBusConnection::ExportAllProperties)
            || !bus.registerService(watcherService)) return 2;
        std::puts("READY"); std::fflush(stdout);
        return app.exec();
    }
    QApplication app(argc, argv);
    app.setApplicationName("vault443-tray-host-test");
    app.setQuitOnLastWindowClosed(false);
    TrayHostTests tests;
    return QTest::qExec(&tests, argc, argv);
}

#include "tray_host_tests.moc"
