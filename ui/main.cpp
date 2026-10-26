#include "bridge.h"
#include "tray.h"
#include "language.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QDBusInterface>
#include <QDBusReply>
#include <QIcon>
#include <QMenu>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QFileInfo>
#include <QDir>
#include <QDebug>

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    app.setApplicationName("vault443");
    app.setApplicationDisplayName("Vault 443");
    app.setOrganizationName("Vault443");
    app.setApplicationVersion(VAULT443_APP_VERSION);
    app.setDesktopFileName("vault443");
    app.setWindowIcon(QIcon(":/assets/profile-icons/vault-door.png"));
    QCommandLineParser parser;
    parser.setApplicationDescription("Vault 443 — Linux VPN client");
    parser.addHelpOption(); parser.addVersionOption();
    parser.addOption({"demo", "Run isolated in-memory demo; never contact the VPN service"});
    parser.addOption({"screenshot", "Write a demo screenshot and exit", "path"});
    parser.addOption({"scale", "Interface scale relative to 944×960 reference", "factor", "0.5"});
    parser.addOption({"demo-screen", "Open demo screen: main/import/import-preview/settings/subscriptions/vpn/vpn-actions/diagnostics/profile/logs/icons/combo/error", "screen", "main"});
    parser.addOption({"demo-state", "Demo runtime: connected/disconnected/connecting/reconnecting/paused_external/error/empty/single/many/stage-resolving_endpoint/retry-wait/disconnecting", "state", "connected"});
    parser.process(app);
    bool ok = false; const double scale = parser.value("scale").toDouble(&ok);
    if (!ok || scale < 0.4 || scale > 3.0) { qCritical("--scale must be between 0.4 and 3.0"); return 2; }
    const bool demo = parser.isSet("demo");
    if (parser.isSet("screenshot") && !demo) { qCritical("--screenshot requires --demo"); return 2; }
    LanguageController language(!demo);
    auto session = QDBusConnection::sessionBus();
    Bridge bridge(demo);
    if (demo) bridge.setDemoState(parser.value("demo-state"));
    if (!demo && session.isConnected()) {
        if (!session.registerService("org.vault443.Client")) {
            QDBusInterface previous("org.vault443.Client", "/org/vault443/Client", "org.vault443.Client1", session);
            previous.asyncCall("Raise");
            QTimer::singleShot(200, &app, &QCoreApplication::quit);
            return app.exec();
        }
        session.registerObject("/org/vault443/Client", &bridge, QDBusConnection::ExportAllSlots);
    }
    QQuickStyle::setStyle("Basic");
    TrayController tray(&bridge, !demo);
    QQmlApplicationEngine engine;
    QObject::connect(&language, &LanguageController::languageChanged, &engine, &QQmlEngine::retranslate);
    engine.rootContext()->setContextProperty("i18n", &language);
    engine.rootContext()->setContextProperty("backend", &bridge);
    engine.rootContext()->setContextProperty("initialScale", scale);
    engine.rootContext()->setContextProperty("demoScreen", demo ? parser.value("demo-screen") : "main");
    engine.load(QUrl("qrc:/qml/Main.qml"));
    if (engine.rootObjects().isEmpty()) return 3;
    auto *window = qobject_cast<QQuickWindow *>(engine.rootObjects().first());
    if (!window) return 3;
    if (parser.isSet("screenshot")) {
        const auto output = QFileInfo(parser.value("screenshot")).absoluteFilePath();
        QTimer::singleShot(900, &app, [window, output, &app] {
            const auto shot = window->grabWindow();
            if (shot.isNull() || !QDir().mkpath(QFileInfo(output).absolutePath()) || !shot.save(output)) { qCritical("Unable to save screenshot"); app.exit(4); }
            else app.quit();
        });
    }
    return app.exec();
}
