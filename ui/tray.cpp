#include "tray.h"
#include "bridge.h"

#include <QApplication>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusServiceWatcher>
#include <QDBusVariant>
#include <QPainter>
#include <QEvent>

TrayPresentation trayPresentation(const QVariantMap &snapshot, bool online, bool busy) {
    TrayPresentation out{QObject::tr("Disconnected"), QColor("#92988f"), false};
    if (!online) {
        out.text = QObject::tr("Service unavailable — VPN state unknown");
        return out;
    }
    if (snapshot.value("busyByOtherUser").toBool()) {
        out.text = QObject::tr("In use by another user");
        return out;
    }
    const auto state = snapshot.value("runtime").toMap().value("state").toString();
    if (state == "connected") { out.text = QObject::tr("Connected"); out.color = QColor("#64e875"); }
    else if (state == "connecting") { out.text = QObject::tr("Connecting…"); out.color = QColor("#f5ca55"); }
    else if (state == "reconnecting") { out.text = QObject::tr("Reconnecting…"); out.color = QColor("#f5ca55"); }
    else if (state == "paused_external") { out.text = QObject::tr("Paused — another VPN provides Internet access"); out.color = QColor("#68acff"); }
    else if (state == "error") { out.text = QObject::tr("Connection error"); out.color = QColor("#f06b5f"); }
    else if (state != "disconnected") { out.text = QObject::tr("VPN state unknown"); }
    const auto operation = snapshot.value("operation").toMap();
    const auto stage = operation.value("stage").toString();
    const bool cleaning = operation.value("action").toString() == "disconnect" && stage != "disconnected" && stage != "cleanup_failed";
    if (cleaning) { out.text = QObject::tr("Disconnecting — restoring network…"); out.color = QColor("#f5ca55"); }
    else if (stage == "cleanup_failed") { out.text = QObject::tr("Network cleanup failed — retry disconnecting"); out.color = QColor("#f06b5f"); }
    else if (!stage.isEmpty() && stage != "connected" && stage != "disconnected" && stage != "paused_external" && stage != "retry_wait") {
        out.text = QObject::tr("Connecting…"); out.color = QColor("#f5ca55");
    }
    const auto id = snapshot.value("activeProfileId").toString();
    // activeProfileId is exposed by the daemon only to the desired session's owner.
    out.canDisconnect = !id.isEmpty() && !busy && !cleaning;
    if (!id.isEmpty()) for (const auto &value : snapshot.value("profiles").toList()) {
        const auto profile = value.toMap();
        if (profile.value("id").toString() != id) continue;
        auto name = profile.value("name").toString().simplified().left(100);
        if (!name.isEmpty()) out.text += " · " + name;
        break;
    }
    return out;
}

QIcon trayIcon(const QColor &color) {
    const QImage door(":/assets/profile-icons/vault-door.png");
    QIcon icon;
    for (int size : {16, 20, 22, 24, 28, 32, 40, 44, 48, 64, 96, 128}) {
        QPixmap pixmap(size, size);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::SmoothPixmapTransform);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.drawImage(QRectF(0, 0, size, size), door);
        const qreal diameter = size * 0.36;
        const qreal stroke = qMax(1.0, size / 24.0);
        painter.setPen(QPen(QColor("#171c17"), stroke));
        painter.setBrush(color);
        painter.drawEllipse(QRectF(size - diameter - stroke/2, size - diameter - stroke/2, diameter, diameter));
        painter.end();
        icon.addPixmap(pixmap);
    }
    return icon;
}

TrayController::TrayController(Bridge *bridge, bool enabled, QObject *parent)
    : QObject(parent), m_bridge(bridge) {
    m_status = m_menu.addAction(QString());
    m_status->setObjectName("tray-status");
    m_status->setEnabled(false);
    m_menu.addSeparator();
    m_menu.addAction(tr("Open Vault 443"), bridge, &Bridge::Raise)->setObjectName("tray-open");
    m_disconnect = m_menu.addAction(tr("Disconnect VPN"), this, [this] {
        if (trayPresentation(m_bridge->snapshot(), m_bridge->online(), m_bridge->networkBusy()).canDisconnect)
            m_bridge->disconnectProfile();
    });
    m_disconnect->setObjectName("tray-disconnect");
    m_menu.addSeparator();
    m_menu.addAction(tr("Quit interface (VPN stays connected)"), qApp, &QApplication::quit)->setObjectName("tray-quit");
    qApp->installEventFilter(this);
    connect(bridge, &Bridge::snapshotChanged, this, &TrayController::update);
    connect(bridge, &Bridge::onlineChanged, this, &TrayController::update);
    connect(bridge, &Bridge::busyChanged, this, &TrayController::update);
    update();
    if (!enabled) { createIcon(); return; }
    connect(&m_hostTimer, &QTimer::timeout, this, &TrayController::checkHost);
    m_hostTimer.start(2000);
    auto *watcher = new QDBusServiceWatcher("org.kde.StatusNotifierWatcher", QDBusConnection::sessionBus(),
                                          QDBusServiceWatcher::WatchForOwnerChange, this);
    connect(watcher, &QDBusServiceWatcher::serviceOwnerChanged, this,
            [this](const QString &, const QString &, const QString &owner) {
        ++m_hostGeneration;
        m_recreate = true;
        m_bridge->setTrayAvailable(false);
        if (owner.isEmpty() && m_tray) m_tray->hide();
        checkHost();
    });
    checkHost();
}

bool TrayController::eventFilter(QObject *watched, QEvent *event) {
    if (watched == qApp && event->type() == QEvent::LanguageChange) retranslate();
    return QObject::eventFilter(watched, event);
}

void TrayController::retranslate() {
    for (auto *action : m_menu.actions()) {
        if (action->objectName() == "tray-open") action->setText(tr("Open Vault 443"));
        else if (action->objectName() == "tray-disconnect") action->setText(tr("Disconnect VPN"));
        else if (action->objectName() == "tray-quit") action->setText(tr("Quit interface (VPN stays connected)"));
    }
    update();
}

void TrayController::createIcon() {
    m_tray = std::make_unique<QSystemTrayIcon>();
    m_color = QColor();
    m_tray->setContextMenu(&m_menu);
    connect(m_tray.get(), &QSystemTrayIcon::activated, m_bridge, [this](auto reason) {
        if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) m_bridge->Raise();
    });
    update();
}

void TrayController::update() {
    const auto view = trayPresentation(m_bridge->snapshot(), m_bridge->online(), m_bridge->networkBusy());
    if (m_tray) {
        if (m_color != view.color) { m_color = view.color; m_tray->setIcon(trayIcon(view.color)); }
        m_tray->setToolTip("Vault 443\n" + view.text);
    }
    auto menuText = view.text;
    m_status->setText(menuText.replace('&', "&&"));
    m_disconnect->setEnabled(view.canDisconnect);
}

void TrayController::checkHost() {
    if (m_hostPending) return;
    m_hostPending = true;
    const auto generation = m_hostGeneration;
    // Qt 6.4's generic Unix theme caches a negative SNI-host result for the
    // process lifetime. Do not construct a tray or ask Qt's availability until
    // the Ubuntu/GNOME StatusNotifier host is ready, including late startup.
    auto message = QDBusMessage::createMethodCall("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher",
                                                "org.freedesktop.DBus.Properties", "Get");
    message.setArguments({"org.kde.StatusNotifierWatcher", "IsStatusNotifierHostRegistered"});
    message.setAutoStartService(false);
    auto *call = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(message, 1000), this);
    connect(call, &QDBusPendingCallWatcher::finished, this, [this, call, generation] {
        const auto reply = call->reply(); call->deleteLater(); m_hostPending = false;
        if (generation != m_hostGeneration) { checkHost(); return; }
        const bool available = reply.type() != QDBusMessage::ErrorMessage &&
            reply.arguments().value(0).value<QDBusVariant>().variant().toBool();
        if (available) {
            if (!m_tray || m_recreate) { createIcon(); m_recreate = false; }
            m_tray->show();
        } else if (m_tray) m_tray->hide();
        m_bridge->setTrayAvailable(available);
        qApp->setQuitOnLastWindowClosed(!available);
    });
}
