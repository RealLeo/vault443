#pragma once

#include <QColor>
#include <QIcon>
#include <QMenu>
#include <QObject>
#include <QSystemTrayIcon>
#include <QTimer>
#include <QVariantMap>
#include <memory>

class Bridge;

struct TrayPresentation {
    QString text;
    QColor color;
    bool canDisconnect = false;
};

TrayPresentation trayPresentation(const QVariantMap &snapshot, bool online, bool busy);
QIcon trayIcon(const QColor &color);

class TrayController final : public QObject {
    Q_OBJECT
public:
    explicit TrayController(Bridge *bridge, bool enabled, QObject *parent = nullptr);
    QSystemTrayIcon *icon() { return m_tray.get(); }
    QMenu *menu() { return &m_menu; }
private:
    bool eventFilter(QObject *watched, QEvent *event) override;
    void retranslate();
    void update();
    void checkHost();
    void createIcon();
    Bridge *m_bridge;
    std::unique_ptr<QSystemTrayIcon> m_tray;
    QMenu m_menu;
    QAction *m_status;
    QAction *m_disconnect;
    QTimer m_hostTimer;
    QColor m_color;
    quint64 m_hostGeneration = 0;
    bool m_hostPending = false, m_recreate = false;
};
