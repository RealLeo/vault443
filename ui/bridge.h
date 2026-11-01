#pragma once

#include <QObject>
#include <QVariantMap>
#include <QHash>
#include <QJsonObject>
#include <QDBusConnection>
#include <QDBusServiceWatcher>
#include <QSettings>
#include <QTimer>
#include <functional>

class Bridge final : public QObject {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.vault443.Client1")
    Q_PROPERTY(QVariantMap snapshot READ snapshot NOTIFY snapshotChanged)
    Q_PROPERTY(QVariantList profiles READ profiles NOTIFY profilesChanged)
    Q_PROPERTY(QVariantList bootProfiles READ bootProfiles NOTIFY bootProfilesChanged)
    Q_PROPERTY(bool importPreparing READ importPreparing NOTIFY requestStateChanged)
    Q_PROPERTY(bool importCommitting READ importCommitting NOTIFY requestStateChanged)
    Q_PROPERTY(bool bootPending READ bootPending NOTIFY requestStateChanged)
    Q_PROPERTY(bool logActionPending READ logActionPending NOTIFY requestStateChanged)
    Q_PROPERTY(QString logsError READ logsError NOTIFY logsStateChanged)
    Q_PROPERTY(QVariantMap preview READ preview NOTIFY previewChanged)
    Q_PROPERTY(QVariantMap workRequests READ workRequests NOTIFY workRequestsChanged)
    Q_PROPERTY(QVariantMap workRoutes READ workRoutes NOTIFY workRoutesChanged)
    Q_PROPERTY(QString workRoutesError READ workRoutesError NOTIFY workRoutesChanged)
    Q_PROPERTY(bool workRoutesPending READ workRoutesPending NOTIFY workRoutesChanged)
    Q_PROPERTY(QVariantList profileLogs READ profileLogs NOTIFY profileLogsChanged)
    Q_PROPERTY(QString logPreviousCursor READ logPreviousCursor NOTIFY logsStateChanged)
    Q_PROPERTY(QString logCursor READ logCursor NOTIFY logsStateChanged)
    Q_PROPERTY(QString diagnostics READ diagnostics NOTIFY diagnosticsChanged)
    Q_PROPERTY(QVariantMap diagnosticData READ diagnosticData NOTIFY diagnosticsChanged)
    Q_PROPERTY(QString diagnosticsError READ diagnosticsError NOTIFY diagnosticsChanged)
    Q_PROPERTY(bool diagnosticsPending READ diagnosticsPending NOTIFY diagnosticsChanged)
    Q_PROPERTY(qint64 diagnosticsReceivedAt READ diagnosticsReceivedAt NOTIFY diagnosticsChanged)
    Q_PROPERTY(qint64 snapshotReceivedAt READ snapshotReceivedAt NOTIFY snapshotChanged)
    Q_PROPERTY(QVariantMap connectionRequest READ connectionRequest NOTIFY connectionRequestChanged)
    Q_PROPERTY(QString connectionError READ connectionError NOTIFY connectionRequestChanged)
    Q_PROPERTY(QString connectionErrorProfile READ connectionErrorProfile NOTIFY connectionRequestChanged)
    Q_PROPERTY(QString error READ error NOTIFY errorChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY busyChanged)
    Q_PROPERTY(bool networkBusy READ networkBusy NOTIFY busyChanged)
    Q_PROPERTY(bool online READ online NOTIFY onlineChanged)
    Q_PROPERTY(bool demo READ demo CONSTANT)
    Q_PROPERTY(bool autostart READ autostart NOTIFY autostartChanged)
    Q_PROPERTY(bool trayAvailable READ trayAvailable WRITE setTrayAvailable NOTIFY trayAvailableChanged)
    Q_PROPERTY(QVariantMap vpnCompatibility READ vpnCompatibility NOTIFY vpnCompatibilityChanged)
    Q_PROPERTY(QString vpnCompatibilityError READ vpnCompatibilityError NOTIFY vpnCompatibilityChanged)
    Q_PROPERTY(bool vpnCompatibilityPending READ vpnCompatibilityPending NOTIFY vpnCompatibilityChanged)
    Q_PROPERTY(bool vpnCompatibilityActive READ vpnCompatibilityActive WRITE setVPNCompatibilityActive NOTIFY vpnCompatibilityActiveChanged)
public:
    explicit Bridge(bool demo, QObject *parent = nullptr);
    QVariantMap snapshot() const { return m_snapshot; }
    QVariantList profiles() const { return m_profiles; }
    QVariantList bootProfiles() const { return m_bootProfiles; }
    bool importPreparing() const { return hasRequest(RequestScope::ImportPrepare); }
    bool importCommitting() const { return hasRequest(RequestScope::ImportCommit); }
    bool bootPending() const { return hasRequest(RequestScope::Boot); }
    bool logActionPending() const { return hasRequest(RequestScope::Logs); }
    QString logsError() const { return m_logsError; }
    QVariantMap preview() const { return m_preview; }
    QVariantMap workRequests() const { return m_workRequests; }
    QVariantMap workRoutes() const { return m_workRoutes; }
    QString workRoutesError() const { return m_workRoutesError; }
    bool workRoutesPending() const { return m_workRoutesPending; }
    Q_INVOKABLE void readWorkFiles(const QList<QUrl> &urls);
    Q_INVOKABLE void prepareWorkImport(const QVariantList &files);
    Q_INVOKABLE void connectWorkProfile(const QString &id);
    Q_INVOKABLE void disconnectWorkProfile(const QString &id);
    Q_INVOKABLE void refreshWorkRoutes();
    Q_INVOKABLE void setWorkRoute(const QString &cidr, const QString &target);
    Q_INVOKABLE void removeWorkRoute(const QString &id);
    Q_INVOKABLE void setWorkDNS(const QString &domain, const QString &target);
    Q_INVOKABLE void removeWorkDNS(const QString &id);
    QVariantList profileLogs() const { return m_profileLogs; }
    QString logPreviousCursor() const { return m_logPreviousCursor; }
    QString logCursor() const { return m_logCursor; }
    QString diagnostics() const { return m_diagnostics; }
    QVariantMap diagnosticData() const { return m_diagnosticData; }
    QString diagnosticsError() const { return m_diagnosticsError; }
    bool diagnosticsPending() const { return m_diagnosticsPending; }
    qint64 diagnosticsReceivedAt() const { return m_diagnosticsReceivedAt; }
    qint64 snapshotReceivedAt() const { return m_snapshotReceivedAt; }
    QVariantMap connectionRequest() const { return m_connectionRequest; }
    QString connectionError() const { return m_connectionError; }
    QString connectionErrorProfile() const { return m_connectionErrorProfile; }
    QString error() const { return m_error; }
    bool busy() const { return hasRequest(RequestScope::Foreground); }
    bool networkBusy() const { return m_networkPending > 0; }
    bool online() const { return m_online; }
    bool demo() const { return m_demo; }
    bool autostart() const;
    bool trayAvailable() const { return m_trayAvailable; }
    void setTrayAvailable(bool available);
    QVariantMap vpnCompatibility() const { return m_vpnCompatibility; }
    QString vpnCompatibilityError() const { return m_vpnCompatibilityError; }
    bool vpnCompatibilityPending() const { return m_compatibilityPending; }
    bool vpnCompatibilityActive() const { return m_compatibilityActive; }
    void setVPNCompatibilityActive(bool active);
    Q_INVOKABLE void refreshVPNCompatibility();
    Q_INVOKABLE void clearError();
    Q_INVOKABLE void prepareImport(const QString &source, const QString &kind, const QString &name);
    Q_INVOKABLE void cancelImport();
    Q_INVOKABLE void commitImport(const QVariantMap &icons);
    Q_INVOKABLE void updateProfile(const QString &id, const QString &name, const QString &iconId);
    Q_INVOKABLE void setProfileDebug(const QString &id, bool enabled);
    Q_INVOKABLE void loadProfileLogs(const QString &id, bool reset = false);
    Q_INVOKABLE void loadOlderProfileLogs(const QString &id);
    Q_INVOKABLE void clearProfileLogs(const QString &id);
    Q_INVOKABLE void copyProfileLogs();
    Q_INVOKABLE void connectProfile(const QString &id);
    Q_INVOKABLE void disconnectProfile();
    Q_INVOKABLE void takeControl();
    Q_INVOKABLE void removeProfile(const QString &id);
    Q_INVOKABLE void refreshSubscriptions();
    Q_INVOKABLE void removeSubscription(const QString &id);
    Q_INVOKABLE void setBootProfile(const QString &id);
    Q_INVOKABLE void getDiagnostics(const QString &profileId = {});
    Q_INVOKABLE void setVPNBinding(const QVariantMap &binding);
    Q_INVOKABLE void setAutostart(bool enabled);
    Q_INVOKABLE void readImportFile(const QUrl &url);
    Q_INVOKABLE void copyDiagnostics();
    Q_INVOKABLE void quitInterface();
    Q_INVOKABLE void setDemoState(const QString &state);
public slots:
    void refresh();
    void Raise();
signals:
    void snapshotChanged();
    void profilesChanged();
    void bootProfilesChanged();
    void requestStateChanged();
    void logsStateChanged();
    void previewChanged();
    void workRequestsChanged();
    void workRoutesChanged();
    void workFilesRead();
    void diagnosticsChanged();
    void connectionRequestChanged();
    void profileLogsChanged();
    void profileLogsAboutToChange();
    void errorChanged();
    void busyChanged();
    void onlineChanged();
    void autostartChanged();
    void trayAvailableChanged();
    void vpnCompatibilityChanged();
    void vpnCompatibilityActiveChanged();
    void raiseRequested();
    void operationDone(const QString &operation, const QVariantMap &result);
    void importFileRead(const QString &text);
private slots:
    void serviceChanged(const QString &name, const QString &oldOwner, const QString &newOwner);
private:
    using Reply = std::function<void(const QVariantMap &)>;
    enum class RequestScope { Foreground, Background, ImportPrepare, ImportCommit, Boot, Logs };
    bool hasRequest(RequestScope scope) const;
    quint64 beginRequest(RequestScope scope);
    void endRequest(quint64 token);
    void retireRequests(RequestScope scope);
    void call(const QString &method, const QVariantList &args = {}, Reply reply = {},
              RequestScope scope = RequestScope::Foreground, std::function<bool()> current = {}, Reply failed = {});
    void fetchProfileLogs(const QString &id, const QString &cursor, bool replace, bool older, bool manual);
    void mutate(const QString &method, const QVariantList &args = {});
    void setError(const QString &message);
    void setOnline(bool available);
    void demoCall(const QString &method, const QVariantList &args, Reply reply);
    void updateDemo(const QString &state, const QString &id = {});
    void invalidateVPNCompatibility();
    void requestConnection(const QString &action, const QString &profileId);
    void requestWorkConnection(const QString &action, const QString &profileId);
    void workRouteCall(const QString &method, const QVariantList &args = {});
    void acceptSnapshot(const QVariantMap &snapshot);
    void finishDiagnostics(const QVariantMap &data, const QString &error);
    QString autostartPath() const;
    QVariantMap m_snapshot, m_preview;
    QString m_importKind = "text";
    QVariantMap m_workRequests, m_workRoutes;
    QString m_workRoutesError;
    bool m_workRoutesPending = false;
    quint64 m_workRoutesGeneration = 0;
    QVariantList m_profiles, m_bootProfiles, m_profileLogs;
    QString m_logsError;
    QString m_logProfile, m_logCursor, m_logPreviousCursor;
    QVariantMap m_demoDraft, m_demoLogs;
    quint64 m_importGeneration = 0, m_logGeneration = 0;
    bool m_logsPending = false;
    QString m_diagnostics, m_error;
    QVariantMap m_diagnosticData, m_connectionRequest;
    QVariantMap m_unconfirmedRequest;
    QString m_diagnosticsError, m_diagnosticsProfile, m_connectionError, m_connectionErrorProfile, m_acceptedOperationId;
    qint64 m_diagnosticsReceivedAt = 0, m_snapshotReceivedAt = 0;
    quint64 m_diagnosticsGeneration = 0;
    bool m_diagnosticsPending = false, m_disconnectQueued = false;
    QDBusConnection m_bus;
    QDBusServiceWatcher *m_watcher = nullptr;
    QHash<quint64, RequestScope> m_requests;
    quint64 m_nextRequest = 0;
    int m_networkPending = 0;
    bool m_demo = false, m_online = false, m_trayAvailable = false;
    bool m_refreshing = false, m_refreshAgain = false, m_demoAutostart = false;
    QVariantMap m_vpnCompatibility;
    QString m_vpnCompatibilityError, m_demoCompatibilityState, m_compatibilitySnapshotKey;
    QTimer m_compatibilityTimer;
    quint64 m_compatibilityGeneration = 0;
    quint64 m_serviceGeneration = 0;
    bool m_compatibilityActive = false, m_compatibilityPending = false, m_compatibilityAgain = false;
};
