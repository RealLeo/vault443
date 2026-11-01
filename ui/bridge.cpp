#include "bridge.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QCryptographicHash>
#include <QDBusConnectionInterface>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QUrl>
#include <QUuid>

namespace {
constexpr auto Service = "org.vault443.Service1";
constexpr auto Object = "/org/vault443/Service1";
constexpr auto Interface = "org.vault443.Service1";
bool isWorkID(const QString &id) {
    return id.startsWith("ovpn-") || id.startsWith("wg-") || id.startsWith("awg-");
}
QVariantMap defaultSnapshot() {
    return {{"profiles", QVariantList{}}, {"workProfiles", QVariantList{}}, {"subscriptions", QVariantList{}},
            {"runtime", QVariantMap{{"state", "disconnected"}, {"message", ""}, {"rxBytes", 0}, {"txBytes", 0}}},
            {"traffic", QVariantMap{{"valid", false}}},
            {"activeProfileId", ""}, {"bootProfileId", ""}, {"busyByOtherUser", false}, {"canAdmin", false}};
}
}

Bridge::Bridge(bool demo, QObject *parent)
    : QObject(parent), m_snapshot(defaultSnapshot()), m_bus(demo ? QDBusConnection(QString()) : QDBusConnection::systemBus()), m_demo(demo) {
    connect(this, &Bridge::snapshotChanged, this, [this] {
        QVariantList bootProfiles{QVariantMap{{"id", ""}, {"name", ""}}};
        for (const auto &value : m_snapshot.value("profiles").toList()) {
            const auto profile = value.toMap();
            bootProfiles.append(QVariantMap{{"id", profile.value("id")}, {"name", profile.value("name")}});
        }
        if (m_bootProfiles != bootProfiles) { m_bootProfiles = bootProfiles; emit bootProfilesChanged(); }
        auto profiles = m_snapshot.value("profiles").toList();
        for (auto &value : profiles) {
            auto profile = value.toMap();
            if (profile.value("kind").toString().isEmpty()) profile["kind"] = "vless";
            if (!profile.value("source").toMap().isEmpty()) profile["sourceKind"] = "outline";
            profile.remove("source"); // Source polling must not recycle cards.
            value = profile;
        }
        // Runtime stages change independently of the library. Replacing a
        // QVariantList model on each stage recycled visible cards and lost the
        // scroll/focus while another work connection was being clicked.
        for (const auto &value : m_snapshot.value("workProfiles").toList()) {
            auto profile = value.toMap();
            profile.remove("runtime"); profile.remove("operation"); profile.remove("lastFailure");
            profiles.append(profile);
        }
        if (profiles != m_profiles) { m_profiles = profiles; emit profilesChanged(); }
        const auto key = m_snapshot.value("activeProfileId").toString() + ":"
            + m_snapshot.value("runtime").toMap().value("state").toString() + ":"
            + QString::number(m_snapshot.value("busyByOtherUser").toBool());
        if (key != m_compatibilitySnapshotKey) { m_compatibilitySnapshotKey = key; invalidateVPNCompatibility(); }
    });
    m_compatibilityTimer.setInterval(5000);
    connect(&m_compatibilityTimer, &QTimer::timeout, this, &Bridge::refreshVPNCompatibility);
    connect(this, &Bridge::onlineChanged, this, &Bridge::invalidateVPNCompatibility);
    if (m_demo) {
        m_snapshot["profiles"] = QVariantList{
            QVariantMap{{"iconId","antenna"},{"debugLogging",false},{"id","demo-main"},{"name",tr("Primary")},{"server","vpn.example.net:443"},{"transport","tcp"},{"security","reality"}},
            QVariantMap{{"iconId","dish"},{"debugLogging",false},{"id","demo-backup"},{"name",tr("Backup")},{"server","backup.example.net:443"},{"transport","ws"},{"security","tls"}},
            QVariantMap{{"iconId","globe"},{"debugLogging",false},{"id","demo-work"},{"name",tr("Work")},{"server","work.example.net:443"},{"transport","grpc"},{"security","tls"}}};
        m_snapshot["activeProfileId"] = "demo-main";
        m_snapshot["bootProfileId"] = "demo-main";
        m_snapshot["canAdmin"] = true;
        m_snapshot["runtime"] = QVariantMap{{"state","connected"},{"message",""},{"connectedAt", QDateTime::currentDateTimeUtc().addSecs(-1458).toString(Qt::ISODate)}, {"rxBytes",128*1024*1024},{"txBytes",24*1024*1024},{"guardArmed",true},{"externalVpns",QVariantList{}}};
        m_snapshot["traffic"] = QVariantMap{{"sessionId", "demo-session"}, {"startedAt", QDateTime::currentMSecsSinceEpoch()-1458000},
            {"durationSeconds", 1458}, {"downloadBytes", 128*1024*1024}, {"uploadBytes", 24*1024*1024},
            {"downloadBytesPerSecond", 1.25*1024*1024}, {"uploadBytesPerSecond", 320*1024},
            {"measuredAt", QDateTime::currentMSecsSinceEpoch()}, {"valid", true}};
        m_demoAutostart = true;
        emit snapshotChanged();
        m_snapshotReceivedAt = QDateTime::currentMSecsSinceEpoch();
        setOnline(true);
        return;
    }
    m_watcher = new QDBusServiceWatcher(Service, m_bus, QDBusServiceWatcher::WatchForOwnerChange, this);
    connect(m_watcher, &QDBusServiceWatcher::serviceOwnerChanged, this, &Bridge::serviceChanged);
    m_bus.connect(Service, Object, Interface, "Changed", this, SLOT(refresh()));
    QTimer::singleShot(0, this, &Bridge::refresh);
    auto *snapshotTimer = new QTimer(this);
    snapshotTimer->setInterval(5000);
    connect(snapshotTimer, &QTimer::timeout, this, &Bridge::refresh);
    snapshotTimer->start();
}

void Bridge::setError(const QString &message) { m_error = message; emit errorChanged(); }
void Bridge::clearError() { setError({}); }
void Bridge::setOnline(bool available) {
    if (m_online == available) return;
    m_online = available;
    if (!available) {
        m_workRoutes.clear(); m_workRoutesError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable. Routes could not be loaded."));
        emit workRoutesChanged();
    }
    emit onlineChanged();
}
void Bridge::setTrayAvailable(bool available) { if (available != m_trayAvailable) { m_trayAvailable = available; emit trayAvailableChanged(); } }
void Bridge::Raise() { emit raiseRequested(); }

void Bridge::setVPNCompatibilityActive(bool active) {
    if (m_compatibilityActive == active) return;
    m_compatibilityActive = active;
    emit vpnCompatibilityActiveChanged();
    invalidateVPNCompatibility();
    if (active) m_compatibilityTimer.start();
    else m_compatibilityTimer.stop();
}

void Bridge::invalidateVPNCompatibility() {
    ++m_compatibilityGeneration;
    m_vpnCompatibility.clear(); m_vpnCompatibilityError.clear();
    emit vpnCompatibilityChanged();
    if (!m_compatibilityActive) return;
    if (m_compatibilityPending) m_compatibilityAgain = true;
    else QTimer::singleShot(0, this, &Bridge::refreshVPNCompatibility);
}

void Bridge::refreshVPNCompatibility() {
    if (!m_compatibilityActive || m_compatibilityPending) return;
    if (!m_online) {
        m_vpnCompatibility.clear();
        m_vpnCompatibilityError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable. Could not check other VPNs."));
        emit vpnCompatibilityChanged(); return;
    }
    if (m_snapshot.value("busyByOtherUser").toBool()) {
        m_vpnCompatibility = {{"busyByOtherUser", true}, {"items", QVariantList{}}};
        m_vpnCompatibilityError.clear(); emit vpnCompatibilityChanged(); return;
    }
    if (m_demo) {
        m_vpnCompatibilityError.clear();
        QVariantList items;
        if (m_demoCompatibilityState == "error") m_vpnCompatibilityError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Could not verify the tunnel owner. Open diagnostics."));
        else if (m_demoCompatibilityState != "empty") items.append(QVariantMap{
            {"interface", "tun0"}, {"manager", "pritunl"}, {"application", "Pritunl"}, {"source", "automatic"},
            {"active", true}, {"verified", true}, {"fullIPv4", true}, {"fullIPv6", false}});
        m_vpnCompatibility = {{"busyByOtherUser", false}, {"items", items}};
        emit vpnCompatibilityChanged(); return;
    }
    m_compatibilityPending = true; m_compatibilityAgain = false;
    emit vpnCompatibilityChanged();
    const auto generation = m_compatibilityGeneration;
    const auto message = QDBusMessage::createMethodCall(Service, Object, Interface, "GetVPNCompatibility");
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, 5000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, generation] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        m_compatibilityPending = false;
        if (m_compatibilityActive && generation == m_compatibilityGeneration) {
            m_vpnCompatibility.clear(); m_vpnCompatibilityError.clear();
            if (answer.type() == QDBusMessage::ErrorMessage) {
                m_vpnCompatibilityError = answer.errorName().contains("UnknownMethod")
                    ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Update the system service to a version with automatic VPN discovery."))
                    : QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Could not refresh the VPN list. Check the service and diagnostics."));
            } else {
                QJsonParseError error;
                const auto json = QJsonDocument::fromJson(answer.arguments().value(0).toString().toUtf8(), &error);
                if (error.error == QJsonParseError::NoError && json.isObject() && json.object().value("items").isArray())
                    m_vpnCompatibility = json.object().toVariantMap();
                else m_vpnCompatibilityError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service returned an invalid VPN list."));
            }
        }
        emit vpnCompatibilityChanged();
        if (m_compatibilityAgain) { m_compatibilityAgain = false; QTimer::singleShot(0, this, &Bridge::refreshVPNCompatibility); }
    });
}

bool Bridge::hasRequest(RequestScope scope) const {
    for (auto value : m_requests) if (value == scope) return true;
    return false;
}
quint64 Bridge::beginRequest(RequestScope scope) {
    if (scope == RequestScope::Background) return 0;
    const bool wasPending = hasRequest(scope);
    const auto token = ++m_nextRequest;
    m_requests.insert(token, scope);
    if (!wasPending) { if (scope == RequestScope::Foreground) emit busyChanged(); else emit requestStateChanged(); }
    return token;
}
void Bridge::endRequest(quint64 token) {
    if (!m_requests.contains(token)) return;
    const auto scope = m_requests.take(token);
    if (!hasRequest(scope)) { if (scope == RequestScope::Foreground) emit busyChanged(); else emit requestStateChanged(); }
}
void Bridge::retireRequests(RequestScope scope) {
    const auto tokens = m_requests.keys();
    for (auto token : tokens) if (m_requests.value(token) == scope) endRequest(token);
}

void Bridge::call(const QString &method, const QVariantList &args, Reply reply,
                  RequestScope scope, std::function<bool()> current, Reply failed) {
    // Polling and best-effort draft cleanup must never disable unrelated UI.
    const bool background = method.startsWith("Get") || method == "CancelImport" || method == "CancelWorkImport";
    if (background && scope == RequestScope::Foreground) scope = RequestScope::Background;
    const auto token = beginRequest(scope);
    if (m_demo) {
        demoCall(method, args, std::move(reply));
        endRequest(token); return;
    }
    auto message = QDBusMessage::createMethodCall(Service, Object, Interface, method);
    message.setArguments(args);
    const bool networkOperation = method == "Connect" || method == "Disconnect" || method == "TakeControl";
    if (networkOperation) { ++m_networkPending; emit busyChanged(); }
    const auto generation = m_serviceGeneration;
    const int timeout = method.startsWith("Get") ? 3000 : (method == "RefreshSubscriptions" ? 720000 : 60000);
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, timeout), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this,
            [this, watcher, method, token, networkOperation, generation, current = std::move(current), failed = std::move(failed), reply = std::move(reply)]() {
        const auto message = watcher->reply();
        watcher->deleteLater();
        endRequest(token);
        if (networkOperation) { --m_networkPending; emit busyChanged(); }
        if (generation != m_serviceGeneration) return;
        if (current && !current()) {
            // A canceled prepare may still have created a service-side draft.
            if (message.type() != QDBusMessage::ErrorMessage && (method == "PrepareImport" || method == "PrepareWorkImport")) {
                const auto json = QJsonDocument::fromJson(message.arguments().value(0).toString().toUtf8());
                const auto draft = json.object().value("draftId").toString();
                if (!draft.isEmpty()) call(method == "PrepareWorkImport" ? "CancelWorkImport" : "CancelImport", {draft});
            }
            return;
        }
        auto reportError = [this, &method, &failed](const QString &error) {
            const QVariantMap result{{"error", error}};
            if (method == "GetSnapshot") { m_refreshing = false; m_refreshAgain = false; setOnline(false); }
            else if (failed) failed(result);
            else setError(error);
            emit operationDone(method, result);
        };
        if (message.type() == QDBusMessage::ErrorMessage) {
            if (method == "CancelImport" || method == "CancelWorkImport") { emit operationDone(method, {}); return; }
            if (message.errorName().contains("ServiceUnknown") || message.errorName().contains("Disconnected")) setOnline(false);
            reportError(message.errorMessage().isEmpty() ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "System service unavailable")) : message.errorMessage());
            return;
        }
        QVariantMap result;
        if (!message.arguments().isEmpty()) {
            QJsonParseError parseError;
            auto json = QJsonDocument::fromJson(message.arguments().first().toString().toUtf8(), &parseError);
            if (parseError.error != QJsonParseError::NoError || (!json.isObject() && !json.isArray())) {
                reportError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service returned an invalid response"))); return;
            }
            result = json.isObject() ? json.object().toVariantMap() : QVariantMap{{"results", json.array().toVariantList()}};
        }
        if (reply) reply(result);
        emit operationDone(method, result);
    });
}

void Bridge::refresh() {
    if (m_refreshing) { m_refreshAgain = true; return; }
    m_refreshing = true;
    call("GetSnapshot", {}, [this](const QVariantMap &result) {
        acceptSnapshot(result); m_refreshing = false;
        if (m_refreshAgain) { m_refreshAgain = false; QTimer::singleShot(0, this, &Bridge::refresh); }
    });
}

void Bridge::acceptSnapshot(const QVariantMap &snapshot) {
    m_snapshot = snapshot;
    m_snapshotReceivedAt = QDateTime::currentMSecsSinceEpoch();
    const auto operation = snapshot.value("operation").toMap();
    if (!m_unconfirmedRequest.isEmpty()
        && operation.value("action") == m_unconfirmedRequest.value("action")
        && operation.value("profileId").toString() == m_unconfirmedRequest.value("profileId").toString()
        && operation.value("stageStartedAt").toLongLong() >= m_unconfirmedRequest.value("stageStartedAt").toLongLong()) {
        m_connectionError.clear(); m_connectionErrorProfile.clear(); m_unconfirmedRequest.clear();
        emit connectionRequestChanged();
    }
    if (!m_acceptedOperationId.isEmpty() && (operation.value("id").toString() == m_acceptedOperationId
        || (m_connectionRequest.value("action").toString() == "disconnect" && snapshot.value("activeProfileId").toString().isEmpty()))) {
        m_connectionRequest.clear(); m_acceptedOperationId.clear(); emit connectionRequestChanged();
    }
    if (snapshot.value("busyByOtherUser").toBool()) {
        m_connectionRequest.clear(); m_acceptedOperationId.clear(); emit connectionRequestChanged();
    }
    bool workChanged = false;
    for (const auto &value : snapshot.value("workProfiles").toList()) {
        const auto profile = value.toMap(); const auto id = profile.value("id").toString();
        const auto request = m_workRequests.value(id).toMap();
        if (request.isEmpty() || request.value("pending").toBool()) continue;
        const auto op = profile.value("operation").toMap();
        const bool disconnected = request.value("action").toString() == "disconnect"
            && !request.value("id").toString().isEmpty()
            && profile.value("runtime").toMap().value("state").toString() == "disconnected";
        if (disconnected || (!request.value("id").toString().isEmpty() && op.value("id") == request.value("id"))
            || op.value("stageStartedAt").toLongLong() >= request.value("stageStartedAt").toLongLong()) {
            m_workRequests.remove(id); workChanged = true;
        }
    }
    if (snapshot.value("busyByOtherUser").toBool()) { m_workRequests.clear(); m_workRoutes.clear(); emit workRoutesChanged(); workChanged = true; }
    if (workChanged) emit workRequestsChanged();
    setOnline(true); emit snapshotChanged();
}

void Bridge::serviceChanged(const QString &, const QString &, const QString &newOwner) {
    m_cancelSwitchQueued = false; m_cancelSwitchPending = false;
    m_sourceRefreshPending.clear();
    ++m_serviceGeneration;
    const auto pendingTokens = m_requests.keys();
    for (auto token : pendingTokens) endRequest(token);
    ++m_importGeneration;
    m_preview.clear(); emit previewChanged();
    ++m_workRoutesGeneration; m_workRoutesPending = false;
    m_workRequests.clear(); m_workRoutes.clear(); emit workRequestsChanged(); emit workRoutesChanged();
    ++m_diagnosticsGeneration;
    if (m_diagnosticsPending || !m_diagnostics.isEmpty()) finishDiagnostics({}, QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service connection lost. The last received snapshot is shown below.")));
    m_connectionRequest.clear(); m_unconfirmedRequest.clear(); m_acceptedOperationId.clear(); m_disconnectQueued = false;
    m_connectionError.clear(); m_connectionErrorProfile.clear();
    emit connectionRequestChanged();
    ++m_logGeneration; m_logsPending = false;
    m_refreshing = false; m_refreshAgain = false;
    invalidateVPNCompatibility();
    setOnline(false);
    if (!newOwner.isEmpty()) { clearError(); refresh(); }
}

void Bridge::mutate(const QString &method, const QVariantList &args) {
    clearError(); call(method, args, [this](const QVariantMap &) { refresh(); });
}
void Bridge::cancelImport() {
    ++m_importGeneration;
    retireRequests(RequestScope::ImportPrepare);
    retireRequests(RequestScope::ImportCommit);
    const auto draft = m_preview.value("draftId").toString();
    m_preview.clear(); emit previewChanged();
    if (!draft.isEmpty()) call(m_importKind == "work" ? "CancelWorkImport" : "CancelImport", {draft});
}
void Bridge::prepareImport(const QString &source, const QString &kind, const QString &name) {
    const auto text = source.trimmed();
    if (kind == "text" && (text.startsWith("vpn://") || text.contains("[Interface]") || text.startsWith("client\n") || text.startsWith("client\r\n"))) {
        QVariantList files;
        if (text.startsWith("vpn://")) {
            for (const auto &line : text.split('\n', Qt::SkipEmptyParts))
                files.append(QVariantMap{{"name", name.isEmpty() ? tr("Imported connection") : name}, {"content", line.trimmed()}});
        } else files.append(QVariantMap{{"name", name.isEmpty() ? tr("Imported connection") : name}, {"content", source}});
        prepareWorkImport(files);
        return;
    }
    cancelImport(); clearError(); m_importKind = kind;
    const auto generation = m_importGeneration;
    call("PrepareImport", {source, kind, name.trimmed()}, [this, generation](const QVariantMap &result) {
        if (generation != m_importGeneration) {
            const auto draft = result.value("draftId").toString();
            if (!draft.isEmpty()) call("CancelImport", {draft});
            return;
        }
        m_preview = result; emit previewChanged();
    }, RequestScope::ImportPrepare, [this, generation] { return generation == m_importGeneration; });
}
void Bridge::commitImport(const QVariantMap &icons) {
    const auto draft = m_preview.value("draftId").toString();
    if (draft.isEmpty() || importCommitting()) return;
    const auto generation = m_importGeneration;
    clearError();
    call(m_importKind == "work" ? "CommitWorkImport" : "CommitImport", {draft, QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(icons)).toJson(QJsonDocument::Compact))},
         [this, draft](const QVariantMap &) {
        // The service consumed this draft. Forget it before operationDone closes
        // the dialog and its cleanup calls cancelImport(). Keep failed drafts.
        if (m_preview.value("draftId").toString() == draft) {
            ++m_importGeneration;
            m_preview.clear(); emit previewChanged();
        }
        refresh();
    }, RequestScope::ImportCommit, [this, generation] { return generation == m_importGeneration; });
}
void Bridge::updateProfile(const QString &id, const QString &name, const QString &iconId) { mutate(isWorkID(id) ? "UpdateWorkProfile" : "UpdateProfile", {id, name.trimmed(), iconId}); }
void Bridge::setProfileDebug(const QString &id, bool enabled) { mutate(isWorkID(id) ? "SetWorkDebug" : "SetProfileDebug", {id, enabled}); }
void Bridge::loadProfileLogs(const QString &id, bool reset) {
    if (id.isEmpty()) return;
    const bool changed = id != m_logProfile;
    if (!changed && logActionPending()) return;
    if (changed || reset) {
        ++m_logGeneration; m_logsPending = false; retireRequests(RequestScope::Logs);
        m_logProfile = id;
        if (changed) {
            emit profileLogsAboutToChange(); m_profileLogs.clear(); emit profileLogsChanged();
            m_logCursor = "tail"; m_logPreviousCursor.clear(); emit logsStateChanged();
        }
    }
    if (m_logsPending) return;
    fetchProfileLogs(id, (changed || reset) ? "tail" : m_logCursor, changed || reset, false, changed || reset);
}
void Bridge::fetchProfileLogs(const QString &id, const QString &cursor, bool replace, bool older, bool manual) {
    m_logsPending = true;
    const auto generation = m_logGeneration;
    call(isWorkID(id) ? "GetWorkLogs" : "GetProfileLogs", {id, cursor, qint32(200)},
         [this, cursor, replace, older](const QVariantMap &result) {
        m_logsPending = false;
        const auto entries = result.value("entries").toList();
        auto combined = replace ? entries : m_profileLogs;
        if (!replace) { if (older) { combined = entries; combined.append(m_profileLogs); } else combined.append(entries); }
        while (combined.size() > 2000) { if (older) combined.removeLast(); else combined.removeFirst(); }
        if (combined != m_profileLogs) {
            emit profileLogsAboutToChange(); m_profileLogs = combined; emit profileLogsChanged();
        }
        const auto previous = (older || cursor == "tail") ? result.value("previousCursor").toString() : m_logPreviousCursor;
        const auto next = older ? m_logCursor : result.value("nextCursor").toString();
        if (m_logPreviousCursor != previous || m_logCursor != next || !m_logsError.isEmpty()) {
            m_logPreviousCursor = previous; m_logCursor = next; m_logsError.clear(); emit logsStateChanged();
        }
    }, manual ? RequestScope::Logs : RequestScope::Background,
       [this, generation] { return generation == m_logGeneration; },
       [this](const QVariantMap &result) { m_logsPending = false; m_logsError = result.value("error").toString(); emit logsStateChanged(); });
}
void Bridge::loadOlderProfileLogs(const QString &id) {
    if (logActionPending() || id != m_logProfile || m_logPreviousCursor.isEmpty()) return;
    ++m_logGeneration; m_logsPending = false;
    fetchProfileLogs(id, m_logPreviousCursor, false, true, true);
}
void Bridge::clearProfileLogs(const QString &id) {
    if (id.isEmpty() || logActionPending()) return;
    ++m_logGeneration; m_logsPending = false;
    const auto generation = m_logGeneration;
    call(isWorkID(id) ? "ClearWorkLogs" : "ClearProfileLogs", {id}, [this, id](const QVariantMap &) {
        if (id == m_logProfile) {
            emit profileLogsAboutToChange(); m_profileLogs.clear(); emit profileLogsChanged();
            m_logCursor = "tail"; m_logPreviousCursor.clear(); m_logsError.clear(); emit logsStateChanged();
            fetchProfileLogs(id, "tail", true, false, true);
        }
    }, RequestScope::Logs, [this, generation] { return generation == m_logGeneration; },
       [this](const QVariantMap &result) { m_logsError = result.value("error").toString(); emit logsStateChanged(); });
}

void Bridge::copyProfileLogs() {
    QStringList lines;
    for (const auto &value : m_profileLogs) { const auto entry = value.toMap(); lines.append(QString("%1 [%2] %3").arg(entry.value("time").toString(), entry.value("level").toString(), entry.value("message").toString())); }
    QApplication::clipboard()->setText(lines.join('\n'));
}
void Bridge::connectProfile(const QString &id) { requestConnection("connect", id); }
void Bridge::cancelProfileSwitch(const QString &operationId) {
    if (m_networkPending > 0) { m_cancelSwitchQueued = true; return; }
    if (operationId.isEmpty() || m_cancelSwitchPending) return;
    if (m_demo) {
        auto op = m_snapshot.value("operation").toMap(); op["stage"] = "switch_cancelled";
        m_snapshot["operation"] = op; m_snapshot["activeProfileId"] = op.value("previousProfileId");
        m_snapshot["runtime"] = QVariantMap{{"state", "connected"}};
        m_connectionRequest.clear(); emit snapshotChanged(); emit connectionRequestChanged(); return;
    }
    m_cancelSwitchPending = true;
    call("CancelSwitch", {operationId}, [this](const QVariantMap &) {m_cancelSwitchPending=false; refresh();},
         RequestScope::Background, {}, [this, operationId](const QVariantMap &r) {
             m_cancelSwitchPending=false;
             if (m_snapshot.value("operation").toMap().value("id").toString() != operationId || !m_connectionRequest.isEmpty()) return;
             m_connectionError=r.value("error").toString();
             m_connectionErrorProfile=m_snapshot.value("operation").toMap().value("profileId").toString();
             emit connectionRequestChanged(); refresh();
         });
}
void Bridge::disconnectProfile() {
    m_cancelSwitchQueued = false;
    const auto id = m_connectionRequest.value("profileId", m_snapshot.value("activeProfileId")).toString();
    // Keep D-Bus acceptance ordered even if Cancel is clicked before Connect's ACK.
    if (m_networkPending > 0) {
        m_disconnectQueued = true;
        m_connectionRequest = {{"action", "disconnect"}, {"profileId", id}, {"stage", "requested"}, {"stageStartedAt", QDateTime::currentMSecsSinceEpoch()}};
        emit connectionRequestChanged(); return;
    }
    requestConnection("disconnect", id);
}
void Bridge::requestConnection(const QString &action, const QString &profileId) {
    if (m_networkPending > 0 || m_snapshot.value("busyByOtherUser").toBool()) return;
    m_connectionError.clear(); m_connectionErrorProfile.clear(); m_acceptedOperationId.clear();
    m_unconfirmedRequest.clear();
    m_connectionRequest = {{"action", action}, {"profileId", profileId}, {"stage", "requested"}, {"stageStartedAt", QDateTime::currentMSecsSinceEpoch()}};
    if (action == "connect" && !m_snapshot.value("activeProfileId").toString().isEmpty())
        m_connectionRequest["previousProfileId"] = m_snapshot.value("activeProfileId");
    emit connectionRequestChanged();
    const auto method = action == "connect" ? QString("RequestConnect") : QString("RequestDisconnect");
    if (m_demo) {
        demoCall(method, action == "connect" ? QVariantList{profileId} : QVariantList{}, {});
        m_connectionRequest.clear(); emit connectionRequestChanged(); return;
    }
    auto message = QDBusMessage::createMethodCall(Service, Object, Interface, method);
    if (action == "connect") message.setArguments({profileId});
    ++m_networkPending; emit busyChanged();
    const auto generation = m_serviceGeneration;
    const auto requested = m_connectionRequest;
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, 3000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, generation, profileId, method, requested] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        --m_networkPending; emit busyChanged();
        if (generation != m_serviceGeneration) return;
        QVariantMap result;
        if (answer.type() == QDBusMessage::ErrorMessage) {
            if (answer.errorName().contains("ServiceUnknown") || answer.errorName().contains("Disconnected")) setOnline(false);
            if (answer.errorName().contains("UnknownMethod")) m_connectionError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Update the Vault 443 system service to the current release."));
            else if (answer.errorName().contains("NoReply")) {
                m_connectionError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not acknowledge the command within 3 s. Checking its status."));
                m_unconfirmedRequest = requested;
            }
            else m_connectionError = answer.errorMessage().isEmpty() ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable — VPN state unknown.")) : answer.errorMessage();
        } else {
            const auto json = QJsonDocument::fromJson(answer.arguments().value(0).toString().toUtf8());
            result = json.object().toVariantMap();
            m_acceptedOperationId = result.value("operationId").toString();
            if (m_acceptedOperationId.isEmpty()) m_connectionError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not return an operation ID."));
        }
        if (!m_connectionError.isEmpty()) {
            m_connectionErrorProfile = profileId;
            m_connectionRequest.clear(); result["error"] = m_connectionError;
        }
        emit connectionRequestChanged(); emit operationDone(method, result);
        if (m_disconnectQueued) { m_disconnectQueued = false; requestConnection("disconnect", profileId); }
        else if (m_cancelSwitchQueued) { m_cancelSwitchQueued=false; if (m_connectionError.isEmpty()) cancelProfileSwitch(m_acceptedOperationId); }
        refresh();
    });
}
void Bridge::takeControl() { mutate("TakeControl"); }
void Bridge::removeProfile(const QString &id) { mutate(isWorkID(id) ? "RemoveWorkProfile" : "RemoveProfile", {id}); }
void Bridge::refreshSubscriptions() { mutate("RefreshSubscriptions"); }
void Bridge::removeSubscription(const QString &id) { mutate("RemoveSubscription", {id}); }
void Bridge::setBootProfile(const QString &id) {
    if (bootPending()) return;
    clearError();
    call("SetBootProfile", {id}, [this, id](const QVariantMap &) {
        m_snapshot["bootProfileId"] = id; emit snapshotChanged(); refresh();
    }, RequestScope::Boot);
}
void Bridge::setVPNBinding(const QVariantMap &binding) {
    auto data = QJsonDocument(QJsonObject::fromVariantMap(binding)).toJson(QJsonDocument::Compact);
    clearError(); call("SetVPNBinding", {QString::fromUtf8(data)}, [this](const QVariantMap &) { invalidateVPNCompatibility(); refresh(); });
}
void Bridge::getDiagnostics(const QString &profileId) {
    if (m_diagnosticsPending && m_diagnosticsProfile == profileId) return;
    // A different profile supersedes the old request. Its late reply must never
    // appear below the new profile's title; repeated same-profile clicks coalesce.
    if (m_diagnosticsProfile != profileId) { m_diagnosticData.clear(); m_diagnostics.clear(); m_diagnosticsReceivedAt = 0; }
    m_diagnosticsProfile = profileId;
    m_diagnosticsPending = true; m_diagnosticsError.clear(); emit diagnosticsChanged();
    const auto generation = ++m_diagnosticsGeneration;
    if (!m_online) { finishDiagnostics({}, QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable — VPN state unknown."))); return; }
    if (m_demo) {
        QTimer::singleShot(60, this, [this, generation, profileId] {
            if (generation != m_diagnosticsGeneration) return;
            if (m_demoCompatibilityState == "diagnostics-error") { finishDiagnostics({}, QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not respond within 3 s. Showing the last received snapshot."))); return; }
            demoCall(isWorkID(profileId) ? "GetWorkDiagnostics" : "GetDiagnostics", {profileId}, [this](const QVariantMap &result) { finishDiagnostics(result, {}); });
        }); return;
    }
    auto message = QDBusMessage::createMethodCall(Service, Object, Interface, profileId.isEmpty() ? "GetDiagnostics" : (isWorkID(profileId) ? "GetWorkDiagnostics" : "GetProfileDiagnostics"));
    if (!profileId.isEmpty()) message.setArguments({profileId});
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, 3000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, generation] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        if (generation != m_diagnosticsGeneration) return;
        if (answer.type() == QDBusMessage::ErrorMessage) {
            finishDiagnostics({}, answer.errorName().contains("NoReply")
                ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not respond within 3 s. Showing the last received snapshot."))
                : QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Could not load diagnostics. Check that the system service is available."))); return;
        }
        QJsonParseError error;
        const auto json = QJsonDocument::fromJson(answer.arguments().value(0).toString().toUtf8(), &error);
        if (error.error != QJsonParseError::NoError || !json.isObject()) finishDiagnostics({}, QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service returned invalid diagnostics.")));
        else finishDiagnostics(json.object().toVariantMap(), {});
    });
}
void Bridge::finishDiagnostics(const QVariantMap &data, const QString &error) {
    m_diagnosticsPending = false; m_diagnosticsError = error;
    if (!data.isEmpty()) { m_diagnosticData = data; m_diagnosticsReceivedAt = QDateTime::currentMSecsSinceEpoch(); }
    auto report = m_diagnosticData;
    if (report.isEmpty()) report["lastSnapshot"] = m_snapshot;
    report["snapshotReceivedAt"] = m_snapshotReceivedAt;
    report["diagnosticsReceivedAt"] = m_diagnosticsReceivedAt;
    if (!error.isEmpty()) report["diagnosticsError"] = error;
    const auto workError = m_workRequests.value(m_diagnosticsProfile).toMap().value("error").toString();
    if (!workError.isEmpty()) report["requestError"] = workError;
    if (!m_connectionError.isEmpty() && (m_diagnosticsProfile.isEmpty() || m_diagnosticsProfile == m_connectionErrorProfile)) report["requestError"] = m_connectionError;
    m_diagnostics = QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(report)).toJson(QJsonDocument::Indented));
    emit diagnosticsChanged();
}
void Bridge::copyDiagnostics() { QApplication::clipboard()->setText(m_diagnostics); }
void Bridge::quitInterface() { QApplication::quit(); }

QString Bridge::autostartPath() const {
    return QStandardPaths::writableLocation(QStandardPaths::ConfigLocation) + "/autostart/vault443.desktop";
}
bool Bridge::autostart() const {
    if (m_demo) return m_demoAutostart;
    QFile file(autostartPath());
    return file.open(QIODevice::ReadOnly) && !file.readAll().contains("Hidden=true");
}
void Bridge::setAutostart(bool enabled) {
    if (m_demo) { m_demoAutostart = enabled; emit autostartChanged(); return; }
    if (!enabled) {
        if (QFile::exists(autostartPath()) && !QFile::remove(autostartPath())) setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Could not disable interface autostart")));
    } else {
        QDir().mkpath(QFileInfo(autostartPath()).absolutePath());
        QSaveFile file(autostartPath());
        auto executable = QCoreApplication::applicationFilePath();
        executable.replace('\\', "\\\\").replace('"', "\\\"").replace('`', "\\`").replace('$', "\\$").replace('%', "%%");
        auto content = QString("[Desktop Entry]\nType=Application\nName=Vault 443\nExec=\"%1\"\nIcon=vault443\nTerminal=false\nX-GNOME-Autostart-enabled=true\n").arg(executable).toUtf8();
        if (!file.open(QIODevice::WriteOnly) || file.write(content) != content.size() || !file.commit()) setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Could not enable interface autostart")));
    }
    emit autostartChanged();
}

void Bridge::readImportFile(const QUrl &url) {
    if (!url.isLocalFile()) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Select a local text file"))); return; }
    QFile file(url.toLocalFile());
    if (!file.open(QIODevice::ReadOnly) || file.size() > 1024 * 1024) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The file is unavailable or larger than 1 MB"))); return; }
    emit importFileRead(QString::fromUtf8(file.readAll()));
}
void Bridge::updateDemo(const QString &state, const QString &id) {
    auto runtime = m_snapshot.value("runtime").toMap(); runtime["state"] = state;
    runtime["guardArmed"] = state != "disconnected";
    runtime["connectedAt"] = state == "connected" ? QDateTime::currentDateTimeUtc().toString(Qt::ISODate) : "";
    runtime["rxBytes"] = 0; runtime["txBytes"] = 0;
    auto traffic = m_snapshot.value("traffic").toMap();
    traffic["measuredAt"] = QDateTime::currentMSecsSinceEpoch();
    if (state != "connected") { traffic["downloadBytesPerSecond"] = 0; traffic["uploadBytesPerSecond"] = 0; }
    m_snapshot["traffic"] = traffic;
    m_snapshot.remove("operation");
    m_snapshot["runtime"] = runtime; m_snapshot["activeProfileId"] = id; emit snapshotChanged();
}
void Bridge::setDemoState(const QString &state) {
    if (!m_demo) return;
    if (state.startsWith("switch-")) {
        updateDemo("connected", "demo-main");
        const auto candidate = m_snapshot.value("profiles").toList()[1].toMap().value("id");
        const auto stage = state == "switch-failed" ? "switch_failed" : state == "switch-restoring" ? "restoring_previous" : "preparing_switch";
        QVariantMap op{{"id", "demo-switch"}, {"action", "connect"}, {"profileId", candidate}, {"previousProfileId", "demo-main"},
                       {"stage", stage}, {"stageStartedAt", QDateTime::currentMSecsSinceEpoch()}};
        if (state == "switch-failed") op["failure"] = QVariantMap{{"profileId", candidate}, {"code", "switch_failed"}, {"message", "Xray rejected the prepared configuration"}};
        m_snapshot["operation"] = op; emit snapshotChanged(); return;
    }
    if (state == "proxy") {
        auto profiles = m_snapshot.value("profiles").toList();
        auto trojan = profiles[1].toMap(); trojan["kind"] = "trojan"; profiles[1] = trojan;
        auto outline = profiles[2].toMap(); outline["kind"] = "shadowsocks"; outline["transport"] = "outline"; outline["security"] = "shadowsocks";
        outline["source"] = QVariantMap{{"kind","outline"},{"updatedAt",QDateTime::currentSecsSinceEpoch()}, {"usingCached",false}, {"blocked",false}, {"updating",false}};
        profiles[2] = outline; m_snapshot["profiles"] = profiles; emit snapshotChanged(); return;
    }
    if (state == "offline") { setOnline(false); return; }
    if (state == "foreign") { m_snapshot["busyByOtherUser"] = true; m_snapshot["activeProfileId"] = ""; emit snapshotChanged(); return; }
    if (state == "large-traffic") {
        auto traffic = m_snapshot.value("traffic").toMap();
        traffic["downloadBytes"] = QVariant::fromValue<qulonglong>(18446744073709551615ULL);
        traffic["uploadBytes"] = QVariant::fromValue<qulonglong>(1099511627776ULL);
        traffic["downloadBytesPerSecond"] = 9876543210.0; traffic["uploadBytesPerSecond"] = 123456.0;
        traffic["durationSeconds"] = 999*3600 + 59*60 + 59;
        m_snapshot["traffic"] = traffic; emit snapshotChanged(); return;
    }
    if (state == "traffic-unavailable") {
        auto traffic = m_snapshot.value("traffic").toMap(); traffic["valid"] = false;
        m_snapshot["traffic"] = traffic; emit snapshotChanged(); return;
    }
    if (state == "work-vpns") {
        QVariantList work;
        for (int i = 1; i <= 2; ++i) work.append(QVariantMap{{"id", QString("ovpn-demo-%1").arg(i)}, {"name", tr("Office %1").arg(i)},
            {"kind", "openvpn"}, {"iconId", i == 1 ? "shield" : "key"}, {"server", "vpn.example.net"}, {"transport", "udp"}, {"security", "TLS"},
            {"runtime", QVariantMap{{"state", "connected"}, {"stage", "connected"}}}});
        m_snapshot["profiles"] = m_snapshot.value("profiles").toList().mid(0, 1);
        m_snapshot["workProfiles"] = work; emit snapshotChanged(); return;
    }
    if (state == "wireguard-vpns") {
        QVariantList work;
        for (int i = 0; i < 2; ++i) {
            const bool awg = i == 1;
            QVariantList peers{QVariantMap{{"id", "demo-peer"}, {"endpoint", "192.0.2.10:51820"}, {"state", "connected"},
                {"lastHandshakeAt", QDateTime::currentSecsSinceEpoch()-20}, {"allowedIPs", QStringList{"10.72.0.0/16"}}}};
            if (awg) peers.append(QVariantMap{{"id", "demo-peer-unavailable"}, {"endpoint", "[2001:db8::20]:443"}, {"state", "reconnecting"},
                {"lastHandshakeAt", 0}, {"allowedIPs", QStringList{"10.73.0.0/16"}}});
            work.append(QVariantMap{{"id", awg ? "awg-demo-east" : "wg-demo-west"}, {"name", awg ? tr("Office East") : tr("Office West")},
                {"kind", awg ? "amneziawg" : "wireguard"}, {"iconId", awg ? "vault-door" : "shield"}, {"server", "vpn.example.net"}, {"transport", "udp"},
                {"runtime", QVariantMap{{"state", awg ? "partial" : "connected"}, {"stage", awg ? "partial" : "connected"}, {"peers", peers},
                    {"routes", QStringList{"10.72.0.0/16"}}, {"dnsServers", QStringList{"10.72.0.53"}}, {"dnsDomains", QStringList{"corp.example"}}}}});
        }
        m_snapshot["profiles"] = m_snapshot.value("profiles").toList().mid(0, 1);
        m_snapshot["workProfiles"] = work; emit snapshotChanged(); return;
    }
    if (state == "diagnostics-error") { m_demoCompatibilityState = state; return; }
    if (state.startsWith("vpn-")) { m_demoCompatibilityState = state.mid(4); invalidateVPNCompatibility(); return; }
    setOnline(true);
    m_snapshot["busyByOtherUser"] = false;
    if (state == "empty") { m_snapshot["profiles"] = QVariantList{}; updateDemo("disconnected"); }
    else if (state == "log-markup") {
        m_demoLogs["demo-main"] = QVariantList{QVariantMap{{"id","1"},{"time",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)},{"level","warning"},{"message","<b>literal & diagnostic</b>"},{"sessionId","demo-markup"}}};
    }
    else if (state == "log-history") {
        QVariantList entries;
        for (int i = 1; i <= 450; ++i) entries.append(QVariantMap{{"id",QString::number(i)},{"time",QDateTime::currentDateTimeUtc().addSecs(i-450).toString(Qt::ISODate)},{"level","info"},{"message",QString("History entry %1").arg(i)},{"sessionId","demo-history"}});
        m_demoLogs["demo-main"] = entries;
    }
    else if (state == "single") {
        const auto profiles = m_snapshot.value("profiles").toList();
        if (profiles.isEmpty()) return;
        auto profile = profiles.first().toMap();
        profile["name"] = tr("Primary connection — Saint Petersburg, secure backup server");
        m_snapshot["profiles"] = QVariantList{profile}; emit snapshotChanged();
    }
    else if (state == "many") {
        auto profiles = m_snapshot.value("profiles").toList();
        for (int i = 4; i <= 20; ++i) profiles.append(QVariantMap{{"id",QString("demo-%1").arg(i)}, {"name",tr("Profile %1 — additional connection").arg(i)}, {"server","example.net"},{"transport","tcp"},{"security","tls"}});
        m_snapshot["profiles"] = profiles; emit snapshotChanged();
    } else if (state.startsWith("stage-") || state == "retry-wait" || state == "disconnecting") {
        updateDemo(state == "retry-wait" ? "error" : "connecting", "demo-main");
        const auto now = QDateTime::currentMSecsSinceEpoch();
        m_snapshot["operation"] = QVariantMap{{"id", "demo-operation"}, {"profileId", "demo-main"}, {"action", state == "disconnecting" ? "disconnect" : "connect"}, {"stage", state == "retry-wait" ? "retry_wait" : (state == "disconnecting" ? "restoring_network" : state.mid(6))}, {"stageStartedAt", now-2000}, {"attempt", 2}, {"nextRetryAt", now+8000}};
        if (state == "retry-wait") m_snapshot["lastFailure"] = QVariantMap{{"profileId", "demo-main"}, {"time", now-1000}, {"code", "dns_timeout"}, {"message", QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "DNS did not respond: the port 53 request and HTTPS fallback both timed out."))}};
        emit snapshotChanged();
    } else if (state == "disconnected") updateDemo(state);
    else if (state == "connected") updateDemo(state, "demo-main");
    else if (state == "paused_external" || state == "connecting" || state == "reconnecting" || state == "error") updateDemo(state, "demo-main");
}
void Bridge::demoCall(const QString &method, const QVariantList &args, Reply reply) {
    // Demo is strictly in-memory: no service, file import writes or network calls.
    QVariantMap result;
    if (method == "GetSnapshot") result = m_snapshot;
    else if (method == "RequestWorkConnect" || method == "RequestWorkDisconnect") {
        auto work = m_snapshot.value("workProfiles").toList();
        const bool connecting = method == "RequestWorkConnect";
        for (auto &value : work) {
            auto profile = value.toMap();
            if (profile.value("id") != args.value(0)) continue;
            profile["runtime"] = QVariantMap{{"state", connecting ? "connected" : "disconnected"}, {"stage", connecting ? "connected" : "disconnected"}};
            profile["operation"] = QVariantMap{{"id", "demo-work-operation"}, {"profileId", args.value(0)},
                {"action", connecting ? "connect" : "disconnect"}, {"stage", connecting ? "connected" : "disconnected"}, {"stageStartedAt", QDateTime::currentMSecsSinceEpoch()}};
            value = profile;
        }
        m_snapshot["workProfiles"] = work; result["operationId"] = "demo-work-operation"; emit snapshotChanged();
    } else if (method == "PrepareWorkImport") {
        const auto files = QJsonDocument::fromJson(args.value(0).toString().toUtf8()).array();
        QVariantList profiles, errors;
        for (qsizetype i = 0; i < files.size(); ++i) {
            const auto file = files[i].toObject(); const auto content = file.value("content").toString();
            const bool wg = content.contains("[Interface]") && content.contains("[Peer]");
            const bool awg = wg && QRegularExpression("(?m)^\\s*(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5]|HeaderProtectionKey)\\s*=").match(content).hasMatch();
            if (!wg && (!content.contains("client") || !content.contains("remote "))) {
                errors.append(QVariantMap{{"line", i+1}, {"message", tr("Expected a self-contained VPN client configuration.")}}); continue;
            }
            const QString kind = awg ? "amneziawg" : wg ? "wireguard" : "openvpn";
            const auto id = (awg ? "awg-" : wg ? "wg-" : "ovpn-") + QString::fromLatin1(QCryptographicHash::hash(content.toUtf8(), QCryptographicHash::Sha256).toHex().left(24));
            bool duplicate = false;
            for (const auto &existing : m_profiles) if (existing.toMap().value("id").toString() == id) duplicate = true;
            for (const auto &existing : profiles) if (existing.toMap().value("id").toString() == id) duplicate = true;
            profiles.append(QVariantMap{{"id", id}, {"name", file.value("name").toString()}, {"iconId", "shield"}, {"debugLogging", false},
                {"kind", kind}, {"server", "work.example.net"}, {"transport", "udp"}, {"security", wg ? kind : "TLS"}, {"duplicate", duplicate},
                {"runtime", QVariantMap{{"state", "disconnected"}}}});
        }
        result = {{"draftId", QUuid::createUuid().toString(QUuid::WithoutBraces)}, {"profiles", profiles}, {"errors", errors}, {"expiresAt", QDateTime::currentSecsSinceEpoch()+600}};
        m_demoDraft = result; m_demoDraft["kind"] = "work";
    } else if (method == "GetWorkRoutes") {
        auto work = m_snapshot.value("workProfiles").toList(); QVariantList items;
        for (const auto &value : work) {
            const auto p = value.toMap();
            const auto state = p.value("runtime").toMap().value("state").toString();
            if (state != "connected" && state != "partial") continue;
            items.append(QVariantMap{{"cidr", items.isEmpty() ? "192.168.96.0/20" : "10.72.0.0/16"}, {"source", p.value("kind")}, {"target", p.value("id")},
                {"targetName", p.value("name")}, {"interface", QString("v443w%1").arg(items.size())}, {"state", "active"}, {"message", items.isEmpty() ? tr("Work VPN takes priority over the overlapping Docker network.") : QString()}});
        }
        result = {{"items", items}, {"profiles", work}, {"rules", m_workRoutes.value("rules", QVariantList{})}, {"dnsRules", m_workRoutes.value("dnsRules", QVariantList{})}};
    } else if (method == "SetWorkRoute" || method == "SetWorkDNS") {
        const bool dns = method == "SetWorkDNS"; const auto key = dns ? "dnsRules" : "rules";
        auto rules = m_workRoutes.value(key).toList();
        const auto destination = dns ? "domain" : "cidr";
        for (qsizetype i = rules.size(); i-- > 0;) if (rules[i].toMap().value(destination) == args.value(0)) rules.removeAt(i);
        rules.append(QVariantMap{{"id", QUuid::createUuid().toString(QUuid::WithoutBraces)}, {destination, args.value(0)}, {"target", args.value(1)}});
        m_workRoutes[key] = rules;
    } else if (method == "RemoveWorkRoute" || method == "RemoveWorkDNS") {
        const auto key = method == "RemoveWorkDNS" ? "dnsRules" : "rules";
        auto rules = m_workRoutes.value(key).toList();
        for (qsizetype i = rules.size(); i-- > 0;) if (rules[i].toMap().value("id") == args.value(0)) rules.removeAt(i);
        m_workRoutes[key] = rules;
    }
    else if (method == "RequestConnect") {
        m_snapshot["traffic"] = QVariantMap{{"sessionId", QUuid::createUuid().toString(QUuid::WithoutBraces)},
            {"startedAt", QDateTime::currentMSecsSinceEpoch()}, {"durationSeconds", 0},
            {"downloadBytes", 0}, {"uploadBytes", 0}, {"downloadBytesPerSecond", 0}, {"uploadBytesPerSecond", 0}, {"valid", true}};
        updateDemo("connected", args.value(0).toString()); result["operationId"] = "demo-operation";
    }
    else if (method == "RequestDisconnect") { updateDemo("disconnected"); result["operationId"] = "demo-operation"; }
    else if (method == "RequestSourceRefresh") {
        auto profiles = m_snapshot.value("profiles").toList();
        for (auto &value : profiles) { auto p = value.toMap(); if (p.value("id") != args.value(0)) continue;
            auto source = p.value("source").toMap(); source["updatedAt"] = QDateTime::currentSecsSinceEpoch(); source["usingCached"] = false; source["lastError"] = ""; p["source"] = source; value = p; }
        m_snapshot["profiles"] = profiles; emit snapshotChanged(); result["operationId"] = "demo-source";
    }
    else if (method == "SetBootProfile") { m_snapshot["bootProfileId"] = args.value(0); emit snapshotChanged(); }
    else if (method == "UpdateProfile" || method == "SetProfileDebug" || method == "RemoveProfile" || method == "UpdateWorkProfile" || method == "SetWorkDebug" || method == "RemoveWorkProfile") {
        const auto key = isWorkID(args.value(0).toString()) ? "workProfiles" : "profiles";
        auto profiles = m_snapshot.value(key).toList();
        for (qsizetype i = profiles.size(); i-- > 0;) {
            auto profile = profiles[i].toMap();
            if (profile.value("id") != args.value(0)) continue;
            if (method == "RemoveProfile" || method == "RemoveWorkProfile") profiles.removeAt(i);
            else { if (method == "SetProfileDebug" || method == "SetWorkDebug") profile["debugLogging"] = args.value(1); else { profile["name"] = args.value(1); if (method == "UpdateProfile" || method == "UpdateWorkProfile") profile["iconId"] = args.value(2); } profiles[i] = profile; }
        }
        m_snapshot[key] = profiles; emit snapshotChanged();
    } else if (method == "PrepareImport") {
        QVariantList profiles, errors;
        const bool subscription = args.value(1).toString() == "subscription";
        const auto source = subscription ? QString("vless://00000000-0000-4000-8000-000000000021@subscription.example.net:443?security=tls#Subscription A\nvless://00000000-0000-4000-8000-000000000022@backup.example.net:443?security=tls#Subscription B") : args.value(0).toString();
        const auto lines = source.split('\n');
        for (int i = 0; i < lines.size(); ++i) {
            const auto line = lines[i].trimmed(); if (line.isEmpty()) continue;
            const QUrl url(line);
            if (!QStringList{"vless", "trojan", "ss"}.contains(url.scheme()) || url.host().isEmpty()) { errors.append(QVariantMap{{"line",i+1},{"message",QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Expected a vless://, trojan:// or ss:// link"))}}); continue; }
            auto identity = url; identity.setFragment({});
            const auto id = QString::fromLatin1(QCryptographicHash::hash(identity.toEncoded(), QCryptographicHash::Sha256).toHex().left(24));
            bool duplicate = false;
            for (const auto &existing : m_profiles) if (existing.toMap().value("id").toString() == id) duplicate = true;
            for (const auto &existing : profiles) if (existing.toMap().value("id").toString() == id) duplicate = true;
            profiles.append(QVariantMap{{"kind",url.scheme() == "ss" ? "shadowsocks" : url.scheme()},{"iconId","antenna"},{"debugLogging",false},{"id", id}, {"line",i+1}, {"name",url.fragment().isEmpty() ? url.host() : url.fragment()}, {"server",url.host()}, {"transport","tcp"},{"security","tls"},{"duplicate",duplicate}});
        }
        result = {{"profiles",profiles},{"errors",errors}};
        {
            result["draftId"] = QUuid::createUuid().toString(QUuid::WithoutBraces);
            result["expiresAt"] = QDateTime::currentSecsSinceEpoch() + 600;
            m_demoDraft = result; m_demoDraft["kind"] = args.value(1); m_demoDraft["name"] = args.value(2);
        }
    } else if ((method == "CancelImport" || method == "CancelWorkImport")) { if (m_demoDraft.value("draftId") == args.value(0)) m_demoDraft.clear();
    } else if ((method == "CommitImport" || method == "CommitWorkImport")) {
        if (m_demoDraft.value("draftId") != args.value(0) || m_demoDraft.value("expiresAt").toLongLong() < QDateTime::currentSecsSinceEpoch()) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The import preview expired. Check the list again."))); emit operationDone(method, {{"error", m_error}}); return; }
        const auto icons = QJsonDocument::fromJson(args.value(1).toString().toUtf8()).object().toVariantMap();
        const auto profileKey = method == "CommitWorkImport" ? "workProfiles" : "profiles";
        auto current = m_snapshot.value(profileKey).toList();
        for (const auto &value : m_demoDraft.value("profiles").toList()) { auto p = value.toMap(); if (p.value("duplicate").toBool()) continue; p["iconId"] = icons.value(p.value("id").toString(), "antenna"); current.append(p); }
        m_snapshot[profileKey] = current;
        if (m_demoDraft.value("kind").toString() == "subscription") {
            auto subscriptions = m_snapshot.value("subscriptions").toList();
            subscriptions.append(QVariantMap{{"id",QUuid::createUuid().toString(QUuid::WithoutBraces)},{"name",m_demoDraft.value("name")},{"updatedAt",QDateTime::currentDateTimeUtc().toString(Qt::ISODate)}});
            m_snapshot["subscriptions"] = subscriptions;
        }
        m_demoDraft.clear(); emit snapshotChanged();
    } else if (method == "GetProfileLogs" || method == "GetWorkLogs") {
        const auto id = args.value(0).toString();
        if (!m_demoLogs.contains(id)) {
            QVariantList entries;
            const bool wg = id.startsWith("wg-") || id.startsWith("awg-");
            const QStringList messages = method == "GetWorkLogs"
                ? QStringList{tr("Connection requested by the user"), wg ? tr("Creating VPN interface") : tr("Starting OpenVPN"), wg ? tr("Peer handshake verified") : tr("Server certificate verified"), tr("Work routes and DNS configured"), tr("Connection established")}
                : QStringList{tr("Connection requested by the user"),tr("Internet traffic protection enabled"),tr("Starting Xray · REALITY / Vision"),tr("TUN and DNS configured"),tr("Connection established"),tr("Xray: transport ready")};
            for (int i = 0; i < messages.size(); ++i) entries.append(QVariantMap{{"id",QString::number(i+1)},{"time",QDateTime::currentDateTimeUtc().addSecs(-20+i*3).toString(Qt::ISODate)},{"level",i == 5 ? "debug" : "info"},{"message",messages[i]},{"sessionId","demo-session"}});
            m_demoLogs[id] = entries;
        }
        const auto entries = m_demoLogs.value(id).toList();
        const auto cursor = args.value(1).toString();
        const auto limit = args.value(2).toInt();
        int start = cursor.toInt(), end = entries.size();
        if (cursor == "tail") start = qMax(0, end - limit);
        else if (cursor.startsWith("before:")) { end = qMax(0, cursor.mid(7).toInt() - 1); start = qMax(0, end - limit); }
        const auto page = entries.mid(start, qMin(limit, end-start));
        result = {{"entries",page},{"nextCursor",QString::number(start+page.size())},{"previousCursor",start > 0 ? QString("before:%1").arg(start+1) : QString()}};
    } else if ((method == "ClearProfileLogs" || method == "ClearWorkLogs")) { m_demoLogs[args.value(0).toString()] = QVariantList{};
    } else if (method == "GetWorkDiagnostics") {
        for (const auto &value : m_snapshot.value("workProfiles").toList()) {
            const auto profile = value.toMap(); if (profile.value("id") != args.value(0)) continue;
            result = {{"mode", "demo"}, {"networkChanges", false}, {"network", profile.value("runtime")}, {"operation", profile.value("operation")}, {"lastFailure", profile.value("lastFailure")}};
        }
    } else if (method == "GetDiagnostics") result = {{"mode","demo"},{"service","in-memory"},{"networkChanges",false},{"network",m_snapshot.value("runtime")},{"operation",m_snapshot.value("operation")},{"lastFailure",m_snapshot.value("lastFailure")}};
    else if (method == "RemoveSubscription") {
        auto subscriptions = m_snapshot.value("subscriptions").toList();
        for (qsizetype i = subscriptions.size(); i-- > 0;) if (subscriptions[i].toMap().value("id") == args.value(0)) subscriptions.removeAt(i);
        m_snapshot["subscriptions"] = subscriptions; emit snapshotChanged();
    }
    if (reply) reply(result);
    emit operationDone(method, result);
}

void Bridge::readWorkFiles(const QList<QUrl> &urls) {
    if (urls.isEmpty()) return;
    if (urls.size() > 32) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Select at most 32 VPN files at a time."))); return; }
    QVariantList files;
    qint64 total = 0;
    for (const auto &url : urls) {
        QFile file(url.toLocalFile());
        if (!url.isLocalFile() || !QFileInfo(url.toLocalFile()).isFile() || !file.open(QIODevice::ReadOnly) || file.size() > 1024*1024) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "A VPN file is unavailable or larger than 1 MB."))); return; }
        const auto data = file.read(1024*1024 + 1);
        total += data.size();
        if (data.size() > 1024*1024 || total > 8*1024*1024) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The selected VPN files exceed the 8 MB import limit."))); return; }
        files.append(QVariantMap{{"name", QFileInfo(file).completeBaseName()}, {"content", QString::fromUtf8(data)}});
    }
    emit workFilesRead();
    prepareWorkImport(files);
}

void Bridge::prepareWorkImport(const QVariantList &files) {
    cancelImport(); clearError(); m_importKind = "work";
    const auto generation = m_importGeneration;
    const auto data = QJsonDocument(QJsonArray::fromVariantList(files)).toJson(QJsonDocument::Compact);
    if (files.isEmpty() || files.size() > 32 || data.size() > 8*1024*1024) { setError(QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The selected VPN files exceed the 8 MB import limit."))); return; }
    const auto json = QString::fromUtf8(data);
    call("PrepareWorkImport", {json}, [this, generation](const QVariantMap &result) {
        if (generation != m_importGeneration) {
            const auto draft = result.value("draftId").toString();
            if (!draft.isEmpty()) call("CancelWorkImport", {draft});
            return;
        }
        m_preview = result; emit previewChanged();
    }, RequestScope::ImportPrepare, [this, generation] { return generation == m_importGeneration; });
}

void Bridge::connectWorkProfile(const QString &id) { requestWorkConnection("connect", id); }
void Bridge::disconnectWorkProfile(const QString &id) { requestWorkConnection("disconnect", id); }
void Bridge::requestWorkConnection(const QString &action, const QString &id) {
    if (!isWorkID(id) || m_snapshot.value("busyByOtherUser").toBool()) return;
    auto previous = m_workRequests.value(id).toMap();
    if (previous.value("pending").toBool()) {
        if (action == "disconnect") {
            previous["disconnectQueued"] = true; previous["action"] = "disconnect";
            m_workRequests[id] = previous; emit workRequestsChanged();
        }
        return;
    }
    QVariantMap request{{"profileId", id}, {"action", action}, {"stage", "requested"},
                        {"stageStartedAt", QDateTime::currentMSecsSinceEpoch()}, {"pending", true}};
    m_workRequests[id] = request; emit workRequestsChanged();
    const auto method = action == "connect" ? QString("RequestWorkConnect") : QString("RequestWorkDisconnect");
    if (m_demo) {
        demoCall(method, {id}, {});
        m_workRequests.remove(id); emit workRequestsChanged(); return;
    }
    auto message = QDBusMessage::createMethodCall(Service, Object, Interface, method);
    message.setArguments({id});
    const auto generation = m_serviceGeneration;
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, 3000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, id, method, generation, request] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        if (generation != m_serviceGeneration) return;
        const bool disconnectQueued = m_workRequests.value(id).toMap().value("disconnectQueued").toBool();
        auto current = request; current["pending"] = false;
        QVariantMap result;
        if (answer.type() == QDBusMessage::ErrorMessage) {
            current["error"] = answer.errorName().contains("NoReply")
                ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not acknowledge the command within 3 s. Checking its status."))
                : answer.errorMessage().isEmpty() ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable — VPN state unknown.")) : answer.errorMessage();
            current["stage"] = "request_failed"; result["error"] = current.value("error");
        } else {
            const auto json = QJsonDocument::fromJson(answer.arguments().value(0).toString().toUtf8());
            result = json.object().toVariantMap(); current["id"] = result.value("operationId");
            if (current.value("id").toString().isEmpty()) {
                current["error"] = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service did not return an operation ID."));
                current["stage"] = "request_failed"; result["error"] = current.value("error");
            }
        }
        m_workRequests[id] = current; emit workRequestsChanged(); emit operationDone(method, result);
        if (disconnectQueued) requestWorkConnection("disconnect", id);
        refresh();
    });
}

void Bridge::refreshWorkRoutes() { workRouteCall("GetWorkRoutes"); }
void Bridge::setWorkRoute(const QString &cidr, const QString &target) { workRouteCall("SetWorkRoute", {cidr.trimmed(), target}); }
void Bridge::removeWorkRoute(const QString &id) { workRouteCall("RemoveWorkRoute", {id}); }
void Bridge::setWorkDNS(const QString &domain, const QString &target) { workRouteCall("SetWorkDNS", {domain.trimmed(), target}); }
void Bridge::removeWorkDNS(const QString &id) { workRouteCall("RemoveWorkDNS", {id}); }
void Bridge::workRouteCall(const QString &method, const QVariantList &args) {
    if (m_workRoutesPending) return;
    if (!m_online || m_snapshot.value("busyByOtherUser").toBool()) {
        m_workRoutes.clear(); m_workRoutesError = !m_online ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Service unavailable. Routes could not be loaded.")) : QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "In use by another user"));
        emit workRoutesChanged(); return;
    }
    m_workRoutesPending = true; m_workRoutesError.clear(); emit workRoutesChanged();
    if (m_demo) {
        demoCall(method, args, [this, method](const QVariantMap &result) {
            m_workRoutesPending = false;
            if (method == "GetWorkRoutes") m_workRoutes = result;
            emit workRoutesChanged();
            if (method != "GetWorkRoutes") refreshWorkRoutes();
        }); return;
    }
    auto message = QDBusMessage::createMethodCall(Service, Object, Interface, method);
    message.setArguments(args);
    const auto generation = m_workRoutesGeneration;
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(message, 3000), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, method, generation] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        if (generation != m_workRoutesGeneration) return;
        m_workRoutesPending = false;
        if (answer.type() == QDBusMessage::ErrorMessage) {
            m_workRoutesError = answer.errorMessage().isEmpty() ? QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "Routes could not be refreshed. Check the service and try again.")) : answer.errorMessage();
        } else if (method == "GetWorkRoutes") {
            const auto json = QJsonDocument::fromJson(answer.arguments().value(0).toString().toUtf8());
            if (!json.isObject()) m_workRoutesError = QString::fromUtf8(QT_TRANSLATE_NOOP("Bridge", "The service returned an invalid route list."));
            else m_workRoutes = json.object().toVariantMap();
        }
        emit workRoutesChanged();
        if (method != "GetWorkRoutes" && m_workRoutesError.isEmpty()) refreshWorkRoutes();
    });
}

void Bridge::refreshProfileSource(const QString &id) {
    if (id.isEmpty() || m_sourceRefreshPending.contains(id)) return;
    m_sourceRefreshPending.insert(id);
    call("RequestSourceRefresh", {id}, [this,id](const QVariantMap &) {m_sourceRefreshPending.remove(id);refresh();},
         RequestScope::Background, {}, [this,id](const QVariantMap &r) {m_sourceRefreshPending.remove(id);setError(r.value("error").toString());});
}
