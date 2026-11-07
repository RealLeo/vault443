#include "servicetransport.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QPointer>
#include <QTimer>
#include <functional>
#include <chrono>

#ifdef Q_OS_WIN
#include <QLocalSocket>
#include <windows.h>
#include <shellapi.h>
#include <aclapi.h>
#else
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusServiceWatcher>
#endif

class ServiceChannel final : public QObject {
    Q_OBJECT
public:
    ServiceChannel();
    void dispatch(const ServiceMessage &message, int timeout, ServiceCallWatcher *watcher);
    static ServiceMessage failure(const QString &name, const QString &message) {
        ServiceMessage reply; reply.m_errorName = name; reply.m_errorMessage = message; return reply;
    }
signals:
    void changed();
    void ownerChanged(const QString &, const QString &, const QString &);
private:
#ifdef Q_OS_WIN
    struct Pending { QPointer<ServiceCallWatcher> watcher; QByteArray frame; QTimer *timer; bool sent = false; };
    void reconnect();
    void flush();
    void read();
    void disconnected();
    void complete(quint64 id, const ServiceMessage &reply);
    void elevate(const ServiceMessage &message, int timeout, ServiceCallWatcher *watcher);
    QLocalSocket m_socket;
    QTimer m_retry;
    QByteArray m_buffer;
    QHash<quint64, Pending> m_pending;
    quint64 m_nextID = 0;
    bool m_authenticated = false;
#else
    QDBusConnection m_bus = QDBusConnection::systemBus();
#endif
};

ServiceMessage ServiceMessage::createMethodCall(const QString &service, const QString &object,
                                               const QString &interfaceName, const QString &method) {
    ServiceMessage message;
    message.m_service = service; message.m_object = object; message.m_interface = interfaceName; message.m_method = method;
    return message;
}
ServiceMessage ServiceMessage::fromJsonRpcError(int code, const QString &message) {
    ServiceMessage reply;
    reply.m_errorName = code == -32601 ? "UnknownMethod" : "ServiceError";
    reply.m_errorMessage = message;
    // Only the service's explicit enrollment rejection offers UAC. Session
    // changes, generic access denial and pipe failures must not.
    if (code == -32001 && message == "Access denied: this user has not been granted Vault 443 access")
        reply.m_errorName = "EnrollmentRequired";
    return reply;
}
ServiceConnection::ServiceConnection(const QString &) {}
ServiceConnection ServiceConnection::systemBus() {
    ServiceConnection connection; connection.m_channel = QSharedPointer<ServiceChannel>::create(); return connection;
}
ServiceCall ServiceConnection::asyncCall(const ServiceMessage &message, int timeout) const {
    ServiceCall call; call.channel = m_channel; call.message = message; call.timeout = timeout; return call;
}
bool ServiceConnection::connect(const QString &, const QString &, const QString &, const QString &signal,
                                QObject *receiver, const char *slot) const {
    if (!m_channel || signal != "Changed") return false;
    QByteArray method(slot);
    if (!method.isEmpty() && method.at(0) >= '0' && method.at(0) <= '2') method.remove(0, 1);
    method = method.left(method.indexOf('('));
    QObject::connect(m_channel.data(), &ServiceChannel::changed, receiver, [receiver, method] {
        QMetaObject::invokeMethod(receiver, method.constData(), Qt::QueuedConnection);
    });
    return true;
}
ServiceCallWatcher::ServiceCallWatcher(const ServiceCall &call, QObject *parent) : QObject(parent) {
    const QPointer<ServiceCallWatcher> self(this);
    QTimer::singleShot(0, this, [self, call] {
        if (!self) return;
        if (call.channel) call.channel->dispatch(call.message, call.timeout, self);
        else self->deliver(ServiceChannel::failure("ServiceUnknown", "System service unavailable"));
    });
}
void ServiceCallWatcher::deliver(const ServiceMessage &reply) { m_reply = reply; emit finished(this); }
ServiceWatcher::ServiceWatcher(const QString &, const ServiceConnection &connection, WatchMode, QObject *parent)
    : QObject(parent) {
    if (connection.m_channel)
        QObject::connect(connection.m_channel.data(), &ServiceChannel::ownerChanged, this, &ServiceWatcher::serviceOwnerChanged);
}

#ifndef Q_OS_WIN
ServiceChannel::ServiceChannel() {
    auto *watcher = new QDBusServiceWatcher("org.vault443.Service1", m_bus, QDBusServiceWatcher::WatchForOwnerChange, this);
    connect(watcher, &QDBusServiceWatcher::serviceOwnerChanged, this, &ServiceChannel::ownerChanged);
    m_bus.connect("org.vault443.Service1", "/org/vault443/Service1", "org.vault443.Service1", "Changed", this, SIGNAL(changed()));
}
void ServiceChannel::dispatch(const ServiceMessage &message, int timeout, ServiceCallWatcher *receiver) {
    auto call = QDBusMessage::createMethodCall(message.m_service, message.m_object, message.m_interface, message.m_method);
    call.setArguments(message.m_arguments);
    auto *watcher = new QDBusPendingCallWatcher(m_bus.asyncCall(call, timeout), this);
    const QPointer<ServiceCallWatcher> target(receiver);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [watcher, target] {
        const auto answer = watcher->reply(); watcher->deleteLater();
        if (!target) return;
        ServiceMessage reply;
        reply.m_arguments = answer.arguments();
        if (answer.type() == QDBusMessage::ErrorMessage) {
            reply.m_errorName = answer.errorName(); reply.m_errorMessage = answer.errorMessage();
        }
        target->deliver(reply);
    });
}
bool ServiceConnection::administratorEligible() { return false; }
QString ServiceConnection::instanceName() { return {}; }
#else
namespace {
bool systemPipePeer(qintptr descriptor) {
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR security = nullptr;
    if (GetSecurityInfo(reinterpret_cast<HANDLE>(descriptor), SE_KERNEL_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &owner, nullptr, &acl, nullptr, &security) != ERROR_SUCCESS) return false;
    bool valid = owner && IsWellKnownSid(owner, WinLocalSystemSid) && acl;
    for (DWORD i = 0; valid && i < acl->AceCount; ++i) {
        void *entry = nullptr;
        if (!GetAce(acl, i, &entry)) { valid = false; break; }
        const auto *ace = static_cast<ACCESS_ALLOWED_ACE *>(entry);
        if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        const auto sid = const_cast<DWORD *>(&ace->SidStart);
        const bool trusted = IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid);
        if (!trusted && (ace->Mask & (GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER | FILE_CREATE_PIPE_INSTANCE))) valid = false;
    }
    LocalFree(security); return valid;
}
QByteArray tokenData(TOKEN_INFORMATION_CLASS kind) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD size = 0; GetTokenInformation(token, kind, nullptr, 0, &size);
    QByteArray storage(static_cast<qsizetype>(size), '\0');
    if (!GetTokenInformation(token, kind, storage.data(), size, &size)) storage.clear();
    CloseHandle(token); return storage;
}
}
bool ServiceConnection::administratorEligible() {
    // This is permission to request UAC, not an administrator assertion. A
    // standard console user can supply a separate administrator's credentials;
    // the service still validates the elevated helper's Windows token.
    DWORD session = 0;
    return !tokenData(TokenUser).isEmpty()
        && ProcessIdToSessionId(GetCurrentProcessId(), &session)
        && session == WTSGetActiveConsoleSessionId();
}
QString ServiceConnection::instanceName() {
    const auto storage = tokenData(TokenUser); if (storage.isEmpty()) return {};
    const auto *user = reinterpret_cast<const TOKEN_USER *>(storage.constData());
    QByteArray sid(reinterpret_cast<const char *>(user->User.Sid), GetLengthSid(user->User.Sid));
    DWORD session = 0; if (!ProcessIdToSessionId(GetCurrentProcessId(), &session)) return {};
    return "Vault443.Client." + QCryptographicHash::hash(sid, QCryptographicHash::Sha256).toHex().left(24) + "." + QString::number(session);
}
ServiceChannel::ServiceChannel() {
    m_retry.setInterval(1000);
    connect(&m_retry, &QTimer::timeout, this, &ServiceChannel::reconnect);
    connect(&m_socket, &QLocalSocket::readyRead, this, &ServiceChannel::read);
    connect(&m_socket, &QLocalSocket::disconnected, this, &ServiceChannel::disconnected);
    connect(&m_socket, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) { disconnected(); });
    m_retry.start(); QTimer::singleShot(0, this, &ServiceChannel::reconnect);
}
void ServiceChannel::reconnect() {
    if (m_socket.state() != QLocalSocket::UnconnectedState) return;
    // FILE_GENERIC_WRITE contains FILE_CREATE_PIPE_INSTANCE. Open a client
    // handle with individual rights so the service can deny server creation.
    HANDLE handle = CreateFileW(L"\\\\.\\pipe\\Vault443.Service1", 0x0012019b,
        0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return;
    if (!systemPipePeer(reinterpret_cast<qintptr>(handle))) { CloseHandle(handle); return; }
    if (!m_socket.setSocketDescriptor(reinterpret_cast<qintptr>(handle), QLocalSocket::ConnectedState, QIODevice::ReadWrite)) { CloseHandle(handle); return; }
    m_authenticated = true; emit ownerChanged("org.vault443.Service1", {}, "windows-service"); flush();
}
void ServiceChannel::flush() {
    if (!m_authenticated) return;
    for (auto it = m_pending.begin(); it != m_pending.end(); ++it)
        if (!it->sent) { m_socket.write(it->frame); it->sent = true; }
}
void ServiceChannel::dispatch(const ServiceMessage &message, int timeout, ServiceCallWatcher *watcher) {
    if (message.m_method == "SetBootProfile" || message.m_method == "SetVPNBinding" || message.m_method == "GrantConsoleOperator") { elevate(message, timeout, watcher); return; }
    if (m_pending.size() >= 64) { watcher->deliver(failure("Busy", "Too many pending service requests")); return; }
    const auto id = ++m_nextID;
    QJsonObject request{{"jsonrpc", "2.0"}, {"id", static_cast<qint64>(id)}, {"method", message.m_method}, {"params", QJsonArray::fromVariantList(message.m_arguments)}};
    auto frame = QJsonDocument(request).toJson(QJsonDocument::Compact) + '\n';
    if (frame.size() > 4 * 1024 * 1024) { watcher->deliver(failure("InvalidParameters", "Service request is too large")); return; }
    auto *timer = new QTimer(this); timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, this, [this, id] { complete(id, failure("NoReply", "The system service did not respond")); });
    m_pending.insert(id, Pending{watcher, frame, timer}); timer->start(timeout); reconnect(); flush();
}
void ServiceChannel::complete(quint64 id, const ServiceMessage &reply) {
    const auto it = m_pending.find(id); if (it == m_pending.end()) return;
    const auto pending = it.value(); m_pending.erase(it); pending.timer->stop(); pending.timer->deleteLater();
    if (pending.watcher) pending.watcher->deliver(reply);
}
void ServiceChannel::read() {
    m_buffer += m_socket.readAll();
    if (m_buffer.size() > 4 * 1024 * 1024) { m_socket.abort(); return; }
    for (;;) {
        const auto end = m_buffer.indexOf('\n'); if (end < 0) return;
        const auto frame = m_buffer.left(end); m_buffer.remove(0, end + 1);
        QJsonParseError parse; const auto json = QJsonDocument::fromJson(frame, &parse);
        if (parse.error != QJsonParseError::NoError || !json.isObject()) { m_socket.abort(); return; }
        const auto object = json.object();
        if (object.value("jsonrpc") != "2.0") { m_socket.abort(); return; }
        if (!object.contains("id")) { if (object.value("method") == "Changed") emit changed(); continue; }
        const auto id = object.value("id").toVariant().toULongLong(); ServiceMessage reply;
        if (object.contains("error")) {
            const auto error = object.value("error").toObject();
            reply = ServiceMessage::fromJsonRpcError(error.value("code").toInt(), error.value("message").toString());
        } else {
            const auto result = object.value("result");
            if (!result.isObject() && !result.isArray()) { complete(id, failure("InvalidResponse", "Invalid service response")); continue; }
            reply.m_arguments = {QString::fromUtf8((result.isObject() ? QJsonDocument(result.toObject()) : QJsonDocument(result.toArray())).toJson(QJsonDocument::Compact))};
        }
        complete(id, reply);
    }
}
void ServiceChannel::disconnected() {
    const bool wasAuthenticated = m_authenticated; m_authenticated = false; m_buffer.clear();
    if (wasAuthenticated) emit ownerChanged("org.vault443.Service1", "windows-service", {});
    const auto ids = m_pending.keys(); for (auto id : ids) complete(id, failure("Disconnected", "System service unavailable"));
}
void ServiceChannel::elevate(const ServiceMessage &message, int timeout, ServiceCallWatcher *watcher) {
    const auto request = QJsonDocument(QJsonObject{{"method", message.m_method}, {"params", QJsonArray::fromVariantList(message.m_arguments)}}).toJson(QJsonDocument::Compact).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    const auto executable = QDir::toNativeSeparators(QCoreApplication::applicationDirPath() + "/vault443-access.exe").toStdWString();
    const auto parameters = (message.m_method == "GrantConsoleOperator"
        ? QStringLiteral("--grant-console")
        : QString("--request %1").arg(QString::fromLatin1(request))).toStdWString();
    SHELLEXECUTEINFOW info{}; info.cbSize = sizeof(info); info.fMask = SEE_MASK_NOCLOSEPROCESS; info.lpVerb = L"runas";
    info.lpFile = executable.c_str(); info.lpParameters = parameters.c_str(); info.nShow = SW_HIDE;
    if (!ShellExecuteExW(&info)) {
        const bool cancelled = GetLastError() == ERROR_CANCELLED;
        watcher->deliver(failure(cancelled ? "AccessCancelled" : "AccessDenied", cancelled ? "Administrator approval was cancelled" : "Could not start the administrative helper")); return;
    }
    auto *timer = new QTimer(this); timer->setInterval(50); const QPointer<ServiceCallWatcher> target(watcher);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout);
    connect(timer, &QTimer::timeout, this, [timer, target, handle = info.hProcess, deadline] {
        const bool finished = WaitForSingleObject(handle, 0) == WAIT_OBJECT_0;
        if (!finished && std::chrono::steady_clock::now() < deadline) return;
        DWORD code = 1; if (finished) GetExitCodeProcess(handle, &code); CloseHandle(handle); timer->stop(); timer->deleteLater();
        if (!target) return;
        if (!finished) target->deliver(ServiceChannel::failure("NoReply", "Administrative action is still pending; refresh the service state"));
        else if (code) target->deliver(ServiceChannel::failure("AccessDenied", "The administrative action failed"));
        else target->deliver(ServiceMessage{});
    }); timer->start();
}
#endif

#include "servicetransport.moc"
