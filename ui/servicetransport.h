#pragma once

#include <QObject>
#include <QSharedPointer>
#include <QString>
#include <QVariantList>

class ServiceChannel;
class ServiceCallWatcher;

class ServiceMessage {
public:
    enum MessageType { ReplyMessage, ErrorMessage };
    static ServiceMessage createMethodCall(const QString &service, const QString &object,
                                           const QString &interfaceName, const QString &method);
    static ServiceMessage fromJsonRpcError(int code, const QString &message);
    void setArguments(const QVariantList &arguments) { m_arguments = arguments; }
    QVariantList arguments() const { return m_arguments; }
    MessageType type() const { return m_errorName.isEmpty() ? ReplyMessage : ErrorMessage; }
    QString errorName() const { return m_errorName; }
    QString errorMessage() const { return m_errorMessage; }
private:
    friend class ServiceChannel;
    QString m_service, m_object, m_interface, m_method;
    QVariantList m_arguments;
    QString m_errorName, m_errorMessage;
};

class ServiceCall {
    friend class ServiceConnection;
    friend class ServiceCallWatcher;
    QSharedPointer<ServiceChannel> channel;
    ServiceMessage message;
    int timeout = 3000;
};

class ServiceCallWatcher final : public QObject {
    Q_OBJECT
public:
    explicit ServiceCallWatcher(const ServiceCall &call, QObject *parent = nullptr);
    ServiceMessage reply() const { return m_reply; }
signals:
    void finished(ServiceCallWatcher *watcher);
private:
    friend class ServiceChannel;
    void deliver(const ServiceMessage &reply);
    ServiceMessage m_reply;
};

class ServiceConnection {
public:
    explicit ServiceConnection(const QString & = {});
    static ServiceConnection systemBus();
    ServiceCall asyncCall(const ServiceMessage &message, int timeout) const;
    bool connect(const QString &, const QString &, const QString &, const QString &signal,
                 QObject *receiver, const char *slot) const;
    static bool administratorEligible();
    static QString instanceName();
private:
    friend class ServiceWatcher;
    QSharedPointer<ServiceChannel> m_channel;
};

class ServiceWatcher final : public QObject {
    Q_OBJECT
public:
    enum WatchMode { WatchForOwnerChange };
    ServiceWatcher(const QString &, const ServiceConnection &connection, WatchMode, QObject *parent);
signals:
    void serviceOwnerChanged(const QString &name, const QString &oldOwner, const QString &newOwner);
};
