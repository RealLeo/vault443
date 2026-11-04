#pragma once

#include <QAbstractListModel>
#include <QVariantMap>

// Presentation order only: neither profiles nor connection intent live here.
class ProfileListModel final : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ rowCount NOTIFY countChanged)
public:
    explicit ProfileListModel(bool persistent, QObject *parent = nullptr);
    int rowCount(const QModelIndex &parent = {}) const override;
    QVariant data(const QModelIndex &index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    void reconcile(const QVariantList &profiles);
    QVariantList items() const { return m_rows; }
    Q_INVOKABLE QString idAt(int row) const;
    Q_INVOKABLE int indexOf(const QString &id) const;
    Q_INVOKABLE bool moveBefore(const QString &id, const QString &beforeId);
signals:
    void viewAboutToChange(bool membershipChanged);
    void changed();
    void countChanged();
    void saveFailed();
private:
    bool save(const QStringList &order);
    QStringList m_order;
    QVariantList m_rows;
    bool m_persistent;
};
