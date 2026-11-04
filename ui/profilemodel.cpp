#include "profilemodel.h"

#include <QSettings>
#include <QSet>

namespace {
constexpr auto OrderKey = "ui/profileOrder";
QStringList validOrder(const QVariant &value) {
    QStringList result;
    if (value.metaType().id() != QMetaType::QStringList && value.metaType().id() != QMetaType::QString
        && value.metaType().id() != QMetaType::QVariantList) return result;
    const auto values = value.toStringList();
    QSet<QString> seen;
    for (const auto &id : values) {
        if (!id.isEmpty() && id.size() <= 256 && !seen.contains(id)) { result.append(id); seen.insert(id); }
    }
    return result;
}
}

ProfileListModel::ProfileListModel(bool persistent, QObject *parent)
    : QAbstractListModel(parent), m_persistent(persistent) {
    if (persistent) m_order = validOrder(QSettings().value(OrderKey));
}
int ProfileListModel::rowCount(const QModelIndex &parent) const { return parent.isValid() ? 0 : m_rows.size(); }
QVariant ProfileListModel::data(const QModelIndex &index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= m_rows.size() || role != Qt::UserRole) return {};
    return m_rows[index.row()];
}
QHash<int, QByteArray> ProfileListModel::roleNames() const { return {{Qt::UserRole, "modelData"}}; }
QString ProfileListModel::idAt(int row) const {
    return row >= 0 && row < m_rows.size() ? m_rows[row].toMap().value("id").toString() : QString{};
}
int ProfileListModel::indexOf(const QString &id) const {
    for (int row = 0; row < m_rows.size(); ++row) if (idAt(row) == id) return row;
    return -1;
}
bool ProfileListModel::save(const QStringList &order) {
    if (!m_persistent) return true;
    QSettings settings;
    const bool existed = settings.contains(OrderKey);
    const auto previous = settings.value(OrderKey);
    settings.setValue(OrderKey, order);
    settings.sync();
    if (settings.status() == QSettings::NoError) return true;
    // Do not leave a failed write in QSettings' shared in-process cache, where
    // a later destructor/sync could unexpectedly persist the rejected move.
    if (existed) settings.setValue(OrderKey, previous); else settings.remove(OrderKey);
    settings.sync();
    emit saveFailed();
    return false;
}
void ProfileListModel::reconcile(const QVariantList &profiles) {
    QHash<QString, QVariant> library;
    QStringList sourceOrder;
    for (const auto &value : profiles) {
        const auto id = value.toMap().value("id").toString();
        if (id.isEmpty() || library.contains(id)) continue;
        library.insert(id, value); sourceOrder.append(id);
    }
    QStringList order;
    QSet<QString> seen;
    for (const auto &id : m_order) if (library.contains(id) && !seen.contains(id)) { order.append(id); seen.insert(id); }
    for (const auto &id : sourceOrder) if (!seen.contains(id)) { order.append(id); seen.insert(id); }
    QVariantList next;
    for (const auto &id : order) next.append(library.value(id));
    // On startup the visible model may already be empty, while settings still
    // contain IDs deleted during the previous GUI session.
    if (m_rows == next && m_order == order) return;
    QSet<QString> oldIDs;
    for (int i = 0; i < m_rows.size(); ++i) oldIDs.insert(idAt(i));
    const bool membership = oldIDs != seen;
    emit viewAboutToChange(membership);
    const int oldCount = m_rows.size();
    for (int i = m_rows.size()-1; i >= 0; --i) {
        if (!seen.contains(idAt(i))) { beginRemoveRows({}, i, i); m_rows.removeAt(i); endRemoveRows(); }
    }
    for (int i = 0; i < order.size(); ++i) {
        const int current = indexOf(order[i]);
        if (current < 0) { beginInsertRows({}, i, i); m_rows.insert(i, next[i]); endInsertRows(); }
        else if (current != i) { beginMoveRows({}, current, current, {}, i); m_rows.move(current, i); endMoveRows(); }
        if (m_rows[i] != next[i]) { m_rows[i] = next[i]; emit dataChanged(index(i), index(i), {Qt::UserRole}); }
    }
    const bool orderChanged = order != m_order;
    m_order = order;
    if (oldCount != m_rows.size()) emit countChanged();
    emit changed();
    // Membership changes must remain visible even if settings are unwritable;
    // only a user move is rejected before touching the visible model.
    if (orderChanged) save(order);
}
bool ProfileListModel::moveBefore(const QString &id, const QString &beforeId) {
    const int from = indexOf(id);
    if (from < 0 || (!beforeId.isEmpty() && indexOf(beforeId) < 0)) return false;
    if (beforeId == id) return true;
    auto order = m_order;
    order.removeAll(id);
    const int to = beforeId.isEmpty() ? order.size() : order.indexOf(beforeId);
    order.insert(to, id);
    if (order == m_order) return true;
    if (!save(order)) return false;
    emit viewAboutToChange(false);
    beginMoveRows({}, from, from, {}, to > from ? to+1 : to);
    m_rows.move(from, to); m_order = order;
    endMoveRows();
    emit changed();
    return true;
}
