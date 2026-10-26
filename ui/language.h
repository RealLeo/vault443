#pragma once

#include <QObject>
#include <QStringList>
#include <QTranslator>

class LanguageController final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString preference READ preference NOTIFY languageChanged)
    Q_PROPERTY(QString language READ language NOTIFY languageChanged)
    Q_PROPERTY(QString localeName READ localeName NOTIFY languageChanged)
public:
    explicit LanguageController(bool persistent = true, QObject *parent = nullptr);
    ~LanguageController() override;
    QString preference() const { return m_preference; }
    QString language() const { return m_language; }
    QString localeName() const { return m_language == "ru" ? "ru_RU" : "en_US"; }
    static QString resolveLanguage(const QStringList &preferences);
    Q_INVOKABLE void setPreference(const QString &preference);
    Q_INVOKABLE QString serviceMessage(const QString &message) const;
signals:
    void languageChanged();
private:
    void apply();
    bool m_persistent;
    QString m_preference = "system", m_language = "en";
    QTranslator m_translator;
};
