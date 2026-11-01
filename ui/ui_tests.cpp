#include "bridge.h"
#include "language.h"
#include "tray.h"
#include <QApplication>
#include <QClipboard>
#include <QDBusMessage>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJSValue>
#include <QPainter>
#include <QQmlApplicationEngine>
#include <QQmlContext>
#include <QQuickItem>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QSignalSpy>
#include <QSettings>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTemporaryFile>
#include <QtTest>

class GuiTests : public QObject {
    Q_OBJECT
private:
    std::unique_ptr<LanguageController> language;
    std::unique_ptr<Bridge> bridge;
    std::unique_ptr<QQmlApplicationEngine> engine;
    QQuickWindow *window = nullptr;
    QQuickItem *findItem(QQuickItem *root, const QString &name) {
        if (root->objectName() == name) return root;
        for (auto *child : root->childItems()) if (auto *found = findItem(child, name)) return found;
        return nullptr;
    }
    QQuickItem *item(const QString &name) { return findItem(window->contentItem(), name); }
    void fixtureControl(const QString &method, const QVariantList &args = {}) {
        auto message = QDBusMessage::createMethodCall("org.vault443.Service1", "/org/vault443/Service1", "org.vault443.Service1", method);
        message.setArguments(args);
        const auto reply = QDBusConnection::systemBus().call(message, QDBus::Block, 5000);
        QVERIFY2(reply.type() != QDBusMessage::ErrorMessage, qPrintable(reply.errorMessage()));
    }
    void fixtureConfigure(const QVariantMap &options) {
        fixtureControl("FixtureConfigure", {QString::fromUtf8(QJsonDocument(QJsonObject::fromVariantMap(options)).toJson(QJsonDocument::Compact))});
    }
    static QString qmlText(const char *source) { return QCoreApplication::translate("Main", source); }
    static QString bridgeText(const char *source) { return QCoreApplication::translate("Bridge", source); }
    static QString trayText(const char *source) { return QCoreApplication::translate("QObject", source); }
    static QString wireGuardFixture(bool awg = false) {
        // Synthetic parser inputs, never used to connect to a real server.
        QString text = QString("[Interface]\nPrivateKey = %1\nAddress = 10.72.0.2/32\nDNS = 10.72.0.53, corp.example\nMTU = 1280\n")
            .arg(QString::fromLatin1(QByteArray(32, 'k').toBase64()));
        if (awg) text += "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nH1 = 101\nH2 = 202\nH3 = 303\nH4 = 404\n";
        text += QString("[Peer]\nPublicKey = %1\nPresharedKey = %2\nEndpoint = %3:51820\nAllowedIPs = 10.72.0.0/16\nPersistentKeepalive = 25\n")
            .arg(QString::fromLatin1(QByteArray(32, 'p').toBase64()), QString::fromLatin1(QByteArray(32, 's').toBase64()), awg ? "east.example" : "west.example");
        return text;
    }
    void click(const QString &name) {
        auto *target = item(name);
        QVERIFY2(target, qPrintable("Missing item: " + name));
        QVERIFY2(target->isVisible() && target->isEnabled(), qPrintable("Disabled/invisible item: " + name));
        const auto position = target->mapToScene(QPointF(target->width() / 2, target->height() / 2));
        QTest::mouseClick(window, Qt::LeftButton, Qt::NoModifier, position.toPoint());
        QCoreApplication::processEvents();
        QTest::qWait(30);
    }
    void importProfiles(Bridge *target, const QString &text) {
        target->prepareImport(text, "text", "");
        QTRY_VERIFY_WITH_TIMEOUT(!target->preview().value("draftId").toString().isEmpty(), 5000);
        target->commitImport({});
        QTRY_VERIFY_WITH_TIMEOUT(target->preview().isEmpty(), 5000);
    }
    void loadWindow(bool demo, double scale = 0.5) {
        language = std::make_unique<LanguageController>(false);
        bridge = std::make_unique<Bridge>(demo);
        engine = std::make_unique<QQmlApplicationEngine>();
        engine->rootContext()->setContextProperty("i18n", language.get());
        engine->rootContext()->setContextProperty("backend", bridge.get());
        connect(language.get(), &LanguageController::languageChanged, engine.get(), &QQmlApplicationEngine::retranslate);
        engine->rootContext()->setContextProperty("initialScale", scale);
        engine->rootContext()->setContextProperty("demoScreen", "main");
        engine->load(QUrl("qrc:/qml/Main.qml"));
        QVERIFY(!engine->rootObjects().isEmpty());
        window = qobject_cast<QQuickWindow *>(engine->rootObjects().first());
        QVERIFY(window);
        window->requestActivate();
        QTest::qWait(120);
    }
private slots:
    void init() { if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") == "1") fixtureConfigure({}); loadWindow(true); }
    void cleanup() { engine.reset(); bridge.reset(); language.reset(); window = nullptr; }
    void bootSelectionSurvivesRefreshAndRemovedProfile() {
        click("settings-button"); auto *field = item("boot-profile");
        field->setProperty("currentIndex", 2);
        QVERIFY(QMetaObject::invokeMethod(field, "activated", Q_ARG(int, 2)));
        const auto chosen = field->property("selectedProfileId").toString();
        QSignalSpy models(bridge.get(), &Bridge::bootProfilesChanged);
        for (int i = 0; i < 25; ++i) bridge->refresh();
        QCOMPARE(models.count(), 0); QCOMPARE(field->property("selectedProfileId").toString(), chosen);
        bridge->removeProfile(chosen);
        QTRY_VERIFY(field->property("missingSelection").toBool());
        QVERIFY(!item("boot-apply")->isEnabled()); QVERIFY(item("boot-selection-missing")->isVisible());
        field->setProperty("currentIndex", 0);
        QVERIFY(QMetaObject::invokeMethod(field, "activated", Q_ARG(int, 0)));
        QVERIFY(item("boot-apply")->isEnabled()); QVERIFY(!field->property("missingSelection").toBool());
    }
    void workImportIconsAndConnectionsStayIndependent() {
        QTemporaryDir files; QVERIFY(files.isValid());
        QList<QUrl> urls;
        for (int i = 1; i <= 2; ++i) {
            const auto path = files.filePath(QString("Office-%1.ovpn").arg(i));
            QFile file(path); QVERIFY(file.open(QIODevice::WriteOnly));
            file.write(QString("client\ndev tun\nremote office%1.example.net 1194 udp\n").arg(i).toUtf8()); file.close();
            urls.append(QUrl::fromLocalFile(path));
        }
        click("import-button");
        bridge->readWorkFiles(urls);
        QCOMPARE(bridge->preview().value("profiles").toList().size(), 2);
        click("import-cancel");
        QCOMPARE(bridge->profiles().size(), 3);
        click("import-button"); bridge->readWorkFiles(urls);
        const auto imported = bridge->preview().value("profiles").toList();
        const auto firstID = imported[0].toMap().value("id").toString();
        const auto secondID = imported[1].toMap().value("id").toString();
        bridge->commitImport({{firstID, "key"}, {secondID, "shield"}});
        QCOMPARE(bridge->profiles().size(), 5);
        QCOMPARE(bridge->snapshot().value("profiles").toList().size(), 3);
        auto work = bridge->snapshot().value("workProfiles").toList();
        QCOMPARE(work[0].toMap().value("iconId").toString(), QString("key"));
        bridge->connectWorkProfile(firstID); bridge->connectWorkProfile(secondID);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        work = bridge->snapshot().value("workProfiles").toList();
        QCOMPARE(work[0].toMap().value("runtime").toMap().value("state").toString(), QString("connected"));
        QCOMPARE(work[1].toMap().value("runtime").toMap().value("state").toString(), QString("connected"));
        bridge->disconnectProfile();
        QCOMPARE(bridge->snapshot().value("workProfiles").toList(), work);
        bridge->disconnectWorkProfile(firstID);
        work = bridge->snapshot().value("workProfiles").toList();
        QCOMPARE(work[0].toMap().value("runtime").toMap().value("state").toString(), QString("disconnected"));
        QCOMPARE(work[1].toMap().value("runtime").toMap().value("state").toString(), QString("connected"));
        bridge->loadProfileLogs(secondID, true);
        QVERIFY(!bridge->profileLogs().isEmpty());
        QVERIFY(!bridge->profileLogs()[1].toMap().value("message").toString().contains("Xray"));
        bridge->readWorkFiles(urls);
        QVERIFY(bridge->preview().value("profiles").toList()[0].toMap().value("duplicate").toBool());
    }
    void workRoutesAndDNSCanReturnToAutomatic() {
        bridge->setDemoState("work-vpns");
        QVERIFY(QMetaObject::invokeMethod(window, "openRoutes")); QTest::qWait(80);
        QVERIFY(item("work-route-destination"));
        item("work-route-destination")->setProperty("text", "192.168.100.15/32");
        item("work-route-target")->setProperty("currentIndex", 1);
        click("work-route-save");
        QCOMPARE(bridge->workRoutes().value("rules").toList().size(), 1);
        click("work-route-0"); click("work-route-remove");
        QCOMPARE(bridge->workRoutes().value("rules").toList().size(), 0);
        item("work-route-kind")->setProperty("currentIndex", 1); QTest::qWait(40);
        item("work-route-destination")->setProperty("text", "corp.example");
        click("work-route-save");
        QCOMPARE(bridge->workRoutes().value("dnsRules").toList().size(), 1);
        click("work-route-0"); click("work-route-remove");
        QCOMPARE(bridge->workRoutes().value("dnsRules").toList().size(), 0);
        bridge->setDemoState("foreign"); bridge->refreshWorkRoutes();
        QVERIFY(bridge->workRoutes().isEmpty());
        QVERIFY(!bridge->workRoutesError().isEmpty());
    }
    void wireGuardTextImportAndPeerDetails() {
        QVariant peerState;
        QVERIFY(QMetaObject::invokeMethod(window, "peerState", Q_RETURN_ARG(QVariant, peerState), Q_ARG(QVariant, QVariant("waiting_handshake"))));
        QCOMPARE(peerState.toString(), qmlText("Waiting for handshake"));
        click("import-button");
        item("import-text")->setProperty("text", wireGuardFixture());
        click("import-preview");
        auto preview = bridge->preview().value("profiles").toList();
        QCOMPARE(preview.size(), 1);
        QCOMPARE(preview[0].toMap().value("kind").toString(), QString("wireguard"));
        click("import-commit");
        auto work = bridge->snapshot().value("workProfiles").toList();
        QCOMPARE(work.size(), 1);
        bridge->connectWorkProfile(work[0].toMap().value("id").toString());
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        bridge->setDemoState("wireguard-vpns");
        QTest::qWait(60);
        QCOMPARE(item("profile-kind-1")->property("text").toString(), QString("WireGuard"));
        QCOMPARE(item("profile-kind-2")->property("text").toString(), QString("AmneziaWG"));
        QCOMPARE(item("status-2")->property("text").toString(), qmlText("Partially connected"));
        QCOMPARE(item("connect-2")->property("text").toString(), qmlText("Disconnect"));
        const auto awg = bridge->snapshot().value("workProfiles").toList()[1].toMap();
        QVERIFY(QMetaObject::invokeMethod(window, "showProfile", Q_ARG(QVariant, QVariant(awg))));
        QTest::qWait(60); click("profile-peers-tab");
        QCOMPARE(item("profile-peers")->property("count").toInt(), 2);
        QVERIFY(item("peer-handshake-1")->property("text").toString().contains(qmlText("Not received yet")));
        const auto before = bridge->snapshot();
        language->setPreference("ru"); QTest::qWait(40);
        QVERIFY(item("peer-state-1")->property("text").toString().contains(QString::fromUtf8("Переподключение")));
        QCOMPARE(bridge->snapshot(), before);
        bridge->setDemoState("offline"); QTest::qWait(30);
        QCOMPARE(item("profile-peers")->property("count").toInt(), 2);
    }
    void wireGuardTrayIncludesPartialAndProtocol() {
        bridge->setDemoState("wireguard-vpns");
        TrayController tray(bridge.get(), false);
        auto *menu = tray.menu()->findChild<QMenu *>("tray-work-vpns");
        QVERIFY(menu); QCOMPARE(menu->actions().size(), 2);
        QVERIFY(menu->actions()[0]->text().contains("WireGuard"));
        QVERIFY(menu->actions()[1]->text().contains("AmneziaWG"));
        const auto view = trayPresentation(bridge->snapshot(), true, false);
        QCOMPARE(view.color, QColor("#f5ca55"));
        QVERIFY(view.text.contains(trayText("Work VPN needs attention")));
        menu->actions()[1]->trigger();
        QCOMPARE(menu->actions().size(), 1);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
    }
    void workButtonLabelsFitBothLanguages() {
        auto check = [this](const QString &name) {
            auto *button = item(name); QVERIFY(button);
            const auto font = button->property("font").value<QFont>();
            const QFontMetricsF metrics(font);
            QVERIFY2(metrics.horizontalAdvance(button->property("text").toString()) <= button->width() - 2*button->property("padding").toDouble() + 1,
                     qPrintable(name + ": " + button->property("text").toString()));
        };
        for (const auto &value : {QString("en"), QString("ru")}) {
            language->setPreference(value); click("import-button"); check("import-work"); click("import-cancel");
            QVERIFY(QMetaObject::invokeMethod(window, "openRoutes")); QTest::qWait(80);
            check("work-route-save"); check("work-route-remove"); check("work-route-refresh");
            QTest::keyClick(window, Qt::Key_Escape); QTest::qWait(30);
        }
    }
    void workMessagesRetranslateWithoutChangingTechnicalValues() {
        language->setPreference("ru");
        QVERIFY(language->serviceMessage("OpenVPN line 12: passwords, MFA and external credential providers are unsupported").startsWith(QString::fromUtf8("Строка OpenVPN 12:")));
        QVERIFY(language->serviceMessage("Several work VPNs claim the same route; select a target").contains(QString::fromUtf8("выберите")));
        language->setPreference("en");
        QCOMPARE(language->serviceMessage("OpenVPN line 12: passwords, MFA and external credential providers are unsupported"), QString("OpenVPN line 12: passwords, MFA and external credential providers are unsupported"));
        QCOMPARE(language->serviceMessage("unknown 192.168.100.15 detail"), QString("unknown 192.168.100.15 detail"));
    }
    void wireGuardImportErrorsTranslateWithoutExposingValues() {
        const auto error = QString("WireGuard line 8: invalid PrivateKey");
        language->setPreference("en");
        QCOMPARE(language->serviceMessage(error), error);
        language->setPreference("ru");
        QCOMPARE(language->serviceMessage(error), QString::fromUtf8("Строка WireGuard 8: Некорректный параметр: PrivateKey"));
        QVERIFY(language->serviceMessage("WireGuard DNS server is outside AllowedIPs").contains(QString::fromUtf8("не входит")));
        QVERIFY(language->serviceMessage("Amnezia API subscriptions and administrative access keys are unsupported; export a client configuration").contains(QString::fromUtf8("клиентскую")));
        QCOMPARE(language->serviceMessage("peer 192.0.2.42 custom diagnostic"), QString("peer 192.0.2.42 custom diagnostic"));
    }
    void workTrayShowsIndependentDisconnectActions() {
        bridge->setDemoState("work-vpns");
        TrayController tray(bridge.get(), false);
        auto *workMenu = tray.menu()->findChild<QMenu *>("tray-work-vpns");
        QVERIFY(workMenu); QCOMPARE(workMenu->actions().size(), 2);
        QVERIFY(trayPresentation(bridge->snapshot(), true, false).text.contains("2"));
        workMenu->actions()[0]->trigger();
        QCOMPARE(workMenu->actions().size(), 1);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        bridge->setDemoState("foreign");
        QVERIFY(!workMenu->menuAction()->isVisible());
        QVERIFY(!trayPresentation(bridge->snapshot(), true, false).text.contains("Office"));
    }
    void compactImportAndTrafficFitInBothLanguagesAndScales() {
        for (const auto &locale : {QString("en"), QString("ru")}) {
            for (const auto scale : {0.5, 0.625, 0.75, 1.0}) {
                // Production scale is a startup setting. A fixed-size Wayland
                // surface cannot reliably change its min/max bounds in-place.
                cleanup();
                loadWindow(true, scale);
                language->setPreference(locale);
                QCoreApplication::processEvents();
                QTRY_COMPARE_WITH_TIMEOUT(window->width(), qRound(944 * scale), 5000);
                QTRY_COMPARE_WITH_TIMEOUT(window->height(), qRound(960 * scale), 5000);
                auto *label = item("import-label"); QVERIFY(label);
                QCOMPARE(label->property("text").toString(), locale == "ru" ? QString::fromUtf8("Импорт") : QString("Import"));
                QVERIFY(label->property("contentWidth").toReal() <= label->width());
                QCOMPARE(label->property("horizontalAlignment").toInt(), int(Qt::AlignHCenter));
                bridge->setDemoState("large-traffic"); QCoreApplication::processEvents();
                for (const auto &name : {"session-duration", "download-rate", "upload-rate", "download-total", "upload-total"}) {
                    auto *text = item(name); QVERIFY(text && text->isVisible());
                    QVERIFY2(text->property("contentWidth").toReal() <= text->width(), name);
                    QVERIFY2(text->property("contentHeight").toReal() <= text->height(), name);
                    const auto bounds = text->mapRectToScene(text->boundingRect());
                    QVERIFY(bounds.left() >= 0 && bounds.right() <= window->width());
                    QVERIFY(bounds.top() >= 0 && bounds.bottom() <= window->height());
                }
                const auto timeBounds = item("session-duration")->mapRectToScene(item("session-duration")->boundingRect());
                qreal right = timeBounds.right();
                for (const auto &name : {"download-rate", "upload-rate", "download-total", "upload-total"}) {
                    auto *value = item(name);
                    const auto bounds = value->mapRectToScene(value->boundingRect());
                    QCOMPARE(bounds.center().y(), timeBounds.center().y());
                    QVERIFY2(bounds.left() > right, name);
                    QCOMPARE(value->property("font").value<QFont>().pixelSize(), 24);
                    QVERIFY(!value->property("description").toString().isEmpty());
                    right = bounds.right();
                }
                QVERIFY(item("download-total")->property("text").toString().endsWith(locale == "ru" ? QString::fromUtf8("ЭБ") : QString("EB")));
                QVERIFY(item("download-rate")->property("text").toString().endsWith(locale == "ru" ? QString::fromUtf8("/с") : QString("/s")));
                QVERIFY(!item("download-total")->property("text").toString().contains('/'));
            }
        }
    }
    void trafficStaysAfterDisconnectAndHidesWhenUnavailableOrForeign() {
        const auto duration = item("session-duration")->property("text");
        const auto total = item("download-total")->property("text");
        const auto session = bridge->snapshot().value("traffic").toMap().value("sessionId");
        bridge->disconnectProfile(); QCoreApplication::processEvents();
        QCOMPARE(item("session-duration")->property("text"), duration);
        QCOMPARE(item("download-total")->property("text"), total);
        QCOMPARE(bridge->snapshot().value("traffic").toMap().value("downloadBytesPerSecond").toInt(), 0);
        bridge->connectProfile("demo-backup"); QCoreApplication::processEvents();
        QVERIFY(bridge->snapshot().value("traffic").toMap().value("sessionId") != session);
        QCOMPARE(item("session-duration")->property("text").toString(), QString("00:00:00"));
        QCOMPARE(bridge->snapshot().value("traffic").toMap().value("downloadBytes").toInt(), 0);
        for (const auto &state : {"offline", "foreign", "traffic-unavailable"}) {
            bridge->setDemoState(state); QCoreApplication::processEvents();
            QCOMPARE(item("session-duration")->property("text").toString(), QString::fromUtf8("—"));
            QCOMPARE(item("download-total")->property("text").toString(), QString::fromUtf8("↓ —"));
            QCOMPARE(item("upload-rate")->property("text").toString(), QString::fromUtf8("↑ —"));
            bridge->setDemoState("connected");
        }
    }
    void initialLanguageUsesSystemPreferences() {
        QCOMPARE(language->preference(), QString("system"));
        QCOMPARE(language->language(), LanguageController::resolveLanguage(QLocale::system().uiLanguages()));
        const auto requestedLanguages = qEnvironmentVariable("LANGUAGE");
        if (!requestedLanguages.isEmpty())
            QCOMPARE(language->language(), LanguageController::resolveLanguage(requestedLanguages.split(':')));
        qInfo().noquote() << "System UI languages:" << QLocale::system().uiLanguages().join(", ")
                          << "; resolved:" << language->language();
    }
    void languageResolution_data() {
        QTest::addColumn<QStringList>("preferences");
        QTest::addColumn<QString>("expected");
        QTest::newRow("Russian-region") << QStringList{"ru_RU"} << QString("ru");
        QTest::newRow("Russian-hyphen") << QStringList{"ru-RU"} << QString("ru");
        QTest::newRow("English-region") << QStringList{"en_US"} << QString("en");
        QTest::newRow("English-GB") << QStringList{"en-GB"} << QString("en");
        QTest::newRow("unsupported") << QStringList{"de_DE"} << QString("en");
        QTest::newRow("C-locale") << QStringList{"C"} << QString("en");
        QTest::newRow("empty") << QStringList{} << QString("en");
        QTest::newRow("first-supported") << QStringList{"de-DE", "ru-RU", "en-US"} << QString("ru");
        QTest::newRow("English-first") << QStringList{"en-US", "ru-RU"} << QString("en");
    }
    void languageResolution() {
        QFETCH(QStringList, preferences); QFETCH(QString, expected);
        QCOMPARE(LanguageController::resolveLanguage(preferences), expected);
    }
    void languagePreferencePersistsAndInvalidValuesUseSystem() {
        cleanup();
        QSettings settings; settings.remove("ui/language"); settings.sync();
        {
            LanguageController first(true);
            QCOMPARE(first.preference(), QString("system"));
            QCOMPARE(first.language(), LanguageController::resolveLanguage(QLocale::system().uiLanguages()));
            first.setPreference("ru");
            QCOMPARE(first.language(), QString("ru"));
            settings.sync(); QCOMPARE(settings.value("ui/language").toString(), QString("ru"));
        }
        {
            LanguageController second(true);
            QCOMPARE(second.preference(), QString("ru"));
            QCOMPARE(second.language(), QString("ru"));
            second.setPreference("en");
            QCOMPARE(second.language(), QString("en"));
        }
        settings.setValue("ui/language", "invalid"); settings.sync();
        {
            LanguageController invalid(true);
            QCOMPARE(invalid.preference(), QString("system"));
            QCOMPARE(invalid.language(), LanguageController::resolveLanguage(QLocale::system().uiLanguages()));
        }
        settings.setValue("ui/language", "ru"); settings.sync();
        {
            LanguageController transient(false);
            QCOMPARE(transient.preference(), QString("system"));
            transient.setPreference("en");
        }
        settings.sync(); QCOMPARE(settings.value("ui/language").toString(), QString("ru"));
        settings.remove("ui/language");
    }
    void hotLanguageSwitchPreservesDraftInputsAndConnection() {
        language->setPreference("en");
        bridge->updateProfile("demo-main", "User profile · Пользователь", "antenna");
        const auto profiles = bridge->profiles();
        const auto state = bridge->snapshot();
        click("import-button");
        const QString link = "vless://00000000-0000-4000-8000-000000000083@language.example:443?security=tls#User%20draft";
        item("import-text")->setProperty("text", link);
        click("import-preview");
        QTRY_VERIFY(item("import-commit")->isEnabled());
        click("import-icon-0"); click("icon-atom");
        const auto preview = bridge->preview();
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        language->setPreference("ru");
        QTRY_COMPARE(item("import-commit")->property("text").toString(), qmlText("Import"));
        QCOMPARE(item("import-text")->property("text").toString(), link);
        QCOMPARE(bridge->preview(), preview); QCOMPARE(bridge->profiles(), profiles); QCOMPARE(bridge->snapshot(), state);
        QVERIFY(item("import-commit")->isEnabled()); QCOMPARE(operations.size(), 0);
        language->setPreference("en");
        QTRY_COMPARE(item("import-commit")->property("text").toString(), QString("Import"));
        QCOMPARE(bridge->preview(), preview); QCOMPARE(operations.size(), 0);
        click("import-cancel"); click("profile-0");
        item("profile-name")->setProperty("text", "Unsaved · Несохранённое");
        operations.clear(); language->setPreference("ru");
        QCoreApplication::processEvents();
        QCOMPARE(item("profile-name")->property("text").toString(), QString("Unsaved · Несохранённое"));
        QCOMPARE(bridge->profiles(), profiles); QCOMPARE(bridge->snapshot(), state); QCOMPARE(operations.size(), 0);
        QTest::keyClick(window, Qt::Key_Escape); click("settings-button");
        item("boot-profile")->setProperty("currentIndex", 2);
        const auto bootSelection = item("boot-profile")->property("currentValue");
        language->setPreference("en"); QCoreApplication::processEvents();
        QCOMPARE(item("boot-profile")->property("currentValue"), bootSelection);
        QCOMPARE(bridge->snapshot(), state); QCOMPARE(operations.size(), 0);
        click("subscriptions-tab");
        item("subscription-name")->setProperty("text", "Unsaved subscription");
        item("subscription-url")->setProperty("text", "https://example.invalid/uncommitted");
        language->setPreference("ru"); QCoreApplication::processEvents();
        QVERIFY(item("subscriptions-tab")->property("checked").toBool());
        QCOMPARE(item("subscription-name")->property("text").toString(), QString("Unsaved subscription"));
        QCOMPARE(item("subscription-url")->property("text").toString(), QString("https://example.invalid/uncommitted"));
        QCOMPARE(bridge->snapshot(), state); QCOMPARE(operations.size(), 0);
    }
    void hotLanguageSwitchUpdatesOfflineStatusAndTray() {
        language->setPreference("en");
        TrayController tray(bridge.get(), false);
        bridge->setDemoState("offline");
        auto *status = tray.menu()->actions().first();
        QCOMPARE(status->text(), QString("Service unavailable — VPN state unknown"));
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        language->setPreference("ru");
        QTRY_COMPARE(status->text(), trayText("Service unavailable — VPN state unknown"));
        QVERIFY(status->text() != QString("Service unavailable — VPN state unknown"));
        QCOMPARE(tray.icon()->toolTip(), QString("Vault 443\n") + status->text());
        QCOMPARE(operations.size(), 0); QVERIFY(!bridge->online());
        click("settings-button");
        QVERIFY(item("language-selector") && item("language-selector")->isEnabled());
        QCOMPARE(item("language-selector")->property("count").toInt(), 3);
        click("language-selector");
        QTest::keyClick(window, Qt::Key_Home);
        QTest::keyClick(window, Qt::Key_Down);
        QTest::keyClick(window, Qt::Key_Return);
        QTRY_COMPARE(language->preference(), QString("en"));
        QTRY_COMPARE(status->text(), QString("Service unavailable — VPN state unknown"));
        QCOMPARE(operations.size(), 0); QVERIFY(!bridge->online());
    }
    void hotLanguageSwitchRetranslatesCachedDiagnostics() {
        language->setPreference("en");
        bridge->setDemoState("retry-wait");
        click("status-0");
        QTRY_VERIFY(!bridge->diagnosticsPending() && !bridge->diagnosticData().isEmpty());
        bridge->setDemoState("diagnostics-error"); click("diagnostics-refresh");
        QTRY_VERIFY(!bridge->diagnosticsPending() && !bridge->diagnosticsError().isEmpty());
        const auto rawError = bridge->diagnosticsError();
        const auto rawReport = bridge->diagnostics();
        const auto snapshot = bridge->snapshot();
        const auto received = bridge->diagnosticsReceivedAt();
        QCOMPARE(item("diagnostics-state")->property("text").toString(), rawError);
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        QSignalSpy updates(bridge.get(), &Bridge::diagnosticsChanged);
        language->setPreference("ru");
        QTRY_COMPARE(item("diagnostics-state")->property("text").toString(), bridgeText("The service did not respond within 3 s. Showing the last received snapshot."));
        QVERIFY(item("diagnostics-state")->property("text").toString() != rawError);
        QVERIFY(item("diagnostics-failure")->property("text").toString().contains(bridgeText("DNS did not respond: the port 53 request and HTTPS fallback both timed out.")));
        QCOMPARE(bridge->diagnostics(), rawReport); QCOMPARE(bridge->snapshot(), snapshot);
        QCOMPARE(bridge->diagnosticsReceivedAt(), received); QCOMPARE(bridge->diagnosticsError(), rawError);
        QCOMPARE(updates.size(), 0); QCOMPARE(operations.size(), 0);
        language->setPreference("en");
        QTRY_COMPARE(item("diagnostics-state")->property("text").toString(), rawError);
        QCOMPARE(bridge->diagnostics(), rawReport); QCOMPARE(updates.size(), 0); QCOMPARE(operations.size(), 0);
    }
    void serviceErrorsTranslateWithoutChangingUnknownTechnicalMessages() {
        const QString dns = "VPN server DNS lookup timed out; DNS and HTTPS fallback did not complete";
        const QString draft = "import draft not found or expired";
        const QString unknown = "Vendor-specific upstream failure (code 918): host.example:443";
        const QString lookalike = dns + " / additional upstream details";
        language->setPreference("en");
        QCOMPARE(language->serviceMessage(dns), dns);
        QCOMPARE(language->serviceMessage(draft), draft);
        QCOMPARE(language->serviceMessage(unknown), unknown);
        language->setPreference("ru");
        QCOMPARE(language->serviceMessage(dns), QString("Истекло время поиска адреса VPN-сервера: DNS и резервный HTTPS не ответили."));
        QCOMPARE(language->serviceMessage(draft), QString("Черновик импорта не найден или истёк. Проверьте список ещё раз."));
        QCOMPARE(language->serviceMessage(unknown), unknown);
        QCOMPARE(language->serviceMessage(lookalike), lookalike);
        QCOMPARE(language->serviceMessage(QString()), QString());
        language->setPreference("en");
        QCOMPARE(language->serviceMessage(dns), dns);
        QCOMPARE(language->serviceMessage(draft), draft);
    }
    void clickConnectDisconnectAndSwitch() {
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        click("connect-0");
        QCOMPARE(bridge->snapshot().value("runtime").toMap().value("state").toString(), QString("disconnected"));
        click("connect-1");
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-backup"));
        click("connect-2");
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-work"));
    }
    void importRequiresCurrentPreview() {
        click("import-button");
        auto *text = item("import-text"); QVERIFY(text);
        text->setProperty("text", "vless://00000000-0000-4000-8000-000000000001@example.net:443?security=tls#Demo");
        auto *commit = item("import-commit"); QVERIFY(commit); QVERIFY(!commit->isEnabled());
        click("import-preview");
        QTRY_VERIFY(commit->isEnabled());
        text->setProperty("text", "invalid");
        QTRY_VERIFY(!commit->isEnabled());
        click("import-preview");
        QVERIFY(!commit->isEnabled());
        QVERIFY(!bridge->preview().value("errors").toList().isEmpty());
        text->setProperty("text", "vless://00000000-0000-4000-8000-000000000001@example.net:443?security=tls#Demo");
        click("import-preview");
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        click("import-commit");
        QCOMPARE(bridge->snapshot().value("profiles").toList().size(), 4);
        QVERIFY(bridge->preview().isEmpty());
        for (const auto &operation : operations) QVERIFY(operation[0].toString() != "CancelImport");
        QVERIFY(bridge->error().isEmpty());
    }
    void escapeClosesSettingsWithoutChangingConnection() {
        click("settings-button");
        QVERIFY(item("boot-apply"));
        QTest::keyClick(window, Qt::Key_Escape);
        QCoreApplication::processEvents();
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        click("connect-0");
        QCOMPARE(bridge->snapshot().value("runtime").toMap().value("state").toString(), QString("disconnected"));
    }
    void closedGuiDoesNotDisconnect() {
        bridge->setTrayAvailable(true);
        click("close-button");
        QVERIFY(!window->isVisible());
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-main"));
        bridge->Raise();
        QTRY_VERIFY(window->isVisible());
    }
    void demoAutostartAndBootAreSeparate() {
        const auto originalBoot = bridge->snapshot().value("bootProfileId").toString();
        click("autostart-button");
        QVERIFY(!bridge->autostart());
        QCOMPARE(bridge->snapshot().value("bootProfileId").toString(), originalBoot);
        click("boot-button");
        QVERIFY(bridge->snapshot().value("bootProfileId").toString().isEmpty());
    }
    void twentyProfilesScrollAndConnectLast() {
        bridge->setDemoState("many");
        auto *list = item("profile-list"); QVERIFY(list);
        QTRY_COMPARE(list->property("count").toInt(), 20);
        QVERIFY(QMetaObject::invokeMethod(list, "positionViewAtEnd"));
        QTRY_VERIFY(item("connect-19"));
        click("connect-19");
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString("demo-20"));
        const double position = list->property("contentY").toDouble();
        bridge->refresh();
        QCoreApplication::processEvents();
        QCOMPARE(list->property("contentY").toDouble(), position);
    }
    void emptyProfilesShowImport() {
        bridge->setDemoState("empty");
        QCoreApplication::processEvents();
        auto *list = item("profile-list"); QVERIFY(list);
        QCOMPARE(list->property("count").toInt(), 0);
        click("empty-action");
        QTRY_VERIFY(item("import-text") && item("import-text")->isVisible());
    }
    void importIconsAreIndividualAndPropertiesPersist() {
        click("import-button");
        item("import-text")->setProperty("text", "vless://00000000-0000-4000-8000-000000000011@one.example:443?security=tls#One\nvless://00000000-0000-4000-8000-000000000012@two.example:443?security=tls#Two");
        click("import-preview");
        QTRY_VERIFY(item("import-icon-0"));
        click("import-icon-0"); click("icon-vault-door");
        click("import-icon-1"); click("icon-radiation");
        click("import-commit");
        const auto profiles = bridge->profiles();
        QCOMPARE(profiles.size(), 5);
        QCOMPARE(profiles[3].toMap().value("iconId").toString(), QString("vault-door"));
        QCOMPARE(profiles[4].toMap().value("iconId").toString(), QString("radiation"));
        click("profile-0"); click("profile-icon-choice"); click("icon-atom");
        item("profile-name")->setProperty("text", "New display name"); click("profile-save");
        QCOMPARE(bridge->profiles().first().toMap().value("iconId").toString(), QString("atom"));
        QCOMPARE(bridge->profiles().first().toMap().value("name").toString(), QString("New display name"));
    }
    void subscriptionPreviewCanCancelThenCommitIcons() {
        click("settings-button"); click("subscriptions-tab");
        item("subscription-name")->setProperty("text", "Test subscription");
        item("subscription-url")->setProperty("text", "https://example.invalid/sub");
        click("subscription-prepare");
        QTRY_VERIFY(item("import-icon-0")); click("import-cancel");
        QCOMPARE(bridge->profiles().size(), 3);
        QVERIFY(bridge->snapshot().value("subscriptions").toList().isEmpty());
        click("subscription-prepare"); click("import-icon-0"); click("icon-gear");
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        click("import-commit");
        QCOMPARE(bridge->profiles().size(), 5);
        QCOMPARE(bridge->profiles()[3].toMap().value("iconId").toString(), QString("gear"));
        QCOMPARE(bridge->snapshot().value("subscriptions").toList().size(), 1);
        QVERIFY(bridge->preview().isEmpty());
        for (const auto &operation : operations) QVERIFY(operation[0].toString() != "CancelImport");
        QVERIFY(bridge->error().isEmpty());
    }
    void profileLogsCopyClearAndDebugDoNotReconnect() {
        const auto active = bridge->snapshot().value("activeProfileId");
        click("profile-0"); click("logs-tab");
        QTRY_VERIFY(!bridge->profileLogs().isEmpty());
        click("logs-copy"); QVERIFY(QApplication::clipboard()->text().contains("Xray"));
        click("debug-logging");
        QVERIFY(bridge->profiles().first().toMap().value("debugLogging").toBool());
        QCOMPARE(bridge->snapshot().value("activeProfileId"), active);
        click("logs-clear"); QVERIFY(bridge->profileLogs().isEmpty());
        click("logs-more"); QVERIFY(bridge->profileLogs().isEmpty());
    }
    void journalMarkupIsLiteralPlainText() {
        bridge->setDemoState("log-markup");
        click("profile-0"); click("logs-tab");
        auto *message = item("journal-message-1"); QVERIFY(message);
        QCOMPARE(message->property("textFormat").toInt(), int(Qt::PlainText));
        QCOMPARE(message->property("text").toString(), QString("<b>literal & diagnostic</b>"));
        click("logs-copy"); QVERIFY(QApplication::clipboard()->text().contains("<b>literal & diagnostic</b>"));
    }
    void journalLoadsTailAndPagesBackWithoutLosingLiveCursor() {
        bridge->setDemoState("log-history");
        click("profile-0"); click("logs-tab");
        QCOMPARE(bridge->profileLogs().size(), 200);
        QCOMPARE(bridge->profileLogs().first().toMap().value("id").toString(), QString("251"));
        const auto liveCursor = bridge->logCursor();
        click("logs-older");
        QCOMPARE(bridge->profileLogs().size(), 400);
        QCOMPARE(bridge->profileLogs().first().toMap().value("id").toString(), QString("51"));
        QCOMPARE(bridge->logCursor(), liveCursor);
        click("logs-older");
        QCOMPARE(bridge->profileLogs().size(), 450);
        QVERIFY(bridge->logPreviousCursor().isEmpty());
        click("logs-more");
        QCOMPARE(bridge->profileLogs().size(), 200);
        QCOMPARE(bridge->profileLogs().last().toMap().value("id").toString(), QString("450"));
    }
    void compactGeometryFocusAndPopup() {
        QCOMPARE(window->size(), QSize(472, 480));
        auto *button = item("connect-0"); QVERIFY(button);
        auto *label = qobject_cast<QQuickItem *>(button->property("contentItem").value<QObject *>()); QVERIFY(label);
        const auto before = label->position();
        const auto position = button->mapToScene(QPointF(button->width()/2, button->height()/2)).toPoint();
        QTest::mousePress(window, Qt::LeftButton, Qt::NoModifier, position);
        QCoreApplication::processEvents();
        QCOMPARE(label->position(), before);
        QVERIFY(!button->property("visualFocus").toBool());
        QCOMPARE(label->y(), 0.0);
        QCOMPARE(label->height(), button->height());
        QTest::mouseRelease(window, Qt::LeftButton, Qt::NoModifier, position);
        item("settings-button")->forceActiveFocus(Qt::MouseFocusReason);
        button->forceActiveFocus(Qt::TabFocusReason);
        QTRY_VERIFY(button->property("visualFocus").toBool());
        const auto *bootLabel = item("boot-label");
        QCOMPARE(item("boot-button")->width() - bootLabel->x() - bootLabel->width(), 20.0);
        QCOMPARE(bootLabel->property("font"), item("autostart-label")->property("font"));
        click("settings-button"); click("boot-profile");
        QQuickItem *popupItem = nullptr;
        for (auto *object : engine->rootObjects().first()->findChildren<QObject *>()) {
            if (object->objectName() == "boot-profile-popup") { popupItem = qobject_cast<QQuickItem *>(object->property("contentItem").value<QObject *>()); break; }
        }
        QVERIFY(popupItem);
        const auto popupRect = popupItem->mapRectToScene(popupItem->boundingRect());
        const auto fieldRect = item("boot-profile")->mapRectToScene(item("boot-profile")->boundingRect());
        QVERIFY(qAbs(popupRect.width() - fieldRect.width()) <= 3);
        QVERIFY2(popupRect.top() >= fieldRect.bottom() - 1 || popupRect.bottom() <= fieldRect.top() + 1, qPrintable(QString("Popup %1..%2 overlaps field %3..%4").arg(popupRect.top()).arg(popupRect.bottom()).arg(fieldRect.top()).arg(fieldRect.bottom())));
        QVERIFY(popupRect.left() >= 0 && popupRect.top() >= 0 && popupRect.right() <= window->width() && popupRect.bottom() <= window->height());
        QTest::keyClick(window, Qt::Key_Escape); click("vpn-tab"); click("vpn-advanced");
        auto *save = item("vpn-save"), *remove = item("vpn-delete"); QVERIFY(save && remove);
        QCOMPARE(save->size(), QSizeF(300, 60)); QCOMPARE(remove->size(), save->size());
    }
    void connectionStagesCancellationAndRetry() {
        bridge->setDemoState("stage-resolving_endpoint");
        QTRY_VERIFY(item("status-0")->property("text").toString().contains(qmlText("Resolving server")));
        QCOMPARE(item("connect-0")->property("text").toString(), qmlText("Cancel"));
        QVERIFY(item("connect-0")->isEnabled());
        const auto initial = item("status-0")->property("text").toString();
        QTRY_VERIFY_WITH_TIMEOUT(item("status-0")->property("text").toString() != initial, 2500);
        click("connect-0");
        QCOMPARE(bridge->snapshot().value("runtime").toMap().value("state").toString(), QString("disconnected"));
        bridge->setDemoState("retry-wait");
        QTRY_VERIFY(item("status-0")->property("text").toString().contains(qmlText("DNS is not responding")));
        QVERIFY(item("status-0")->property("text").toString().contains(qmlText("%1\nRetry in %2 s").section('\n', 1).section("%2", 0, 0)));
        auto *statusLabel = item("status-0")->property("contentItem").value<QObject *>(); QVERIFY(statusLabel);
        QTRY_COMPARE(statusLabel->property("lineCount").toInt(), 2);
        QVERIFY(!statusLabel->property("truncated").toBool());
        QCOMPARE(item("connect-0")->property("text").toString(), qmlText("Disconnect"));
        const auto failure = bridge->snapshot().value("lastFailure");
        bridge->setDemoState("stage-starting_core");
        QCOMPARE(bridge->snapshot().value("lastFailure"), failure);
        bridge->setDemoState("disconnecting");
        QTRY_COMPARE(item("connect-0")->property("text").toString(), qmlText("Disconnecting…"));
        QVERIFY(!item("connect-0")->isEnabled()); QVERIFY(!item("connect-1")->isEnabled());
        QVERIFY(item("status-0")->property("text").toString().contains(qmlText("Restoring network")));
        bridge->setDemoState("disconnected");
        QCOMPARE(bridge->snapshot().value("lastFailure"), failure);
        QVERIFY(bridge->error().isEmpty());
    }
    void diagnosticsShowsFailureCacheAndProfileLogs() {
        bridge->setDemoState("retry-wait");
        auto *status = item("status-0"); QVERIFY(status);
        QTest::mouseMove(window, status->mapToScene(QPointF(status->width()/2, status->height()/2)).toPoint());
        QTest::qWait(850); // A visible tooltip must not intercept the status click.
        click("status-0");
        QTRY_VERIFY(item("diagnostics-state"));
        QTRY_VERIFY(!bridge->diagnosticsPending() && !bridge->diagnosticData().isEmpty());
        QVERIFY(item("diagnostics-failure")->property("text").toString().contains(language->serviceMessage(bridge->snapshot().value("lastFailure").toMap().value("message").toString())));
        click("diagnostics-copy");
        QVERIFY(QApplication::clipboard()->text().contains("dns_timeout"));
        QVERIFY(QApplication::clipboard()->text().contains("network"));
        const auto received = bridge->diagnosticsReceivedAt();
        const auto data = bridge->diagnosticData();
        bridge->setDemoState("diagnostics-error");
        click("diagnostics-refresh");
        QTRY_VERIFY(!bridge->diagnosticsPending());
        QVERIFY(bridge->diagnosticsError().contains("3 s"));
        QCOMPARE(bridge->diagnosticData(), data); QCOMPARE(bridge->diagnosticsReceivedAt(), received);
        QVERIFY(item("diagnostics-state")->property("text").toString() == language->serviceMessage(bridge->diagnosticsError()));
        QVERIFY(bridge->error().isEmpty());
        click("diagnostics-logs");
        QTRY_VERIFY(item("profile-logs")->isVisible());
        QTest::keyClick(window, Qt::Key_Escape);
        bridge->setDemoState("offline");
        click("status-0");
        QTRY_VERIFY(item("diagnostics-state")->property("text").toString() == language->serviceMessage(bridge->diagnosticsError()));
        QCOMPARE(bridge->diagnosticsReceivedAt(), received);
        QVERIFY(!item("diagnostics-logs")->isEnabled());
        QVERIFY(bridge->error().isEmpty());
    }
    void pointerCursorsDoNotConsumeActionsOrTextInput() {
        const auto hover = [this](const QString &name, Qt::CursorShape shape) {
            auto *control = item(name); QVERIFY(control);
            auto *handler = control->findChild<QObject *>("pointer-hover"); QVERIFY(handler);
            QCOMPARE(handler->property("cursorShape").toInt(), int(shape));
            const auto position = control->mapToScene(QPointF(control->width()/2, control->height()/2)).toPoint();
            QTest::mouseMove(window, QPoint(3, 3));
            QTest::mouseMove(window, position); QCoreApplication::processEvents();
            if (control->isEnabled()) QTRY_VERIFY(handler->property("hovered").toBool());
            QCOMPARE(window->cursor().shape(), shape);
        };
        hover("import-button", Qt::PointingHandCursor);
        hover("profile-0", Qt::PointingHandCursor);
        hover("status-0", Qt::PointingHandCursor);
        hover("connect-0", Qt::PointingHandCursor);
        bridge->setDemoState("disconnecting");
        hover("connect-0", Qt::ArrowCursor);
        click("settings-button"); hover("launch-tab", Qt::PointingHandCursor);
        hover("boot-profile", Qt::PointingHandCursor);
        click("subscriptions-tab");
        auto *field = item("subscription-name"); QVERIFY(field);
        QVERIFY(!field->findChild<QObject *>("pointer-hover"));
        click("subscription-name");
        QTest::keyClick(window, Qt::Key_C);
        QVERIFY(field->property("text").toString().contains("c"));
        QCOMPARE(window->cursor().shape(), Qt::IBeamCursor);
    }
    void trayStateOwnershipAndHiddenWindow() {
        TrayController tray(bridge.get(), false);
        const auto actions = tray.menu()->actions();
        auto *status = actions.first();
        auto *disconnect = tray.menu()->findChild<QAction *>("tray-disconnect");
        auto *open = tray.menu()->findChild<QAction *>("tray-open");
        QVERIFY(disconnect && open); QVERIFY(!status->isEnabled());
        bridge->setTrayAvailable(true); window->hide();
        const QList<QPair<QString, const char *>> states{{"connected", "Connected"}, {"connecting", "Connecting…"},
            {"reconnecting", "Reconnecting…"}, {"paused_external", "Paused — another VPN provides Internet access"}, {"error", "Connection error"}};
        for (const auto &state : states) {
            bridge->setDemoState(state.first);
            QVERIFY(tray.icon()->toolTip().contains(trayText(state.second)));
            QVERIFY(status->text().contains(bridge->profiles().first().toMap().value("name").toString()));
            QVERIFY(disconnect->isEnabled());
            QVERIFY(!window->isVisible());
        }
        open->trigger(); QTRY_VERIFY(window->isVisible());
        disconnect->trigger();
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), QString());
        QVERIFY(status->text().contains(trayText("Disconnected"))); QVERIFY(!disconnect->isEnabled());
        bridge->setDemoState("connected"); bridge->setDemoState("foreign");
        QCOMPARE(status->text(), trayText("In use by another user"));
        QVERIFY(!tray.icon()->toolTip().contains(bridgeText("Primary"))); QVERIFY(!disconnect->isEnabled());
        bridge->setDemoState("offline");
        QCOMPARE(status->text(), trayText("Service unavailable — VPN state unknown"));
        QVERIFY(!disconnect->isEnabled());
        bridge->setDemoState("connected");
        QVERIFY(!trayPresentation(bridge->snapshot(), true, true).canDisconnect);
    }
    void trayIconSizesAndStateColors() {
        const QStringList states{"disconnected", "connected", "connecting", "reconnecting", "paused_external", "error"};
        const QStringList colors{"#92988f", "#64e875", "#f5ca55", "#f5ca55", "#68acff", "#f06b5f"};
        QImage sheet(360, 40 * states.size(), QImage::Format_ARGB32_Premultiplied); sheet.fill(QColor("#20231f"));
        QPainter painter(&sheet);
        for (int i = 0; i < states.size(); ++i) {
            bridge->setDemoState(states[i]);
            const auto view = trayPresentation(bridge->snapshot(), true, false);
            QCOMPARE(view.color, QColor(colors[i]));
            const auto icon = trayIcon(view.color); QVERIFY(!icon.isNull());
            for (int size : {16, 20, 24, 32, 48, 64}) {
                const auto pixels = icon.pixmap(QSize(size, size), 1.0).toImage();
                QCOMPARE(pixels.size(), QSize(size, size));
                const auto badge = pixels.pixelColor(qRound(size * 0.80), qRound(size * 0.80));
                QVERIFY(qAbs(badge.red() - view.color.red()) < 5 && qAbs(badge.green() - view.color.green()) < 5);
                QVERIFY(pixels.pixelColor(size/2, size/2).alpha() > 0);
            }
            for (int s = 0; s < 4; ++s) {
                const int size = 16 + s * 4;
                painter.drawPixmap(8 + s * 38, i * 40 + 4, icon.pixmap(size, size));
            }
            painter.setPen(view.color); painter.drawText(166, i*40 + 24, states[i]);
        }
        painter.end();
        const auto output = qEnvironmentVariable("VAULT443_TRAY_PREVIEW");
        if (!output.isEmpty()) QVERIFY(sheet.save(output));
    }
    void settingsVersionAndAutomaticVPNTab() {
        const auto original = bridge->snapshot();
        click("settings-button");
        for (const auto &tab : {"launch-tab", "subscriptions-tab", "vpn-tab"}) {
            click(tab);
            auto *version = item("settings-version"); QVERIFY(version && version->isVisible());
            QCOMPARE(version->property("text").toString(), qmlText("Vault 443 · version %1").arg(QCoreApplication::applicationVersion()));
            const auto rect = version->mapRectToScene(version->boundingRect());
            QVERIFY(rect.bottom() <= window->height() && rect.top() > 0);
        }
        QTRY_VERIFY(bridge->vpnCompatibilityActive());
        QTRY_VERIFY(item("vpn-detected-0"));
        QVERIFY(!item("vpn-manager")->isVisible());
        QVERIFY(!bridge->busy()); QCOMPARE(bridge->snapshot(), original);
        bridge->setDemoState("vpn-error");
        QTRY_VERIFY(item("vpn-discovery-status")->property("text").toString() == language->serviceMessage(bridge->vpnCompatibilityError()));
        QVERIFY(bridge->error().isEmpty());
        bridge->setDemoState("vpn-empty");
        QTRY_VERIFY(item("vpn-discovery-status")->property("text").toString() == qmlText("No active external VPNs found. Connect Pritunl, then open this tab."));
        bridge->setDemoState("foreign");
        QTRY_VERIFY(bridge->vpnCompatibility().value("busyByOtherUser").toBool());
        QVERIFY(bridge->vpnCompatibility().value("items").toList().isEmpty());
        click("launch-tab"); QVERIFY(!bridge->vpnCompatibilityActive());
        click("vpn-tab"); window->hide(); QTRY_VERIFY(!bridge->vpnCompatibilityActive());
        bridge->Raise(); QTRY_VERIFY(bridge->vpnCompatibilityActive());
        if (QGuiApplication::platformName() != "offscreen") QTRY_VERIFY(window->isActive());
        QTest::keyClick(window, Qt::Key_Escape); QTRY_VERIFY(!bridge->vpnCompatibilityActive());
    }
    void realDBusPollingDoesNotBlinkOrClosePopup() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && bridge->bootProfiles().size() > 2, 5000);
        fixtureConfigure({{"Pulse", true}, {"SnapshotMS", 250}, {"LogsMS", 400}, {"PrepareMS", 350}});
        click("import-button");
        const QString link = "vless://00000000-0000-4000-8000-000000000121@poll.example:443?security=tls#Polling";
        item("import-text")->setProperty("text", link);
        QSignalSpy preparing(item("import-preparing"), SIGNAL(visibleChanged()));
        QSignalSpy review(item("import-preview"), SIGNAL(enabledChanged()));
        QSignalSpy busy(bridge.get(), &Bridge::busyChanged);
        QTest::qWait(2500);
        QCOMPARE(preparing.count(), 0); QCOMPARE(review.count(), 0); QCOMPARE(busy.count(), 0);
        QVERIFY(!item("import-preparing")->isVisible());
        click("import-preview"); QVERIFY(bridge->importPreparing());
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 3000);
        click("import-icon-0"); click("icon-atom");
        auto *importDialog = window->findChild<QObject *>("import-dialog"); QVERIFY(importDialog);
        const auto choices = importDialog->property("iconChoices").value<QJSValue>().toVariant();
        QTest::qWait(2200);
        QCOMPARE(item("import-text")->property("text").toString(), link);
        QCOMPARE(importDialog->property("iconChoices").value<QJSValue>().toVariant(), choices);
        click("import-cancel");
        click("settings-button");
        auto *field = item("boot-profile");
        field->setProperty("currentIndex", 2);
        QVERIFY(QMetaObject::invokeMethod(field, "activated", Q_ARG(int, 2)));
        const auto chosen = field->property("currentValue");
        click("boot-profile");
        auto *popup = field->property("popup").value<QObject *>(); QVERIFY(popup);
        QTRY_VERIFY(popup->property("visible").toBool());
        QSignalSpy fieldChanges(field, SIGNAL(enabledChanged()));
        QSignalSpy applyChanges(item("boot-apply"), SIGNAL(enabledChanged()));
        QSignalSpy popupChanges(popup, SIGNAL(visibleChanged()));
        QSignalSpy modelChanges(bridge.get(), &Bridge::bootProfilesChanged);
        QSignalSpy snapshots(bridge.get(), &Bridge::snapshotChanged);
        QTest::qWait(15500);
        QVERIFY(snapshots.count() >= 10);
        QCOMPARE(fieldChanges.count(), 0); QCOMPARE(applyChanges.count(), 0);
        QCOMPARE(modelChanges.count(), 0); QCOMPARE(popupChanges.count(), 0);
        QVERIFY(popup->property("visible").toBool()); QCOMPARE(field->property("currentValue"), chosen);
        QTest::keyClick(window, Qt::Key_Escape);
        fixtureConfigure({});
    }
    void realDBusJournalActionsSupersedePolling() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->profiles().isEmpty(), 5000);
        const auto id = bridge->profiles().first().toMap().value("id").toString();
        fixtureControl("FixtureSeedLogs", {id, qint32(500)});
        fixtureConfigure({{"Pulse", true}, {"SnapshotMS", 150}, {"LogsMS", 400}});
        click("profile-0"); click("logs-tab");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->profileLogs().size() == 200, 3000);
        QSignalSpy older(item("logs-older"), SIGNAL(enabledChanged()));
        QSignalSpy latest(item("logs-more"), SIGNAL(enabledChanged()));
        QSignalSpy clear(item("logs-clear"), SIGNAL(enabledChanged()));
        QSignalSpy copy(item("logs-copy"), SIGNAL(enabledChanged()));
        QSignalSpy entries(bridge.get(), &Bridge::profileLogsChanged);
        QTest::qWait(5200);
        QCOMPARE(older.count(), 0); QCOMPARE(latest.count(), 0); QCOMPARE(clear.count(), 0); QCOMPARE(copy.count(), 0);
        QCOMPARE(entries.count(), 0);
        // An old background reply must not overwrite a manual older-page request.
        bridge->loadProfileLogs(id);
        click("logs-older"); QVERIFY(bridge->logActionPending());
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->profileLogs().size() == 400, 3000);
        click("logs-more");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->profileLogs().size() == 200, 3000);
        auto *list = item("profile-logs"); list->setProperty("contentY", 100.0);
        fixtureControl("FixtureAppendLog", {id, "Fresh synthetic entry"});
        bridge->loadProfileLogs(id);
        QTRY_COMPARE_WITH_TIMEOUT(bridge->profileLogs().size(), 201, 3000);
        QTRY_VERIFY(qAbs(list->property("contentY").toDouble() - 100.0) < 2.0);
        // Capture a nonempty response before clearing; delay its delivery.
        fixtureConfigure({{"Pulse", true}, {"LogsMS", 700}});
        bridge->loadProfileLogs(id, true);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending(), 3000);
        fixtureControl("FixtureAppendLog", {id, "Must not reappear after clear"});
        bridge->loadProfileLogs(id);
        QTest::qWait(100);
        click("logs-clear");
        bridge->clearProfileLogs(id); // Duplicate manual click is ignored.
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->profileLogs().isEmpty(), 3000);
        QTest::qWait(1000); QVERIFY(bridge->profileLogs().isEmpty());
        fixtureConfigure({{"LogsMS", 100}, {"FailLogs", true}});
        bridge->loadProfileLogs(id);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logsError().isEmpty(), 2000);
        QVERIFY(bridge->error().isEmpty()); QVERIFY(item("logs-clear")->isEnabled());
        fixtureConfigure({}); bridge->loadProfileLogs(id);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->logsError().isEmpty(), 2000);
        fixtureConfigure({{"LogsMS", 3500}});
        bridge->loadProfileLogs(id, true);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && !bridge->logsError().isEmpty(), 4000);
        QVERIFY(bridge->online()); QVERIFY(item("logs-clear")->isEnabled());
        fixtureConfigure({}); bridge->loadProfileLogs(id, true);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->logsError().isEmpty(), 2000);
        const auto second = bridge->profiles()[1].toMap().value("id").toString();
        fixtureControl("FixtureSeedLogs", {second, qint32(3)});
        fixtureConfigure({{"LogsMS", 500}}); bridge->loadProfileLogs(id);
        QVERIFY(QMetaObject::invokeMethod(window, "showProfile", Q_ARG(QVariant, bridge->profiles()[1])));
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->logActionPending() && bridge->profileLogs().size() == 3, 2000);
        QTest::qWait(700); QCOMPARE(bridge->profileLogs().size(), 3);
        fixtureConfigure({});
    }
    void realDBusScopedRequestsResetAndIgnoreOldReplies() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && bridge->profiles().size() > 2, 5000);
        fixtureConfigure({{"PrepareMS", 800}, {"FailPrepare", true}});
        click("import-button");
        const QString link = "vless://00000000-0000-4000-8000-000000000122@canceled.example:443?security=tls#Canceled";
        item("import-text")->setProperty("text", link); click("import-preview");
        QVERIFY(bridge->importPreparing());
        item("import-text")->setProperty("text", link + "-edited");
        QVERIFY(!bridge->importPreparing());
        QTest::qWait(1000); QVERIFY(bridge->error().isEmpty()); QVERIFY(bridge->preview().isEmpty());
        QCOMPARE(item("import-text")->property("text").toString(), link + "-edited");
        fixtureConfigure({{"PrepareMS", 1000}}); click("import-preview");
        fixtureControl("FixtureRestart");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->importPreparing(), 1500);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online(), 3000);
        QTest::qWait(1100); QVERIFY(bridge->preview().isEmpty());
        QCOMPARE(item("import-text")->property("text").toString(), link + "-edited");
        click("import-cancel");
        fixtureConfigure({{"BootMS", 400}, {"FailBoot", true}});
        click("settings-button");
        auto *field = item("boot-profile"); field->setProperty("currentIndex", 2);
        QVERIFY(QMetaObject::invokeMethod(field, "activated", Q_ARG(int, 2)));
        const auto choice = field->property("selectedProfileId").toString();
        click("boot-apply"); QVERIFY(bridge->bootPending());
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->bootPending() && !bridge->error().isEmpty(), 3000);
        QCOMPARE(field->property("selectedProfileId").toString(), choice);
        bridge->clearError(); QTest::keyClick(window, Qt::Key_Escape);
        fixtureConfigure({{"BootMS", 200}});
        bridge->setBootProfile(choice);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->bootPending() && bridge->snapshot().value("bootProfileId").toString() == choice, 3000);
        fixtureConfigure({});
    }
    void realDBusOpenVPNImportControlAndRoutesWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1" || qEnvironmentVariableIsEmpty("VAULT443_UI_OPENVPN_FILE")
            || qEnvironmentVariableIsEmpty("VAULT443_UI_OPENVPN_BLOCKED_FILE")) QSKIP("Private OpenVPN D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        const auto previousVless = bridge->snapshot().value("activeProfileId").toString();
        const auto primary = bridge->snapshot().value("profiles").toList().first().toMap().value("id").toString();
        bridge->connectProfile(primary);
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("runtime").toMap().value("state").toString(), QString("connected"), 3000);
        const auto originalCount = bridge->profiles().size();
        const auto workCount = bridge->snapshot().value("workProfiles").toList().size();
        auto workProfile = [this](const QString &id) {
            for (const auto &value : bridge->snapshot().value("workProfiles").toList()) if (value.toMap().value("id").toString() == id) return value.toMap();
            return QVariantMap{};
        };
        const QList<QUrl> files{QUrl::fromLocalFile(qEnvironmentVariable("VAULT443_UI_OPENVPN_FILE")), QUrl::fromLocalFile(qEnvironmentVariable("VAULT443_UI_OPENVPN_BLOCKED_FILE"))};
        click("import-button"); bridge->readWorkFiles(files);
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled() && !bridge->busy(), 5000);
        QVERIFY2(bridge->preview().value("errors").toList().isEmpty(), qPrintable(bridge->error()));
        QCOMPARE(bridge->preview().value("profiles").toList().size(), 2);
        click("import-cancel"); QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy(), 3000);
        QCOMPARE(bridge->profiles().size(), originalCount);
        click("import-button"); bridge->readWorkFiles(files);
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled() && !bridge->busy(), 5000);
        const auto prepared = bridge->preview().value("profiles").toList();
        const auto first = prepared[0].toMap().value("id").toString();
        const auto blocked = prepared[1].toMap().value("id").toString();
        click("import-icon-0"); click("icon-atom");
        click("import-icon-1"); click("icon-key");
        click("import-commit");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("workProfiles").toList().size(), workCount+2, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy(), 3000);
        QCOMPARE(workProfile(first).value("iconId").toString(), QString("atom"));
        QCOMPARE(workProfile(blocked).value("iconId").toString(), QString("key"));
        auto *list = item("profile-list"); QVERIFY(list);
        QVERIFY(QMetaObject::invokeMethod(list, "positionViewAtEnd"));
        QTRY_VERIFY(item(QString("connect-%1").arg(originalCount+1)));
        QSignalSpy libraryChanges(bridge.get(), &Bridge::profilesChanged);
        click(QString("connect-%1").arg(originalCount));
        click(QString("connect-%1").arg(originalCount+1));
        QTRY_COMPARE_WITH_TIMEOUT(workProfile(first).value("runtime").toMap().value("state").toString(), QString("connected"), 3000);
        QTRY_COMPARE_WITH_TIMEOUT(workProfile(blocked).value("operation").toMap().value("stage").toString(), QString("resolving_endpoint"), 3000);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), primary);
        QCOMPARE(bridge->snapshot().value("runtime").toMap().value("state").toString(), QString("connected"));
        QTRY_COMPARE_WITH_TIMEOUT(item(QString("connect-%1").arg(originalCount+1))->property("text").toString(), qmlText("Cancel"), 2000);
        QElapsedTimer cancelTime; cancelTime.start();
        click(QString("connect-%1").arg(originalCount+1));
        QTRY_COMPARE_WITH_TIMEOUT(workProfile(blocked).value("runtime").toMap().value("state").toString(), QString("disconnected"), 2500);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->workRequests().contains(blocked), 2500);
        QVERIFY(cancelTime.elapsed() < 2500);
        QCOMPARE(libraryChanges.size(), 0); // Stage updates preserve scroll/focus and card identity.
        QCOMPARE(workProfile(first).value("runtime").toMap().value("state").toString(), QString("connected"));
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), primary);
        QVERIFY(QMetaObject::invokeMethod(window, "openRoutes"));
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->workRoutesPending() && !bridge->workRoutes().isEmpty(), 3000);
        QVERIFY2(bridge->workRoutesError().isEmpty(), qPrintable(bridge->workRoutesError()));
        const auto ruleCount = bridge->workRoutes().value("rules").toList().size();
        item("work-route-destination")->setProperty("text", "192.168.100.15/32");
        item("work-route-target")->setProperty("currentIndex", int(workCount+1));
        click("work-route-save");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->workRoutes().value("rules").toList().size(), ruleCount+1, 3000);
        QCOMPARE(bridge->workRoutes().value("rules").toList().last().toMap().value("target").toString(), first);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->workRoutesPending(), 3000);
        click(QString("work-route-%1").arg(ruleCount)); click("work-route-remove");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->workRoutes().value("rules").toList().size(), ruleCount, 3000);
        item("work-route-kind")->setProperty("currentIndex", 1); QTest::qWait(40);
        item("work-route-destination")->setProperty("text", "corp.example");
        item("work-route-target")->setProperty("currentIndex", int(workCount));
        const auto dnsCount = bridge->workRoutes().value("dnsRules").toList().size();
        click("work-route-save");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->workRoutes().value("dnsRules").toList().size(), dnsCount+1, 3000);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->workRoutesPending(), 3000);
        click(QString("work-route-%1").arg(dnsCount)); click("work-route-remove");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->workRoutes().value("dnsRules").toList().size(), dnsCount, 3000);
        QTest::keyClick(window, Qt::Key_Escape);
        bridge->getDiagnostics(first);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending(), 3000);
        QVERIFY2(bridge->diagnosticsError().isEmpty(), qPrintable(bridge->diagnosticsError()));
        QCOMPARE(bridge->diagnosticData().value("runtime").toMap().value("state").toString(), QString("connected"));
        QVERIFY(!bridge->diagnostics().contains("PRIVATE KEY"));
        bridge->loadProfileLogs(first, true); QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy(), 3000);
        bridge->disconnectWorkProfile(first);
        QTRY_COMPARE_WITH_TIMEOUT(workProfile(first).value("runtime").toMap().value("state").toString(), QString("disconnected"), 3000);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->workRequests().isEmpty(), 3000);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), primary);
        bridge->removeProfile(first); bridge->removeProfile(blocked);
        QTRY_COMPARE_WITH_TIMEOUT(bridge->profiles().size(), originalCount, 3000);
        if (previousVless.isEmpty()) bridge->disconnectProfile(); else if (previousVless != primary) bridge->connectProfile(previousVless);
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("activeProfileId").toString(), previousVless, 3000);
        QVERIFY2(bridge->error().isEmpty(), qPrintable(bridge->error()));
    }
    void realDBusWireGuardAndAmneziaImportWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1" || qEnvironmentVariableIsEmpty("DBUS_SYSTEM_BUS_ADDRESS"))
            QSKIP("Opt-in private test D-Bus fixture is not running");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        const auto count = bridge->snapshot().value("workProfiles").toList().size();
        const auto previousVless = bridge->snapshot().value("activeProfileId").toString();
        const auto native = wireGuardFixture(true);
        const QJsonObject last{{"config", native}};
        const QJsonObject container{{"container", "amnezia-awg"}, {"awg", QJsonObject{{"last_config", QString::fromUtf8(QJsonDocument(last).toJson(QJsonDocument::Compact))}}}};
        const QJsonObject key{{"description", "Synthetic East"}, {"containers", QJsonArray{container}}};
        const auto encoded = "vpn://" + QString::fromLatin1(qCompress(QJsonDocument(key).toJson(QJsonDocument::Compact)).toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
        QTemporaryDir files; QVERIFY(files.isValid());
        QList<QUrl> urls;
        for (const auto &entry : {QPair<QString, QString>{"West.conf", wireGuardFixture()}, {"East.vpn", encoded}}) {
            QFile file(files.filePath(entry.first)); QVERIFY(file.open(QIODevice::WriteOnly));
            QCOMPARE(file.write(entry.second.toUtf8()), entry.second.toUtf8().size()); file.close();
            urls.append(QUrl::fromLocalFile(file.fileName()));
        }
        click("import-button"); bridge->readWorkFiles(urls);
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 3000);
        auto entries = bridge->preview().value("profiles").toList();
        QCOMPARE(entries.size(), 2);
        QCOMPARE(entries[0].toMap().value("kind").toString(), QString("wireguard"));
        QCOMPARE(entries[1].toMap().value("kind").toString(), QString("amneziawg"));
        const auto wg = entries[0].toMap().value("id").toString();
        const auto awg = entries[1].toMap().value("id").toString();
        const auto previewJSON = QJsonDocument(QJsonObject::fromVariantMap(bridge->preview())).toJson();
        QVERIFY(!previewJSON.contains(QByteArray(32, 'k').toBase64()));
        QVERIFY(!previewJSON.contains(QByteArray(32, 's').toBase64()));
        const auto preview = bridge->preview();
        language->setPreference("ru"); QCoreApplication::processEvents();
        QCOMPARE(bridge->preview(), preview);
        click("import-cancel");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy(), 3000);
        QCOMPARE(bridge->snapshot().value("workProfiles").toList().size(), count);
        click("import-button"); bridge->readWorkFiles(urls);
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 3000);
        bridge->commitImport({{wg, "shield"}, {awg, "vault-door"}});
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("workProfiles").toList().size(), count + 2, 3000);
        auto profile = [this](const QString &id) {
            for (const auto &value : bridge->snapshot().value("workProfiles").toList()) if (value.toMap().value("id").toString() == id) return value.toMap();
            return QVariantMap{};
        };
        QCOMPARE(profile(awg).value("iconId").toString(), QString("vault-door"));
        bridge->connectWorkProfile(wg); bridge->connectWorkProfile(awg);
        QTRY_COMPARE_WITH_TIMEOUT(profile(wg).value("runtime").toMap().value("state").toString(), QString("connected"), 3000);
        QTRY_COMPARE_WITH_TIMEOUT(profile(awg).value("runtime").toMap().value("state").toString(), QString("connected"), 3000);
        QCOMPARE(bridge->snapshot().value("activeProfileId").toString(), previousVless);
        bridge->getDiagnostics(awg);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending(), 3000);
        QVERIFY(bridge->diagnosticsError().isEmpty());
        QVERIFY(!bridge->diagnostics().contains(QString::fromLatin1(QByteArray(32, 'k').toBase64())));
        bridge->updateProfile(wg, "Renamed West", "atom");
        QTRY_COMPARE_WITH_TIMEOUT(profile(wg).value("name").toString(), QString("Renamed West"), 3000);
        bridge->setProfileDebug(awg, true);
        QTRY_VERIFY_WITH_TIMEOUT(profile(awg).value("debugLogging").toBool(), 3000);
        bridge->disconnectWorkProfile(wg);
        QTRY_COMPARE_WITH_TIMEOUT(profile(wg).value("runtime").toMap().value("state").toString(), QString("disconnected"), 3000);
        QCOMPARE(profile(awg).value("runtime").toMap().value("state").toString(), QString("connected"));
        bridge->disconnectWorkProfile(awg);
        QTRY_COMPARE_WITH_TIMEOUT(profile(awg).value("runtime").toMap().value("state").toString(), QString("disconnected"), 3000);
        click("import-button");
        item("import-text")->setProperty("text", encoded); click("import-preview");
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 3000);
        QVERIFY(bridge->preview().value("profiles").toList()[0].toMap().value("duplicate").toBool());
        click("import-cancel");
        bridge->removeProfile(wg); bridge->removeProfile(awg);
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("workProfiles").toList().size(), count, 3000);
        QVERIFY2(bridge->error().isEmpty(), qPrintable(bridge->error()));
    }
    void realDBusLanguageSwitchPreservesDraftWithoutMutations() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1" || qEnvironmentVariableIsEmpty("DBUS_SYSTEM_BUS_ADDRESS"))
            QSKIP("Opt-in private test D-Bus fixture is not running");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        click("import-button");
        const QString link = "vless://00000000-0000-4000-8000-000000000086@switch.example:443?security=tls#Private%20draft";
        item("import-text")->setProperty("text", link);
        click("import-preview");
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 3000);
        const auto preview = bridge->preview();
        const auto snapshot = bridge->snapshot();
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        QSignalSpy busy(bridge.get(), &Bridge::busyChanged);
        for (const auto &locale : {"en", "ru", "system"}) {
            language->setPreference(locale); QCoreApplication::processEvents();
            QCOMPARE(item("import-text")->property("text").toString(), link);
            QCOMPARE(bridge->preview(), preview); QCOMPARE(bridge->snapshot(), snapshot);
            QVERIFY(item("import-commit")->isEnabled());
            QCOMPARE(operations.size(), 0); QCOMPARE(busy.size(), 0);
        }
        click("import-cancel");
        QTRY_VERIFY(!bridge->busy());
        QCOMPARE(bridge->snapshot(), snapshot);
    }
    void realDBusCompatibilityWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        const auto original = bridge->snapshot();
        QSignalSpy busy(bridge.get(), &Bridge::busyChanged);
        click("settings-button"); click("vpn-tab");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->vpnCompatibility().isEmpty(), 6000);
        QVERIFY2(bridge->vpnCompatibilityError().isEmpty(), qPrintable(bridge->vpnCompatibilityError()));
        QCOMPARE(bridge->snapshot(), original); QCOMPARE(busy.size(), 0);
        QVERIFY(!bridge->vpnCompatibility().value("items").toList().isEmpty());
        QSignalSpy refreshed(bridge.get(), &Bridge::vpnCompatibilityChanged);
        for (int i = 0; i < 20; ++i) bridge->refreshVPNCompatibility();
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->vpnCompatibilityPending(), 6000);
        QCOMPARE(refreshed.size(), 2); // One request start and one reply, despite 20 calls.
        QCOMPARE(busy.size(), 0); QCOMPARE(bridge->snapshot(), original);
        QTest::keyClick(window, Qt::Key_Escape); QVERIFY(!bridge->vpnCompatibilityActive());
        QVERIFY(bridge->error().isEmpty());
    }
    void realDBusResponsiveConnectionWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        bridge->disconnectProfile();
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->networkBusy() && bridge->snapshot().value("activeProfileId").toString().isEmpty(), 2000);
        const int previous = bridge->profiles().size();
        importProfiles(bridge.get(), "vless://00000000-0000-4000-8000-000000000071@blocked.example:443?security=tls#Blocked\nvless://00000000-0000-4000-8000-000000000072@failed.example:443?security=tls#Failed");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->profiles().size(), previous+2, 3000);
        const auto blocked = bridge->profiles()[previous].toMap().value("id").toString();
        const auto failed = bridge->profiles()[previous+1].toMap().value("id").toString();
        auto *list = item("profile-list"); QVERIFY(list);
        QVERIFY(QMetaObject::invokeMethod(list, "positionViewAtEnd"));
        QTRY_VERIFY(item(QString("connect-%1").arg(previous)));
        QElapsedTimer timer; timer.start();
        click(QString("connect-%1").arg(previous));
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("operation").toMap().value("stage").toString(), QString("resolving_endpoint"), 1500);
        QVERIFY(timer.elapsed() < 1500);
        QCOMPARE(item(QString("connect-%1").arg(previous))->property("text").toString(), qmlText("Cancel"));
        QVERIFY(bridge->error().isEmpty());
        timer.restart();
        bridge->getDiagnostics(blocked);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending() && !bridge->diagnosticData().isEmpty(), 1500);
        QVERIFY(timer.elapsed() < 1500);
        QVERIFY(bridge->diagnosticsError().isEmpty());
        QVERIFY(bridge->diagnostics().contains("resolving_endpoint"));
        timer.restart();
        click(QString("connect-%1").arg(previous));
        QTRY_VERIFY_WITH_TIMEOUT(bridge->snapshot().value("activeProfileId").toString().isEmpty(), 1500);
        QVERIFY(timer.elapsed() < 1500);
        click(QString("connect-%1").arg(previous+1));
        QTRY_COMPARE_WITH_TIMEOUT(bridge->snapshot().value("operation").toMap().value("stage").toString(), QString("retry_wait"), 1500);
        QVERIFY(!bridge->snapshot().value("lastFailure").toMap().value("message").toString().isEmpty());
        QVERIFY(item(QString("status-%1").arg(previous+1))->property("text").toString().contains(qmlText("%1\nRetry in %2 s").section('\n', 1).section("%2", 0, 0)));
        QCOMPARE(item(QString("connect-%1").arg(previous+1))->property("text").toString(), qmlText("Disconnect"));
        const auto failure = bridge->snapshot().value("lastFailure");
        click(QString("connect-%1").arg(previous+1));
        QTRY_VERIFY_WITH_TIMEOUT(bridge->snapshot().value("activeProfileId").toString().isEmpty(), 1500);
        QCOMPARE(bridge->snapshot().value("lastFailure"), failure);
        bridge->getDiagnostics(failed);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending(), 1500);
        QCOMPARE(bridge->diagnosticData().value("lastFailure"), failure);
        QVERIFY(bridge->error().isEmpty());
        // Waiting past the first retry must not restart a canceled connection.
        QTest::qWait(1200); bridge->refresh();
        QTRY_VERIFY(!bridge->busy());
        QVERIFY(bridge->snapshot().value("activeProfileId").toString().isEmpty());
    }
    void realDBusDiagnosticsDeadlineWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1") QSKIP("Private D-Bus fixture required");
        cleanup(); loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        const auto previous = bridge->profiles().size();
        importProfiles(bridge.get(), "vless://00000000-0000-4000-8000-000000000073@slowdiagnostics.example:443?security=tls#SlowDiagnostics");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->profiles().size(), previous+1, 3000);
        const auto id = bridge->profiles().last().toMap().value("id").toString();
        QSignalSpy changes(bridge.get(), &Bridge::diagnosticsChanged);
        QElapsedTimer timer; timer.start();
        for (int i=0; i<20; ++i) bridge->getDiagnostics(id);
        QVERIFY(bridge->diagnosticsPending());
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending(), 4000);
        QVERIFY(timer.elapsed() < 4000);
        QVERIFY(bridge->diagnosticsError().contains("3 s"));
        QVERIFY(bridge->diagnostics().contains("lastSnapshot"));
        QVERIFY(bridge->diagnostics().contains("snapshotReceivedAt"));
        QCOMPARE(changes.size(), 2); // Only start and timeout, with no parallel requests.
        const auto cached = bridge->diagnostics();
        QTest::qWait(2300); // The late five-second reply cannot overwrite the timeout.
        QCOMPARE(bridge->diagnostics(), cached); QCOMPARE(changes.size(), 2);
        QVERIFY(bridge->error().isEmpty());
        // Switching profiles supersedes the outstanding query instead of showing
        // A's technical summary under B's title. The late A response is discarded.
        bridge->getDiagnostics(id);
        QVERIFY(bridge->diagnosticsPending());
        bridge->getDiagnostics(bridge->profiles().first().toMap().value("id").toString());
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->diagnosticsPending() && bridge->diagnosticsError().isEmpty(), 1500);
        const auto switched = bridge->diagnostics();
        QTest::qWait(3300);
        QCOMPARE(bridge->diagnostics(), switched);
        QVERIFY(bridge->diagnosticsError().isEmpty()); QVERIFY(bridge->error().isEmpty());
    }
    void realDBusImportDialogWhenFixtureAvailable_data() {
        QTest::addColumn<bool>("fromFile");
        QTest::newRow("pasted-link") << false;
        QTest::newRow("local-file") << true;
    }
    void realDBusImportDialogWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1" || qEnvironmentVariableIsEmpty("DBUS_SYSTEM_BUS_ADDRESS")) QSKIP("Opt-in private test D-Bus fixture is not running");
        QFETCH(bool, fromFile);
        cleanup();
        loadWindow(false);
        QTRY_VERIFY_WITH_TIMEOUT(bridge->online() && !bridge->busy(), 5000);
        const auto previousCount = bridge->profiles().size();
        const QString link = QString("vless://00000000-0000-4000-8000-000000000056@%1.example:443?security=tls#Dialog").arg(fromFile ? "file" : "pasted");
        QTemporaryFile file;
        QVERIFY(file.open());
        QCOMPARE(file.write(link.toUtf8()), link.toUtf8().size());
        QVERIFY(file.flush());

        click("import-button");
        if (fromFile) bridge->readImportFile(QUrl::fromLocalFile(file.fileName()));
        else item("import-text")->setProperty("text", link);
        click("import-preview");
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 5000);
        click("import-icon-0"); click("icon-atom");
        QSignalSpy operations(bridge.get(), &Bridge::operationDone);
        QStringList failures;
        QObject scope;
        connect(bridge.get(), &Bridge::errorChanged, &scope, [&] {
            if (!bridge->error().isEmpty()) failures.append(bridge->error());
        });
        click("import-commit");
        QTRY_COMPARE_WITH_TIMEOUT(bridge->profiles().size(), previousCount + 1, 5000);
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy() && (!item("import-text") || !item("import-text")->isVisible()), 5000);
        QVERIFY2(failures.isEmpty(), qPrintable(failures.join("\n")));
        QVERIFY(bridge->preview().isEmpty());
        QCOMPARE(bridge->profiles().last().toMap().value("iconId").toString(), QString("atom"));
        for (const auto &operation : operations) QVERIFY(operation[0].toString() != "CancelImport");

        // Closing a fresh preview still cancels it, without changing saved profiles.
        click("import-button");
        item("import-text")->setProperty("text", link);
        click("import-preview");
        QTRY_VERIFY_WITH_TIMEOUT(item("import-commit")->isEnabled(), 5000);
        operations.clear();
        click("import-cancel");
        QTRY_VERIFY_WITH_TIMEOUT(!bridge->busy() && (!item("import-text") || !item("import-text")->isVisible()), 5000);
        bool cancelled = false;
        for (const auto &operation : operations) if (operation[0].toString() == "CancelImport") cancelled = true;
        QVERIFY(cancelled);
        QCOMPARE(bridge->profiles().size(), previousCount + 1);
        QVERIFY2(failures.isEmpty(), qPrintable(failures.join("\n")));
    }
    void realDBusRoundTripWhenFixtureAvailable() {
        if (qEnvironmentVariable("VAULT443_UI_PRIVATE_BUS_TEST") != "1" || qEnvironmentVariableIsEmpty("DBUS_SYSTEM_BUS_ADDRESS")) QSKIP("Opt-in private test D-Bus fixture is not running");
        Bridge live(false);
        QSignalSpy errors(&live, &Bridge::errorChanged);
        QTRY_VERIFY_WITH_TIMEOUT(live.online(), 5000);
        QTRY_VERIFY_WITH_TIMEOUT(live.snapshot().value("profiles").toList().size() >= 3, 5000);
        const auto id = live.snapshot().value("profiles").toList().first().toMap().value("id").toString();
        live.connectProfile(id);
        QTRY_COMPARE_WITH_TIMEOUT(live.snapshot().value("activeProfileId").toString(), id, 5000);
        live.updateProfile(id, "Qt D-Bus integration", "antenna");
        QTRY_COMPARE_WITH_TIMEOUT(live.snapshot().value("profiles").toList().first().toMap().value("name").toString(), QString("Qt D-Bus integration"), 5000);
        live.updateProfile(id, "Qt D-Bus integration", "radiation");
        QTRY_COMPARE_WITH_TIMEOUT(live.snapshot().value("profiles").toList().first().toMap().value("iconId").toString(), QString("radiation"), 5000);
        live.setProfileDebug(id, true);
        QTRY_VERIFY_WITH_TIMEOUT(live.snapshot().value("profiles").toList().first().toMap().value("debugLogging").toBool(), 5000);
        live.prepareImport("vless://00000000-0000-4000-8000-000000000055@qt.example:443?security=tls#QtDraft", "text", "");
        QTRY_VERIFY_WITH_TIMEOUT(!live.preview().value("draftId").toString().isEmpty(), 5000);
        const auto importedId = live.preview().value("profiles").toList().first().toMap().value("id").toString();
        const auto previousCount = live.profiles().size();
        const auto draftId = live.preview().value("draftId").toString();
        live.commitImport({{importedId, "invalid-icon"}});
        QTRY_VERIFY_WITH_TIMEOUT(!live.busy() && !live.error().isEmpty(), 5000);
        QCOMPARE(live.preview().value("draftId").toString(), draftId);
        QCOMPARE(live.profiles().size(), previousCount);
        live.commitImport({{importedId, "atom"}});
        QTRY_COMPARE_WITH_TIMEOUT(live.profiles().size(), previousCount + 1, 5000);
        QVERIFY(live.preview().isEmpty());
        QCOMPARE(live.profiles().last().toMap().value("iconId").toString(), QString("atom"));
        live.loadProfileLogs(id, true);
        QTRY_VERIFY_WITH_TIMEOUT(!live.busy(), 5000);
        live.getDiagnostics();
        QTRY_VERIFY_WITH_TIMEOUT(!live.diagnostics().isEmpty(), 5000);
        live.disconnectProfile();
        QTRY_VERIFY_WITH_TIMEOUT(live.snapshot().value("activeProfileId").toString().isEmpty(), 5000);
        QVERIFY2(live.error().isEmpty(), qPrintable(live.error()));
    }
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    QTemporaryDir settingsDirectory;
    if (!settingsDirectory.isValid()) return 2;
    QCoreApplication::setOrganizationName("Vault443Tests");
    QCoreApplication::setApplicationName("vault443-ui-tests");
    QSettings::setDefaultFormat(QSettings::IniFormat);
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDirectory.path());
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, settingsDirectory.path());
    QStandardPaths::setTestModeEnabled(true);
    app.setApplicationVersion(VAULT443_APP_VERSION);
    QQuickStyle::setStyle("Basic");
    GuiTests tests;
    return QTest::qExec(&tests, argc, argv);
}
#include "ui_tests.moc"
