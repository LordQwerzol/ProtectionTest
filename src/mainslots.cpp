#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "securitycenter.h"
#include "util.h"

#include <QProcess>
#include <QTcpSocket>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QTimer>
#include <algorithm>
#include <memory>

// Строка EICAR хранится задом наперёд, чтобы антивирус не принял
// за вирус сам ProtectionTest.exe. Разворачивается только в момент теста.
static QByteArray eicarTestString()
{
    QByteArray s("*H+H$!ELIF-TSET-SURIVITNA-DRADNATS-RACIE$}7)CC7)^P(45XZP\\4[PA@%P!O5X");
    std::reverse(s.begin(), s.end());
    return s;
}

// Асинхронная попытка TCP-подключения с таймаутом
void MainWindow::probeTcp(const QString &host, quint16 port, int timeoutMs,
                          std::function<void(bool, const QString &)> done)
{
    auto *sock  = new QTcpSocket(this);
    auto *timer = new QTimer(sock);
    timer->setSingleShot(true);

    auto finish = [sock, timer, done](bool ok, const QString &details) {
        if (sock->property("done").toBool()) return;
        sock->setProperty("done", true);
        timer->stop();
        sock->abort();
        sock->deleteLater();
        done(ok, details);
    };

    connect(sock, &QTcpSocket::connected, this, [finish] { finish(true, "соединение установлено"); });
    connect(sock, &QTcpSocket::errorOccurred, this, [finish, sock] { finish(false, sock->errorString()); });
    connect(timer, &QTimer::timeout, this, [finish] { finish(false, "нет ответа"); });

    timer->start(timeoutMs);
    sock->connectToHost(host, port);
}

void MainWindow::checkInternet()
{
    const QString host = "77.88.8.8";
    const quint16 port = 53;
    const int timeoutMs = 3000;
    const QString target = QString("%1:%2").arg(host).arg(port);

    setCardState(ui->cardNet, ui->statusNet, "run", "Проверка…");

    probeTcp(host, port, timeoutMs, [=](bool ok, const QString &details) {
        const QString text = ok ? "Соединение с " + target + " установлено"
                                : "Нет соединения с " + target + ": " + details;

        setCardState(ui->cardNet, ui->statusNet, ok ? "ok" : "bad", ok ? "В норме" : "Проблема");
        ui->descNet->setText(text);
        m_results["Подключение к Интернету"] = ok;
        addLog("Подключение к Интернету: " + text);
        onCheckFinished();
    });
}

void MainWindow::checkFirewallInstalled()
{
    setCardState(ui->cardFwInstalled, ui->statusFwInstalled, "run", "Проверка…");
    QStringList found;
    bool protectedNow = false;

    // 1. Сторонние межсетевые экраны из Центра безопасности
    const SecurityCenterResult sc = querySecurityCenter(ProductKind::Firewall);
    if (sc.available) {
        for (const SecurityProduct &p : sc.products) {
            found << describeProduct(p, ProductKind::Firewall);
            if (p.enabled) protectedNow = true;
        }
    } else {
        addLog("Центр безопасности: " + sc.error);
    }

    // 2. Встроенный брандмауэр Windows
    const FirewallStatus wf = queryWindowsFirewall();
    if (wf.queried) {
        bool activeOn = true;
        if ((wf.activeProfiles & NET_FW_PROFILE2_DOMAIN)  && !wf.domain)     activeOn = false;
        if ((wf.activeProfiles & NET_FW_PROFILE2_PRIVATE) && !wf.privateNet) activeOn = false;
        if ((wf.activeProfiles & NET_FW_PROFILE2_PUBLIC)  && !wf.publicNet)  activeOn = false;

        found << QString("Брандмауэр Windows (%1)").arg(activeOn ? "вкл." : "выкл.");
        if (activeOn) protectedNow = true;
    }

    // 3. Итог
    if (protectedNow) {
        setCardState(ui->cardFwInstalled, ui->statusFwInstalled, "ok", "В норме");
        ui->descFwInstalled->setText(found.join(", "));
    } else {
        setCardState(ui->cardFwInstalled, ui->statusFwInstalled, "bad", "Проблема");
        ui->descFwInstalled->setText(found.isEmpty() ? "Межсетевой экран не найден"
                                                     : "Ни один межсетевой экран не включён");
    }

    m_results["Наличие МЭ"] = protectedNow;
    addLog("Наличие МЭ: " + (found.isEmpty() ? QString("не найден") : found.join("; ")));
    onCheckFinished();
}

void MainWindow::checkAntivirusInstalled()
{
    const SecurityCenterResult sc = querySecurityCenter(ProductKind::AntiVirus);

    if (!sc.available) {
        setCardState(ui->cardAvInstalled, ui->statusAvInstalled, "bad", "Проблема");
        ui->descAvInstalled->setText("Не удалось опросить Центр безопасности");
        m_results["Наличие антивируса"] = false;
        addLog("Наличие антивируса: " + sc.error);
        onCheckFinished();
        return;
    }

    QStringList names;
    bool outdated = false;
    for (const SecurityProduct &p : sc.products) {
        names << describeProduct(p, ProductKind::AntiVirus);
        if (p.enabled && !p.upToDate) outdated = true;
    }

    const bool ok = sc.hasEnabled();
    setCardState(ui->cardAvInstalled, ui->statusAvInstalled,
                 ok ? "ok" : "bad", ok ? "В норме" : "Проблема");
    ui->descAvInstalled->setText(sc.products.isEmpty() ? "Антивирус не найден"
                                                       : names.join(", "));

    m_results["Наличие антивируса"] = ok;
    addLog("Наличие антивируса: " + (names.isEmpty() ? QString("не найден") : names.join("; ")));
    if (outdated)
        addLog("Рекомендация: обновите антивирусные базы");
    onCheckFinished();
}

void MainWindow::checkFirewallWorking()
{
    auto finishCard = [this](const QString &state, const QString &pill,
                             const QString &desc, const QString &log, bool count, bool ok) {
        setCardState(ui->cardFwWorking, ui->statusFwWorking, state, pill);
        ui->descFwWorking->setText(desc);
        addLog("Работа МЭ: " + log);
        if (count) m_results["Работа МЭ"] = ok;
        onCheckFinished();
    };

    setCardState(ui->cardFwWorking, ui->statusFwWorking, "run", "Проверка…");

    // 1. Читаем заранее созданное правило (только чтение)
    const TestRuleInfo rule = queryTestRule();
    if (!rule.found) {
        finishCard("bad", "Нет правила", "Тестовое правило «ProtectionTest Block» не найдено",
                   rule.error, true, false);
        return;
    }
    if (!rule.outbound || !rule.block || rule.remoteAddress.isEmpty() || rule.remotePort == 0) {
        finishCard("bad", "Ошибка", "Правило настроено неверно",
                   "правило должно быть исходящим, блокирующим, с одним адресом и портом",
                   true, false);
        return;
    }

    const QString target = QString("%1:%2").arg(rule.remoteAddress).arg(rule.remotePort);
    addLog(QString("Работа МЭ: правило найдено (%1), цель %2")
               .arg(rule.enabled ? "включено" : "выключено", target));

    // 2. Попытка подключиться к запрещённому узлу
    probeTcp(rule.remoteAddress, rule.remotePort, 3000,
             [=](bool connected, const QString &details) {
        if (rule.enabled && !connected)
            finishCard("ok", "В норме", "Соединение с " + target + " заблокировано правилом",
                       "ограничение действует, соединение заблокировано (" + details + ")",
                       true, true);
        else if (rule.enabled && connected)
            finishCard("bad", "Проблема", "Правило включено, но соединение прошло",
                       "МЭ не применяет правило: соединение с " + target + " установлено",
                       true, false);
        else if (!rule.enabled && connected)
            finishCard("bad", "Правило выкл.", "Ограничение не действует: правило отключено",
                       "правило отключено, соединение с " + target + " установлено",
                       true, false);
        else
            finishCard("none", "Неясно", "Узел недоступен даже без правила",
                       "правило отключено, но соединение не установлено (" + details +
                       ") — проверьте Интернет", false, false);
    });
}

void MainWindow::checkAntivirusWorking()
{
    const int timeoutMs = 15000;
    const QString path = QDir(QDir::tempPath()).filePath("protectiontest_eicar.com");
    const QByteArray eicar = eicarTestString();

    auto finish = [this](bool ok, const QString &desc, const QString &log) {
        setCardState(ui->cardAvWorking, ui->statusAvWorking, ok ? "ok" : "bad",
                     ok ? "В норме" : "Проблема");
        ui->descAvWorking->setText(desc);
        m_results["Работа антивируса"] = ok;
        addLog("Работа антивируса: " + log);
        if (!ok)
            addLog("Рекомендация: включите защиту файлов в реальном времени в настройках антивируса");
        onCheckFinished();
        ui->btnCheckAvWorking->setEnabled(true);
    };

    setCardState(ui->cardAvWorking, ui->statusAvWorking, "run", "Проверка…");
    ui->btnCheckAvWorking->setEnabled(false);
    QFile::remove(path);   // на случай, если файл остался от прошлого запуска

    // Шаг 1–2: запись тестового файла
    {
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly) || f.write(eicar) != eicar.size()) {
            finish(true, "Запись тестового файла заблокирована",
                   "антивирус заблокировал запись EICAR (" + f.errorString() + ")");
            return;
        }
    }   // здесь файл закрывается — многие антивирусы проверяют его именно в этот момент

    addLog("Работа антивируса: тестовый файл EICAR создан, ожидание реакции…");

    // Шаг 3: наблюдение за файлом
    auto elapsed = std::make_shared<QElapsedTimer>();
    elapsed->start();
    auto *timer = new QTimer(this);

    connect(timer, &QTimer::timeout, this, [=] {
        bool reacted = false;
        QString how;

        if (!QFileInfo::exists(path)) {
            reacted = true;
            how = "файл удалён или помещён в карантин";
        } else {
            QFile r(path);
            if (!r.open(QIODevice::ReadOnly)) {
                reacted = true;
                how = "доступ к файлу заблокирован";
            } else if (r.readAll() != eicar) {
                reacted = true;
                how = "содержимое файла изменено (вылечен)";
            }
        }

        const double sec = elapsed->elapsed() / 1000.0;

        if (reacted) {
            timer->stop();
            timer->deleteLater();
            QFile::remove(path);
            finish(true, QString("Угроза обнаружена за %1 с").arg(sec, 0, 'f', 1),
                   QString("%1 через %2 с").arg(how).arg(sec, 0, 'f', 1));
        } else if (elapsed->elapsed() >= timeoutMs) {
            // Шаг 4: антивирус не отреагировал
            timer->stop();
            timer->deleteLater();
            QFile::remove(path);
            finish(false, QString("Файл EICAR не обнаружен за %1 с").arg(timeoutMs / 1000),
                   QString("антивирус не отреагировал на EICAR за %1 с").arg(timeoutMs / 1000));
        }
    });

    timer->start(500);
}