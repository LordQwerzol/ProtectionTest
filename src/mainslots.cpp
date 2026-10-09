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

void MainWindow::checkInternet()
{
    setCardState(ui->cardNet, ui->statusNet, "run", "Проверка…");

    auto *sock  = new QTcpSocket(this);
    auto *timer = new QTimer(sock);
    timer->setSingleShot(true);

    // лямба-выражение для сокета
    auto finish = [this, sock, timer](bool ok, const QString &details) 
    {
        if (sock->property("done").toBool())
            return;
        sock->setProperty("done", true);
        timer->stop();
        sock->abort();

        setCardState(ui->cardNet, ui->statusNet, ok ? "ok" : "bad", ok ? "В норме" : "Проблема");
        ui->descNet->setText(details);
        m_results["Подключение к Интернету"] = ok;
        addLog("Подключение к Интернету: " + details);
        onCheckFinished();

        sock->deleteLater();
    };

    connect(sock, &QTcpSocket::connected, this, [finish] {
        finish(true, "Соединение с 77.88.8.8:53 установлено");
    });
    connect(sock, &QTcpSocket::errorOccurred, this, [finish, sock] {
        finish(false, "Ошибка: " + sock->errorString());
    });
    connect(timer, &QTimer::timeout, this, [finish] {
        finish(false, "Нет ответа за 3 секунды");
    });

    timer->start(3000);
    sock->connectToHost("77.88.8.8", 53);
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
    const FirewallEnforcement fe = queryFirewallEnforcement();

    QStringList problems;
    if (!fe.queried)                 problems << "нет доступа к настройкам брандмауэра";
    if (!fe.serviceRunning)          problems << "служба брандмауэра (mpssvc) остановлена";
    if (!fe.bfeRunning)              problems << "служба фильтрации (BFE) остановлена";
    if (!fe.inboundBlockedByDefault) problems << "входящие соединения по умолчанию разрешены";

    const bool ok = problems.isEmpty();
    setCardState(ui->cardFwWorking, ui->statusFwWorking, ok ? "ok" : "bad", ok ? "В норме" : "Проблема");
    ui->descFwWorking->setText(ok ? "Фильтрация активна, входящие блокируются" : problems.first());

    m_results["Работа МЭ"] = ok;
    addLog("Работа МЭ: " + (ok ? QString("службы запущены, входящие по умолчанию блокируются")
                               : problems.join("; ")));
    onCheckFinished();
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