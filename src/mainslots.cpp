#include "mainwindow.h"
#include "ui_mainwindow.h"

#include "securitycenter.h"
#include "util.h"

#include <QProcess>
#include <QTcpSocket>
#include <QTimer>

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
        updateSummary();

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
    updateSummary();
}

void MainWindow::checkAntivirusInstalled()
{
    const SecurityCenterResult sc = querySecurityCenter(ProductKind::AntiVirus);

    if (!sc.available) {
        setCardState(ui->cardAvInstalled, ui->statusAvInstalled, "bad", "Проблема");
        ui->descAvInstalled->setText("Не удалось опросить Центр безопасности");
        m_results["Наличие антивируса"] = false;
        addLog("Наличие антивируса: " + sc.error);
        updateSummary();
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
    updateSummary();
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
    updateSummary();
}