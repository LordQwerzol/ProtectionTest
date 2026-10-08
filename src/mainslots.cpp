#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QProcess>
#include <QTcpSocket>
#include <QTimer>

void MainWindow::checkInternet()
{
    setCardState(ui->cardNet, ui->statusNet, "run", "Проверка…");
    ui->btnCheckNet->setEnabled(false);

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

        ui->btnCheckNet->setEnabled(true);
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