#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QStyle>
#include <QTime>
#include <QTimer>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->navOverview, &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(0); });
    connect(ui->navLog,      &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(1); });
    connect(ui->navReport,   &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(2); });
    connect(ui->btnCheckNet, &QPushButton::clicked, this, &MainWindow::checkInternet);
    connect(ui->btnCheckFwInstalled, &QPushButton::clicked, this, &MainWindow::checkFirewallInstalled);
    connect(ui->btnCheckAvInstalled, &QPushButton::clicked, this, &MainWindow::checkAntivirusInstalled);
    connect(ui->btnCheckFwWorking, &QPushButton::clicked, this, &MainWindow::checkFirewallWorking);
    connect(ui->btnCheckAvWorking, &QPushButton::clicked, this, &MainWindow::checkAntivirusWorking);
    connect(ui->btnRunAll,      &QPushButton::clicked, this, &MainWindow::runAllChecks);
    connect(ui->btnBuildReport, &QPushButton::clicked, this, &MainWindow::buildReport);
    connect(ui->btnSaveReport,  &QPushButton::clicked, this, &MainWindow::saveReport);

    ui->reportView->setStyleSheet("font-family: \"Segoe UI\"; font-size: 10pt;");
}

MainWindow::~MainWindow()
{
    delete ui;
}

// Логирование в журнал
void MainWindow::addLog(const QString &message)
{
    const QString line = QTime::currentTime().toString("hh:mm:ss") + "  " + message;
    ui->logText->appendPlainText(line);
}

// Обновление главнного счетчика
void MainWindow::updateSummary()
{
    const int total = 5;
    int okCount = 0;
    for (bool ok : m_results)
        if (ok) ++okCount;
    const int badCount = m_results.size() - okCount;

    ui->scoreLabel->setText(QString("%1/%2").arg(okCount).arg(total));
    ui->scoreLabel->setProperty("state", badCount > 0 ? "bad"
                                       : m_results.size() == total ? "ok" : "none");
    ui->scoreLabel->style()->unpolish(ui->scoreLabel);
    ui->scoreLabel->style()->polish(ui->scoreLabel);

    if (badCount > 0) 
    {
        ui->heroTitle->setText(QString("Обнаружены проблемы: %1").arg(badCount));
        ui->heroSubtitle->setText("Подробности — в карточках и журнале событий");
    } else if (m_results.size() == total) 
    {
        ui->heroTitle->setText("Защита в порядке");
        ui->heroSubtitle->setText("Все проверки пройдены успешно");
    } else 
    {
        ui->heroTitle->setText(QString("Проверено %1 из %2").arg(m_results.size()).arg(total));
        ui->heroSubtitle->setText("Запустите оставшиеся проверки");
    }
}

// Изменение статуса визуальной карты
void MainWindow::setCardState(QFrame *card, QLabel *pill, const QString &state, const QString &text)
{
    for (QWidget *w : {static_cast<QWidget*>(card), static_cast<QWidget*>(pill)}) 
    {
        w->setProperty("state", state);
        w->style()->unpolish(w);
        w->style()->polish(w);
    }
    pill->setText(text);
}

// Устоновка возможности прожимания кнопки
void MainWindow::setChecksEnabled(bool enabled)
{
    for (QPushButton *b : {ui->btnCheckNet, ui->btnCheckFwInstalled, ui->btnCheckFwWorking,
                           ui->btnCheckAvInstalled, ui->btnCheckAvWorking, ui->btnRunAll})
        b->setEnabled(enabled);
}

// Запуск полной проверки
void MainWindow::runAllChecks()
{
    if (m_runningAll)
        return;

    m_results.clear();
    m_queue = {
        [this] { checkInternet(); },
        [this] { checkFirewallInstalled(); },
        [this] { checkFirewallWorking(); },
        [this] { checkAntivirusInstalled(); },
        [this] { checkAntivirusWorking(); },
    };
    m_queueTotal = m_queue.size();
    m_runningAll = true;

    addLog("=== Запущена полная проверка ===");
    startNextCheck();
}

// Запуск следующей в очереди проверки
void MainWindow::startNextCheck()
{
    if (m_queue.isEmpty()) {
        m_runningAll = false;
        setChecksEnabled(true);
        addLog("=== Полная проверка завершена ===");
        return;
    }

    setChecksEnabled(false);
    const auto next = m_queue.takeFirst();
    // через очередь событий, чтобы синхронные проверки не вызывали рекурсию
    QTimer::singleShot(0, this, next);
}

// Обновление карточки или продолжение
void MainWindow::onCheckFinished()
{
    updateSummary();
    if (m_runningAll) {
        startNextCheck();
    }
}