#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QStyle>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    connect(ui->navOverview, &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(0); });
    connect(ui->navLog,      &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(1); });
    connect(ui->navReport,   &QPushButton::clicked, this, [this]{ ui->pages->setCurrentIndex(2); });
}

MainWindow::~MainWindow()
{
    delete ui;
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