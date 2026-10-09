#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFrame>
#include <QLabel>
#include <QMap>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void checkInternet();
    void checkFirewallInstalled();
    void checkAntivirusInstalled();
    void checkFirewallWorking();
    void checkAntivirusWorking();
    void runAllChecks();
    void buildReport();
    void saveReport();

private:
    Ui::MainWindow *ui;

    void setCardState(QFrame *card, QLabel *pill, const QString &state, const QString &text);

    void addLog(const QString &message);
    void updateSummary();
    void startNextCheck();
    void onCheckFinished();
    void setChecksEnabled(bool enabled);  
    void styleReportTables();
    bool writeReport(const QString &path, QString *error = nullptr);
    
    // Переменная для отчета 
    QMap<QString, bool> m_results;
    QList<std::function<void()>> m_queue;   // очередь полной проверки
    int  m_queueTotal = 0;
    bool m_runningAll = false;
    QString m_reportMarkdown;
};
#endif // MAINWINDOW_H
