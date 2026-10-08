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

private:
    Ui::MainWindow *ui;

    void setCardState(QFrame *card, QLabel *pill, const QString &state, const QString &text);

    void addLog(const QString &message);
    void updateSummary();
    
    // Переменная для отчета ?
    QMap<QString, bool> m_results;
};
#endif // MAINWINDOW_H
