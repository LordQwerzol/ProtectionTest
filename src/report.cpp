// Полная проверка, формирование отчёта и сохранение в Markdown
#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <QSysInfo>
#include <QTextDocument>
#include <QTextFrame>
#include <QTextStream>
#include <QTextTable>

// ===================== Отчёт =====================

namespace {
struct ReportItem {
    QString key;             // ключ в m_results
    QLabel *details;         // подпись карточки с подробностями
    QString recommendation;  // что посоветовать при провале
};

QString mdEscape(QString s)
{
    s.replace('|', "\\|");
    s.replace('\n', ' ');
    return s;
}
} // namespace

void MainWindow::buildReport()
{
    const QList<ReportItem> items = {
        {"Подключение к Интернету", ui->descNet,
         "Проверьте сетевой кабель или Wi-Fi и настройки подключения."},
        {"Наличие МЭ", ui->descFwInstalled,
         "Включите брандмауэр Windows или установите сторонний межсетевой экран."},
        {"Работа МЭ", ui->descFwWorking,
         "Запустите службы mpssvc и BFE, установите блокировку входящих соединений по умолчанию."},
        {"Наличие антивируса", ui->descAvInstalled,
         "Установите антивирус или включите Microsoft Defender, обновите базы."},
        {"Работа антивируса", ui->descAvWorking,
         "Включите защиту файлов в реальном времени в настройках антивируса."},
    };

    int passed = 0, failed = 0;
    for (const auto &it : items) {
        if (!m_results.contains(it.key)) continue;
        m_results.value(it.key) ? ++passed : ++failed;
    }
    const int notRun = items.size() - passed - failed;

    QString verdict;
    if (failed > 0)          verdict = QString("Обнаружены проблемы: %1").arg(failed);
    else if (notRun > 0)     verdict = QString("Выполнены не все проверки (%1 из %2)").arg(passed).arg(items.size());
    else                     verdict = "Защита в порядке";

    QString md;
    QTextStream out(&md);

    out << "# Отчёт о проверке средств защиты\n\n";
    out << "| Параметр | Значение |\n|---|---|\n";
    out << "| Дата и время | " << QDateTime::currentDateTime().toString("dd.MM.yyyy HH:mm:ss") << " |\n";
    out << "| Компьютер | " << mdEscape(QSysInfo::machineHostName()) << " |\n";
    out << "| Пользователь | " << mdEscape(qEnvironmentVariable("USERNAME")) << " |\n";
    out << "| Операционная система | " << mdEscape(QSysInfo::prettyProductName()) << " |\n";
    out << "| Программа | ProtectionTest |\n\n";

    out << "## Итог\n\n";
    out << "**" << verdict << "** — пройдено " << passed << " из " << items.size() << " проверок.\n\n";

    out << "## Результаты проверок\n\n";
    out << "| № | Проверка | Результат | Подробности |\n|---|---|---|---|\n";
    int n = 1;
    for (const auto &it : items) {
        QString result = "— не выполнялась";
        if (m_results.contains(it.key))
            result = m_results.value(it.key) ? "В норме" : "Проблема";
        const QString details = m_results.contains(it.key) ? it.details->text() : QString("—");
        out << "| " << n++ << " | " << it.key << " | " << result << " | " << mdEscape(details) << " |\n";
    }
    out << "\n";

    out << "## Рекомендации\n\n";
    bool anyRec = false;
    for (const auto &it : items) {
        if (m_results.contains(it.key) && !m_results.value(it.key)) {
            out << "- **" << it.key << ":** " << it.recommendation << "\n";
            anyRec = true;
        }
    }
    if (notRun > 0) {
        out << "- Выполните оставшиеся проверки для полной оценки защищённости.\n";
        anyRec = true;
    }
    if (!anyRec)
        out << "Рекомендаций нет: все средства защиты работают.\n";
    out << "\n";
    m_reportMarkdown = md;
    ui->reportView->setMarkdown(md);
    styleReportTables();
    addLog("Отчёт сформирован");
}

void MainWindow::saveReport()
{
    if (m_reportMarkdown.isEmpty())
        buildReport();

    const QString defaultName = QDir(QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation))
        .filePath("ProtectionTest_" + QDateTime::currentDateTime().toString("yyyy-MM-dd_HH-mm") + ".md");

    QString path = QFileDialog::getSaveFileName(this, "Сохранить отчёт", defaultName,
                                                "Отчёт Markdown (*.md)");
    if (path.isEmpty())
        return;                                   // пользователь нажал «Отмена»
    if (!path.endsWith(".md", Qt::CaseInsensitive))
        path += ".md";

    QString error;
    if (writeReport(path, &error)) {
        addLog("Отчёт сохранён: " + QDir::toNativeSeparators(path));
    } else {
        QMessageBox::warning(this, "Ошибка сохранения", error);
        addLog("Ошибка сохранения отчёта: " + error);
    }
}

bool MainWindow::writeReport(const QString &path, QString *error)
{
    QFile f(path);
    if (!f.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = f.errorString();
        return false;
    }
    f.write(m_reportMarkdown.toUtf8());
    return true;
}

// Markdown-таблицы в QTextBrowser по умолчанию тесные — добавляем отступы и рамки
void MainWindow::styleReportTables()
{
    QTextDocument *doc = ui->reportView->document();
    for (QTextFrame *frame : doc->rootFrame()->childFrames()) {
        if (auto *table = qobject_cast<QTextTable *>(frame)) {
            QTextTableFormat fmt = table->format();
            fmt.setCellPadding(6);
            fmt.setCellSpacing(0);
            fmt.setBorder(1);
            fmt.setBorderStyle(QTextFrameFormat::BorderStyle_Solid);
            fmt.setBorderBrush(QColor("#d1d5db"));
            fmt.setBorderCollapse(true);
            fmt.setWidth(QTextLength(QTextLength::PercentageLength, 100));
            table->setFormat(fmt);
        }
    }
}
