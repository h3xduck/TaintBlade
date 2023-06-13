#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include <QVBoxLayout>
#include <QMenu>
#include <QPushButton>
#include "widgets/process/TracedProcessWidget.h"
#include "widgets/MultiWindowViewWidget.h"
#include "dialogs/DLLSelectorDialog.h"
#include "dialogs/TaintSourceSelectorDialog.h"
#include "dialogs/TracePointSelectorDialog.h"
#include "dialogs/NopSectionSelectorDialog.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

    public:
        MainWindow(QWidget *parent = nullptr);
        ~MainWindow();

        void renderMultiWindow();

    private slots:
        void on_actionOpen_triggered();

        void on_actionSelect_configuration_triggered();

        void on_actionRun_triggered();

        void tracerProcess_finished();

        void actionDLL_triggered();
        void actionTaintSources_triggered();
        void actionTracePoints_triggered();
        void actionNOPSections_triggered();

    private:
        Ui::MainWindow *ui;
        QVBoxLayout* centralLayout;
        MultiWindowViewWidget *multiWindowViewWidget;

};
#endif // MAINWINDOW_H
