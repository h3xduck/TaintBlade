#include "mainwindow.h"
#include "./ui_mainwindow.h"
#include "Globals.h"
#include "ExecutionBridge.h"
#include "PinConfigurationDialog.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setCentralWidget(ui->centralWidget);

}

MainWindow::~MainWindow()
{
    delete ui;
}


void MainWindow::on_actionOpen_triggered()
{
    GLOBAL_VARS::selectedToTraceBinaryPath = QFileDialog::getOpenFileName(this, "Select EXE to trace");
    if (!GLOBAL_VARS::selectedToTraceBinaryPath.isEmpty())
    {
        qDebug() << "User selected file "<< GLOBAL_VARS::selectedToTraceBinaryPath <<" to be opened";
        //Execute main tracer program. Will fail if arguments are not properly set until this point
        EXECUTION::executeTracer(GLOBAL_VARS::selectedToTraceBinaryPath, GLOBAL_VARS::pinExeDirPath,
                                 GLOBAL_VARS::tracerDLLDirPath, GLOBAL_VARS::selectedOutputDirPath);
    }
}


void MainWindow::on_actionSelect_configuration_triggered()
{
    //Open the dialog to select the three different config options
    qDebug() << "Launching pin configuration option dialog";
    PinConfigurationDialog *dialog = new PinConfigurationDialog;
    dialog->show();
}

