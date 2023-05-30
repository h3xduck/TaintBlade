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
    }
}


void MainWindow::on_actionSelect_configuration_triggered()
{
    //Open the dialog to select the three different config options
    qDebug() << "Launching pin configuration option dialog";
    PinConfigurationDialog *dialog = new PinConfigurationDialog;
    dialog->exec();
}


void MainWindow::on_actionRun_triggered()
{
    //Execute the program. If some argument is not available, then show a message of so
    if(GLOBAL_VARS::selectedToTraceBinaryPath.isEmpty())
    {
        QMessageBox msgWarning;
        msgWarning.setText("Please select the program to trace first");
        msgWarning.setIcon(QMessageBox::Warning);
        msgWarning.setWindowTitle("Caution");
        msgWarning.exec();

        MainWindow::on_actionOpen_triggered();
    }

    //If we reach this point and the argument is not set, is because the user cancelled some operation. So halt
    if(GLOBAL_VARS::selectedToTraceBinaryPath.isEmpty())
    {
        return;
    }

    if(GLOBAL_VARS::selectedOutputDirPath.isEmpty() ||
        GLOBAL_VARS::pinExeDirPath.isEmpty() ||
        GLOBAL_VARS::tracerDLLDirPath.isEmpty())
    {
        QMessageBox msgWarning;
        msgWarning.setText("Please complete PIN configuration first");
        msgWarning.setIcon(QMessageBox::Warning);
        msgWarning.setWindowTitle("Caution");
        msgWarning.exec();

        MainWindow::on_actionSelect_configuration_triggered();
    }

    //If we reach this point and some argument is not set, is because the user cancelled some operation. So halt
    if(GLOBAL_VARS::selectedOutputDirPath.isEmpty() ||
        GLOBAL_VARS::pinExeDirPath.isEmpty() ||
        GLOBAL_VARS::tracerDLLDirPath.isEmpty())
    {
        return;
    }

    //If we reach this point, everything is set, call tracer
    EXECUTION::executeTracer(GLOBAL_VARS::selectedToTraceBinaryPath, GLOBAL_VARS::pinExeDirPath, GLOBAL_VARS::tracerDLLDirPath, GLOBAL_VARS::selectedOutputDirPath);
}

