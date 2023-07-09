#include "../include/mainwindow.h"
#include "./ui_mainwindow.h"
#include "common/Globals.h"
#include "utils/exec/ExecutionBridge.h"
#include "dialogs/PinConfigurationDialog.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->setCentralWidget(ui->centralWidget);
    this->window()->setWindowState(Qt::WindowMaximized);
    this->setWindowTitle("TaintBlade v0.3.0-alpha");

    connect(ui->actionDll, SIGNAL(triggered()), this, SLOT(actionDLL_triggered()));
    connect(ui->actionTaintSources, SIGNAL(triggered()), this, SLOT(actionTaintSources_triggered()));
    connect(ui->actionTracePoints, SIGNAL(triggered()), this, SLOT(actionTracePoints_triggered()));
    connect(ui->actionNOPSections, SIGNAL(triggered()), this, SLOT(actionNOPSections_triggered()));
    connect(ui->actionStop, SIGNAL(triggered()), this, SLOT(actionStop_triggered()));
    connect(ui->actionExit, &QAction::triggered, [=]() {this->close(); });
    connect(ui->actionAbout, SIGNAL(triggered()), this, SLOT(actionAbout_triggered()));

    configureToolBarOptionsCheckOutputdirIsSet();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::renderMultiWindow()
{
    this->centralLayout = new QVBoxLayout();
    if(ui->centralWidget->layout())
    {
        qDebug() << "Resetting multiwindow";
        ui->centralWidget = new QWidget(this);
        ui->centralWidget->setObjectName("centralWidget");
        ui->centralWidget->setEnabled(true);
        QSizePolicy sizePolicy(QSizePolicy::Maximum, QSizePolicy::Maximum);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(ui->centralWidget->sizePolicy().hasHeightForWidth());
        ui->centralWidget->setSizePolicy(sizePolicy);
        this->setCentralWidget(ui->centralWidget);
    }
    ui->centralWidget->setLayout(centralLayout);
    ui->centralWidget->layout()->setContentsMargins(0,0,0,0);
    this->multiWindowViewWidget = new MultiWindowViewWidget(this);
    this->centralLayout->addWidget(this->multiWindowViewWidget);
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
    configureToolBarOptionsCheckOutputdirIsSet();
}

void MainWindow::tracerProcess_finished()
{
    //This is called when the tracer process is finished
    qDebug()<<"TRACER PROCESS FINISHED";

    //Toggle the state of the run/stop buttons
    ui->actionRun->setEnabled(true);
    ui->actionStop->setEnabled(false);

    //Also terminate the tracer process drawer
    this->multiWindowViewWidget->tracedProcessFinished();
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

    //If we reach this point, everything is set, call tracer program
    EXECUTION::executeTracer(GLOBAL_VARS::selectedToTraceBinaryPath, GLOBAL_VARS::pinExeDirPath, GLOBAL_VARS::tracerDLLDirPath, GLOBAL_VARS::selectedOutputDirPath);
    ui->actionRun->setEnabled(false);
    ui->actionStop->setEnabled(true);

    //Now, register a callback so that we can know when the process finishes
    connect(EXECUTION::tracerProcess, (void(QProcess::*)(int))&QProcess::finished, [=]{ MainWindow::tracerProcess_finished(); });

    //Finally, we will render the elements of the multi window
    renderMultiWindow();
    //And start to show any process that we find in the traced process window
    this->multiWindowViewWidget->showTracedProcesses();
}

void MainWindow::actionDLL_triggered()
{
    //The button should be deactivated, the output path should be set prior to this being enables
    DLLSelectorDialog dialog;
    dialog.exec();
}

void MainWindow::actionTaintSources_triggered()
{
    //The button should be deactivated, the output path should be set prior to this being enables
    TaintSourceSelectorDialog dialog;
    dialog.exec();
}

void MainWindow::actionTracePoints_triggered()
{
    //The button should be deactivated, the output path should be set prior to this being enables
    TracePointSelectorDialog dialog;
    dialog.exec();
}

void MainWindow::actionNOPSections_triggered()
{
    //The button should be deactivated, the output path should be set prior to this being enables
    NopSectionSelectorDialog dialog;
    dialog.exec();
}

void MainWindow::actionStop_triggered()
{
    EXECUTION::commandStopExecution();
}

void MainWindow::configureToolBarOptionsCheckOutputdirIsSet()
{
    bool state = false;
    if (!GLOBAL_VARS::selectedOutputDirPath.isEmpty())
    {
        state = true;
    }
    ui->actionDll->setEnabled(state);
    ui->actionNOPSections->setEnabled(state);
    ui->actionTaintSources->setEnabled(state);
    ui->actionTracePoints->setEnabled(state);
}

void MainWindow::actionAbout_triggered()
{
    AboutDialog dialog;
    dialog.exec();
}