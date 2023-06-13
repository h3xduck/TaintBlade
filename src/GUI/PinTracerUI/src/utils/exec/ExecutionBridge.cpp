#include "utils/exec/ExecutionBridge.h"

QProcess* EXECUTION::tracerProcess;

/**
 * Delete all files from previous tracer runs
 */
void deletePreviousRunFiles()
{
    qDebug()<<"Starting file deletion";
    QString path = GLOBAL_VARS::selectedOutputDirPath;
    QDir dir(path);
    dir.setNameFilters(QStringList() << "*.dfx" << "*dump.db");
    dir.setFilter(QDir::Files);
    foreach(QString dirFile, dir.entryList())
    {
        qDebug()<<"Removing: "<<dirFile;
        dir.remove(path+"/"+dirFile);
    }
}

void EXECUTION::executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir)
{
    //Run the tracer program with all provided arguments.
    qDebug() << "Launching the tracer program with arguments:\n\tProgram:"<<programPath<<"\n\tPIN exe:"<<pinExe<<"\n\tTracer DLL:"<<tracerDLL<<"\n\tOutput dir:"<<outputDir;

    //First we remove all previous run files
    deletePreviousRunFiles();

    //Then, execute the tracer
    EXECUTION::tracerProcess = new QProcess();
    QString program = pinExe;
    QStringList programArgs;
    programArgs << "-follow_execv" << "-t" << tracerDLL << "-o" << "pinlog.dfx" << "-s"<< "syspinlog.dfx" 
        << "-i"<<"imgpinlog.dfx" << "-dllinclude" << "dllinclude.txt" << "-d" << "debuglogfile.dfx" 
        << "-nopsections" << "nopsections.txt" << "-trace" << "tracepoints.txt"
        << "-taint" << "taintsources.txt" << "--" << programPath << "127.0.0.1";
    EXECUTION::tracerProcess->setWorkingDirectory(outputDir);
    EXECUTION::tracerProcess->start(program, programArgs);
    qDebug() <<"Executing: "<<EXECUTION::tracerProcess->program() << "Args: " <<EXECUTION::tracerProcess->arguments();
}


bool EXECUTION::tracerProcessRunning()
{
    if(EXECUTION::tracerProcess != NULL)
    {
        return EXECUTION::tracerProcess->state() != QProcess::NotRunning;
    }

    return false;
}
