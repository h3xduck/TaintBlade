#include "ExecutionBridge.h"

QProcess* EXECUTION::tracerProcess;

void EXECUTION::executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir)
{
    //Run the tracer program with all provided arguments.
    qDebug() << "Launching the tracer program with arguments:\n\tProgram:"<<programPath<<"\n\tPIN exe:"<<pinExe<<"\n\tTracer DLL:"<<tracerDLL<<"\n\tOutput dir:"<<outputDir;

    EXECUTION::tracerProcess = new QProcess();
    QString program = pinExe;
    QStringList programArgs;
    programArgs << "-follow_execv" << "-t" << tracerDLL << "-o" << "pinlog.dfx" << "-s"<< "syspinlog.dfx" << "-i"<<"imgpinlog.dfx" << "-d"<<"debuglogfile.dfx" << "-taint" <<"taintsources.txt" << "--"<<programPath<<"127.0.0.1";
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
