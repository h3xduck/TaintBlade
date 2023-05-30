#include "ExecutionBridge.h"

void EXECUTION::executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir)
{
    //Run the tracer program with all provided arguments.
    qDebug() << "Launching the tracer program with arguments:\n\tProgram:"<<programPath<<"\n\tPIN exe:"<<pinExe<<"\n\tTracer DLL:"<<tracerDLL<<"\n\tOutput dir:"<<outputDir;

    QProcess* process = new QProcess();
    QString program = pinExe;
    QStringList programArgs;
    programArgs << "-follow_execv" << "-t" << tracerDLL << "-o" << "pinlog.dfx" << "-s"<< "syspinlog.dfx" << "-i"<<"imgpinlog.dfx" << "-d"<<"debuglogfile.dfx" << "-taint" <<"taintsources.txt" << "--"<<programPath<<"127.0.0.1";
    process->setWorkingDirectory(outputDir);
    process->start(program, programArgs);
    qDebug() <<"Executing: "<<process->program() << "Args: " <<process->arguments();
}
