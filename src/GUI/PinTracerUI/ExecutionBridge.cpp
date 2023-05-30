#include "ExecutionBridge.h"

void EXECUTION::executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir)
{
    //Run the tracer program with all provided arguments.
    qDebug() << "Launching the tracer program with arguments:\n\tProgram:"<<programPath<<"\n\tPIN exe:"<<pinExe<<"\n\tTracer DLL:"<<tracerDLL<<"\n\tOutput dir:"<<outputDir;
}
