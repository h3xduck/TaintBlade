#ifndef EXECUTIONBRIDGE_H
#define EXECUTIONBRIDGE_H

#include <QString>
#include <QMessageBox>
#include <QDebug>
#include <QProcess>

namespace EXECUTION
{
    /**
    Process holding the tracer process, if running
    */
    extern QProcess* tracerProcess;

    /**
    Executes the main tracer application
    */
    void executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir);

    /**
     * Returns whether the tracer process is currently running
     */
    bool tracerProcessRunning();
}

#endif // EXECUTIONBRIDGE_H
