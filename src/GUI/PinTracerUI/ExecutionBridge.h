#ifndef EXECUTIONBRIDGE_H
#define EXECUTIONBRIDGE_H

#include <QString>
#include <QMessageBox>
#include <QDebug>
#include <QProcess>

namespace EXECUTION
{
    /**
    Executes the main tracer application
    */
    void executeTracer(QString programPath, QString pinExe, QString tracerDLL, QString outputDir);
}

#endif // EXECUTIONBRIDGE_H
