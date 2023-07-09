#ifndef GLOBALS_H
#define GLOBALS_H

#include <QString>
#include "widgets/protocol/data/Protocol.h"
#include <memory>

class MultiWindowViewWidget;

namespace GLOBAL_VARS
{
    //Path of the binary that will be traced
    extern QString selectedToTraceBinaryPath;
    //Path of the directory where output data is stored
    extern QString selectedOutputDirPath;
    //Path of the main pin.exe program
    extern QString pinExeDirPath;
    //Path of the tracer DLL
    extern QString tracerDLLDirPath;

    //PID of currently selected traced process data (the one being visualized in the GUI)
    extern QString selectedProcessPID;
    //Index of currently selected buffer
    extern int selectedBufferIndex;
    //Main window widget
    extern MultiWindowViewWidget* mainMultiWindowWidget;

    //Protocol. Gathered from the DB.
    extern std::shared_ptr<PROTOCOL::Protocol> globalProtocol;
}


#endif // GLOBALS_H
