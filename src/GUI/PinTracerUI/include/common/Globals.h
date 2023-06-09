#ifndef GLOBALS_H
#define GLOBALS_H

#include <QString>
#include "widgets/protocol/data/Protocol.h"
#include <memory>

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

    //Protocol. Gathered from the DB.
    extern std::shared_ptr<PROTOCOL::Protocol> globalProtocol;
}


#endif // GLOBALS_H
