#include "common/Globals.h"


QString GLOBAL_VARS::selectedToTraceBinaryPath = "C:/Users/Marcos/source/repos/h3xduck/TFM/samples/tcp_client.exe";
QString GLOBAL_VARS::selectedOutputDirPath = "C:/Users/Marcos/source/repos/h3xduck/TFM/src/test/testgui";
QString GLOBAL_VARS::pinExeDirPath = "C:/Users/Marcos/source/repos/h3xduck/TFM/src/external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/pin.exe";
QString GLOBAL_VARS::tracerDLLDirPath = "C:/Users/Marcos/source/repos/h3xduck/TFM/src/PinTracer/x64/Release/PinTracer.dll";

QString GLOBAL_VARS::selectedProcessPID = "";
int GLOBAL_VARS::selectedBufferIndex = -1;

std::shared_ptr<PROTOCOL::Protocol> GLOBAL_VARS::globalProtocol;