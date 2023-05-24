#ifndef _TAINT_SINK_H_
#define _TAINT_SINK_H_

#include "../../utils/io/log.h"
#include "TaintController.h"
#include "../../utils/inst/InstructionWorker.h"
#include "../../utils/io/DataDumper.h"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "../../utils/inst/ScopeFilterer.h"
#include "../../common/Context.h"

#define ANY_FUNC_IN_DLL "ANY_FUNC_DLL_SOURCE"

#ifndef _WINDOWS_HEADERS_H_
#define _WINDOWS_HEADERS_H_
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um
namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
#include <wininet.h>
}
#endif

namespace TAINT
{
	namespace CORE
	{
		namespace TAINT_SINK
		{
			//CreateProcess and related
			void createProcessAEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10);
			void createProcessWEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10);
		
			void MultiByteToWideCharEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6);
			void MultiByteToWideCharExit(ADDRINT retVal, VOID* dllName, VOID* funcName);
		}
	}
}



#endif