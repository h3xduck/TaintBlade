#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../../utils/io/log.h"
#include <stdarg.h>
#include "TaintController.h"
#include "../../utils/inst/InstructionWorker.h"
#include "../../utils/io/DataDumper.h"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "../../utils/inst/ScopeFilterer.h"

#define ANY_FUNC_IN_DLL "ANY_FUNC_DLL_SOURCE"

#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um

namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
}

extern TaintController taintController;
extern DataDumper dataDumper;
extern ScopeFilterer scopeFilterer;

//Function arguments
struct wsock_recv_t
{
	//Args
	WINDOWS::SOCKET s;
	char* buf;
	int len;
	int flags;

	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
};
static wsock_recv_t wsockRecv;

static std::tr1::unordered_map<ADDRINT, struct DataDumper::func_dll_names_dump_line_t> genericRoutineCalls;

class TaintSource
{
public:
	//Map for generic routine instrumentation. Key is retIP, includes arguments addresses
	
	//Handlers
	static VOID wsockRecvEnter(int retIp, std::string dllName, std::string funcName, ...)
	{
		int NUM_ARGS = 4;
		va_list vaList;
		va_start(vaList, funcName);

		wsockRecv.s = va_arg(vaList, WINDOWS::SOCKET);
		wsockRecv.buf = va_arg(vaList, char*);
		wsockRecv.len = va_arg(vaList, int);
		wsockRecv.flags = va_arg(vaList, int);

		va_end(vaList);

		LOG_INFO("Called wsockRecvEnter()\n\tretIp: "<<retIp<<"\n\tbuf: " << wsockRecv.buf << "\n\tlen: "<< wsockRecv.len);
	};
	static VOID wsockRecvExit(int retVal, std::string dllName, std::string funcName, ...)
	{
		//Firstly, we must check that we received something. Return value is # of bytes read
		if(retVal<=0)
		{
			//No tainting needed
			return;
		}
		//Otherwise, we taint as many bytes in buf as indicated by retVal
		LOG_INFO("Called wsockRecvExit()\n\tretVal:" << retVal << "\n\tbuf: " << wsockRecv.buf << "\n\tlen: " << wsockRecv.len);

		std::vector<UINT16> colorVector = taintController.taintMemoryNewColor((ADDRINT)wsockRecv.buf, retVal);
		//LOG_DEBUG("Logging original color:: DLL:" << dllName << " FUNC:" << funcName);
		for (auto color : colorVector)
		{
			taintController.registerOriginalColor(color, dllName, funcName);
		}
		
	}

	static VOID mainEnter(int retIp, std::string dllName, std::string funcName, ...)
	{
		LOG_DEBUG("Called mainEnter()");
		
		//Test: taint RAX
		//taintController.printTaint();
		taintController.taintRegNewColor(REG_RAX);
		taintController.taintRegNewColor(REG_RBX);
	};
	static VOID mainExit(int retVal, std::string dllName, std::string funcName, ...)
	{
		LOG_DEBUG("Called mainExit()");
		//taintController.printTaint();
	}

	static VOID emptyHandler() {};


	std::string dllName;
	std::string funcName;
	int numArgs = 0;

	//placeholders
	VOID(*enterHandler)(int, std::string, std::string, ...) = NULL;
	VOID(*exitHandler)(int, std::string, std::string, ...) = NULL;

	TaintSource() {};
	TaintSource(const std::string dllName, const std::string funcName, int numArgs, VOID(*enter)(int, std::string, std::string, ...), VOID(*exit)(int, std::string, std::string, ...));

	void taintSourceLogAll();

	static VOID genericRoutineInstrumentEnter(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, UINT32 instSize, CONTEXT* ctx, THREADID tid,
		VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
	{
		PIN_LockClient();

		//Only if we are going from main dll to another
		if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isMainExecutable(branchTargetAddress))
		{
			if (branchTaken)
			{

				struct DataDumper::func_dll_names_dump_line_t data;
				IMG moduleFrom = IMG_FindByAddress(ip);
				if (!IMG_Valid(moduleFrom))
				{
					std::cerr << "Image invalid at address " << ip << std::endl;
					return;
				}

				std::string dllFrom = InstructionWorker::getDllFromAddress(ip);
				ADDRINT baseAddrFrom = InstructionWorker::getBaseAddress(ip);
				std::string routineNameFrom = InstructionWorker::getFunctionNameFromAddress(ip);
				std::string dllTo = InstructionWorker::getDllFromAddress(branchTargetAddress);
				ADDRINT baseAddrTo = InstructionWorker::getBaseAddress(branchTargetAddress);
				std::string routineNameTo = InstructionWorker::getFunctionNameFromAddress(branchTargetAddress);

				data.dllFrom = dllFrom;
				data.funcFrom = routineNameFrom;
				data.memAddrFrom = baseAddrFrom;
				data.dllTo = dllTo;
				data.funcTo = routineNameTo;
				data.memAddrTo = baseAddrTo;
				data.arg0 = arg0;
				data.arg1 = arg1;
				data.arg2 = arg2;
				data.arg3 = arg3;
				data.arg4 = arg4;
				data.arg5 = arg5;

				genericRoutineCalls.insert(std::make_pair<ADDRINT, struct DataDumper::func_dll_names_dump_line_t>(baseAddrFrom, data));

				//At this point, we log the function and the arguments
				dataDumper.writeRoutineDumpLine(data);
			}
		}

		PIN_UnlockClient();
		
	}

	static void genericRoutineInstrumentExit(ADDRINT retVal, ADDRINT retIp)
	{
		auto it = genericRoutineCalls.find(retIp);
		if (it == genericRoutineCalls.end())
		{
			LOG_ERR("Tried to instrument generic routine at exit, but entry not found");
		}
		else
		{
			LOG_DEBUG("Found retIP in the generic routine calls map");

			genericRoutineCalls.erase(retIp);
		}
	}

};

#endif