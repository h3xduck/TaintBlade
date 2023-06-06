#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../../utils/io/log.h"
#include <stdarg.h>
#include "TaintController.h"
#include "../../utils/inst/InstructionWorker.h"
#include "../../utils/io/DataDumper.h"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "../../utils/inst/ScopeFilterer.h"
#include "../../common/Context.h"

#define ANY_FUNC_IN_DLL "ANY_FUNC_DLL_SOURCE"

#ifndef _WINDOWS_HEADERS_H_
#define _WINDOWS_HEADERS_H_
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um
namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
#include <wininet.h>
}
#endif

extern TaintController taintController;
extern ScopeFilterer scopeFilterer;
extern Context ctx;
//Function arguments
struct wsock_recv_t
{
	ADDRINT ip;

	//Args
	WINDOWS::SOCKET s;
	char* buf;
	int len;
	int flags;

	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
};
static wsock_recv_t wsockRecv;

struct wininet_internetreadfile_t
{
	ADDRINT ip;

	//Args
	WINDOWS::LPVOID hFile;
	WINDOWS::LPVOID lpBuffer;
	WINDOWS::DWORD dwNumberOfBytesToRead;
	WINDOWS::LPDWORD lpdwNumberOfBytesRead;

	// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile
};
static wininet_internetreadfile_t wininetInternetReadFile;

static std::tr1::unordered_map<ADDRINT, struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t> genericRoutineCalls;

class TaintSource
{
public:
	bool TaintSource::operator==(const TaintSource& other) const
	{
		if (this->dllName != other.dllName ||
			this->funcName != other.funcName ||
			this->numArgs != other.numArgs)
		{
			return false;
		}

		return true;
	}


	//Map for generic routine instrumentation. Key is retIP, includes arguments addresses
	
	//****************Handlers***********************************************************//
	
	///////////////// WSOCK /////////////////
	static VOID wsockRecvEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
	{
		int NUM_ARGS = 4;
		wsockRecv.ip = currIp;
		wsockRecv.s = (WINDOWS::SOCKET)arg1;
		wsockRecv.buf = (char*)arg2;
		wsockRecv.len = (int)arg3;
		wsockRecv.flags = (int)arg4;

		LOG_INFO("Called wsockRecvEnter()\n\tretIp: "<<retIp<<"\n\tbuf: " << wsockRecv.buf << "\n\tlen: "<< wsockRecv.len);
	};
	static VOID wsockRecvExit(ADDRINT retVal, VOID* dllName, VOID* funcName)
	{
		INT32 retValSigned = static_cast<INT32>(retVal);
		//Firstly, we must check that we received something. Return value is # of bytes read
		if (retValSigned <= 0)
		{
			LOG_INFO("Called wsockRecvExit(), but no tainting needed (retval: " << retValSigned << ")");
			//No tainting needed
			return;
		}
		const std::string* dllNameStr = static_cast<std::string*>(dllName);
		const std::string* funcNameStr = static_cast<std::string*>(funcName);

		//Otherwise, we taint as many bytes in buf as indicated by retVal
		LOG_INFO("Called wsockRecvExit()\n\tretVal:" << retValSigned << "\n\tbuf: " << wsockRecv.buf << "\n\tlen: " << wsockRecv.len);

		std::string val = InstructionWorker::getMemoryValueHexString((ADDRINT)wsockRecv.buf, retVal);

		//Update the instruction values so that we are right at the end of the routine right now, 
		//where we taint the data
		PIN_LockClient();
		RTN rtn = RTN_FindByAddress(wsockRecv.ip);
		if (rtn == RTN_Invalid())
		{
			return;
		}
		RTN_Open(rtn);
		const ADDRINT routineEndInstAddress = INS_Address(RTN_InsTail(rtn));
		RTN_Close(rtn);
		ctx.updateCurrentInstructionFullAddress(routineEndInstAddress);
		ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(routineEndInstAddress));
		ctx.updateLastMemoryValue(val, retVal);
		PIN_UnlockClient();

		std::vector<UINT16> colorVector = taintController.taintMemoryNewColor((ADDRINT)wsockRecv.buf, retVal);
		//LOG_DEBUG("Logging original color:: DLL:" << dllName << " FUNC:" << funcName);
		int offset = 0;
		for (auto color : colorVector)
		{
			//Each 1 byte, we get a different color
			taintController.registerOriginalColor(color, *dllNameStr, *funcNameStr, (ADDRINT)((wsockRecv.buf)+offset), (UINT8)(wsockRecv.buf[offset]));
			offset++;
			//LOG_DEBUG("Here2");
		}

		LOG_DEBUG("Called wsockexit");

		//Register that this routine had some taint event
		UTILS::IO::DataDumpLine::taint_routine_dump_line_t data;
		data.instAddrEntry = wsockRecv.ip;
		data.instAddrLast = routineEndInstAddress;
		data.dll = *dllNameStr;
		data.func = *funcNameStr;
		data.containedEventsType = UTILS::IO::DataDumpLine::TAINT_SRC;
		ctx.getDataDumper().writeTaintRoutineDumpLine(data);
	};

	///////////////// WININET /////////////////
	static VOID wininetInternetReadFileEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
	{
		int NUM_ARGS = 4;
		
		wininetInternetReadFile.ip = currIp;
		wininetInternetReadFile.hFile = (WINDOWS::LPVOID)arg1;
		wininetInternetReadFile.lpBuffer = (WINDOWS::LPVOID)arg2;
		wininetInternetReadFile.dwNumberOfBytesToRead = (WINDOWS::DWORD)arg3;
		wininetInternetReadFile.lpdwNumberOfBytesRead = (WINDOWS::LPDWORD)arg4;

		LOG_INFO("Called wininetInternetReadFileEnter()\n\tretIp: " << retIp << "\n\tlpBuffer: " << wininetInternetReadFile.lpBuffer << "\n\tRequested length: " << wininetInternetReadFile.dwNumberOfBytesToRead);
	}
	static VOID wininetInternetReadFileExit(ADDRINT retVal, VOID* dllName, VOID* funcName)
	{
		//Firstly, we must check that we received something. Return value is TRUE if call successful, FALSE otherwise
		if (retVal == FALSE)
		{
			//No tainting needed
			return;
		}

		const std::string* dllNameStr = static_cast<std::string*>(dllName);
		const std::string* funcNameStr = static_cast<std::string*>(funcName);

		//Otherwise, we taint as many bytes in buf as indicated by retVal
		LOG_INFO("Called wininetInternetReadFileExit()\n\tretVal:" << retVal << "\n\tlpBuffer: " << wininetInternetReadFile.lpBuffer << "\n\tReceived len: " << *wininetInternetReadFile.lpdwNumberOfBytesRead);

		//Update the instruction values so that we are right at the end of the routine right now, 
		//where we taint the data
		PIN_LockClient();
		RTN rtn = RTN_FindByAddress(wininetInternetReadFile.ip);
		if (rtn == RTN_Invalid())
		{
			return;
		}
		RTN_Open(rtn);
		const ADDRINT routineEndInstAddress = INS_Address(RTN_InsTail(rtn));
		RTN_Close(rtn);
		ctx.updateCurrentInstructionFullAddress(routineEndInstAddress);
		ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(routineEndInstAddress));
		std::string val = InstructionWorker::getMemoryValueHexString((ADDRINT)wininetInternetReadFile.lpBuffer, *(wininetInternetReadFile.lpdwNumberOfBytesRead));
		ctx.updateLastMemoryValue(val, *(wininetInternetReadFile.lpdwNumberOfBytesRead));
		PIN_UnlockClient();


		std::vector<UINT16> colorVector = taintController.taintMemoryNewColor((ADDRINT)wininetInternetReadFile.lpBuffer, *(wininetInternetReadFile.lpdwNumberOfBytesRead));
		//LOG_DEBUG("Logging original color:: DLL:" << dllName << " FUNC:" << funcName);
		int offset = 0;
		for (auto color : colorVector)
		{
			//Each 1 byte, we get a different color
			taintController.registerOriginalColor(color, *dllNameStr, *funcNameStr, (ADDRINT)((char*)(wininetInternetReadFile.lpBuffer) + offset), (UINT8)(((char*)wininetInternetReadFile.lpBuffer)[offset]));
			offset++;
		}

		//Register that this routine had some taint event
		UTILS::IO::DataDumpLine::taint_routine_dump_line_t data;
		data.instAddrEntry = routineEndInstAddress;
		data.instAddrLast = INS_Address(RTN_InsTail(rtn));
		data.dll = *dllNameStr;
		data.func = *funcNameStr;
		data.containedEventsType = UTILS::IO::DataDumpLine::TAINT_SRC;
		ctx.getDataDumper().writeTaintRoutineDumpLine(data);
	};



	///////////////// MAIN (FOR TESTING). Taints RAX and RBX /////////////////
	static VOID mainEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
	{
		LOG_DEBUG("Called mainEnter()");
		
		//Test: taint RAX
		//taintController.printTaint();
#ifdef TARGET_IA32E
		//taintController.taintRegNewColor(LEVEL_BASE::REG::REG_RBX);
		taintController.taintRegNewColor(REG_RBX);
#else 
		taintController.taintRegNewColor(LEVEL_BASE::REG::REG_EAX);
		taintController.taintRegNewColor(REG_EBX);
#endif
	};
	static VOID mainExit(ADDRINT retVal, VOID* dllName, VOID* funcName)
	{
		LOG_DEBUG("Called mainExit()");
		//taintController.printTaint();
	}

	static VOID emptyHandler() {};


	std::string dllName;
	std::string funcName;
	int numArgs = 0;

	//placeholders
	VOID(*enterHandler)(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6) = NULL;
	VOID(*exitHandler)(ADDRINT, VOID*, VOID*) = NULL;

	TaintSource() {};
	TaintSource(const std::string dllName, const std::string funcName, int numArgs, 
		VOID(*enter)(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6),
		VOID(*exit)(ADDRINT, VOID*, VOID*));

	void taintSourceLogAll();

	static VOID genericRoutineInstrumentEnter(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, UINT32 instSize, ADDRINT nextInstAddr, CONTEXT* localCtx, THREADID tid,
		VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
	{
		PIN_LockClient();
		
		//In the case this goes from our main executable or a scoped image to another one, we log the address from which
		//we are jumping from since it might be interesting to be dumped
		if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isScopeImage(ip))
		{
			ctx.lastRoutineInfo().possibleJumpPoint = ip;
			ctx.lastRoutineInfo().possibleBaseJumpPoint = InstructionWorker::getBaseAddress(ip);
			RTN rtn = RTN_FindByAddress(ip); 
			RTN_Open(rtn);
			ctx.lastRoutineInfo().routineStart = INS_Address(RTN_InsHeadOnly(rtn));
			ctx.lastRoutineInfo().routineBaseStart = InstructionWorker::getBaseAddress(ctx.lastRoutineInfo().routineStart);
			RTN_Close(rtn);
			ctx.lastRoutineInfo().funcName = InstructionWorker::getFunctionNameFromAddress(ip);
			ctx.lastRoutineInfo().dllName = InstructionWorker::getDllFromAddress(ip);
		}

		//We will log the arguments of this routine, but only if we are going from main dll to another, or another scoped image
		if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isMainExecutable(branchTargetAddress) ||
			scopeFilterer.isScopeImage(ip) || scopeFilterer.isScopeImage(branchTargetAddress))
		{
			if (branchTaken)
			{

				struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t data;
				IMG moduleFrom = IMG_FindByAddress(ip);
				if (!IMG_Valid(moduleFrom))
				{
					std::cerr << "Image invalid at address " << ip << std::endl;
					return;
				}

				std::string dllFrom = InstructionWorker::getDllFromAddress(ip);
				std::string routineNameFrom = InstructionWorker::getFunctionNameFromAddress(ip);
				std::string dllTo = InstructionWorker::getDllFromAddress(branchTargetAddress);
				std::string routineNameTo = InstructionWorker::getFunctionNameFromAddress(branchTargetAddress);

				data.dllFrom = dllFrom;
				data.funcFrom = routineNameFrom;
				data.memAddrFrom = InstructionWorker::getBaseAddress(ip);
				data.dllTo = dllTo;
				data.funcTo = routineNameTo;
				data.memAddrTo = InstructionWorker::getBaseAddress(branchTargetAddress);
				data.arg0 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg0));
				data.arg1 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg1));
				data.arg2 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg2));
				data.arg3 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg3));
				data.arg4 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg4));
				data.arg5 = InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(arg5));

				genericRoutineCalls.erase(nextInstAddr);
				genericRoutineCalls.insert(std::make_pair<ADDRINT, struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t>(nextInstAddr, data));
				//LOG_DEBUG("Inserted entry jump at " << to_hex_dbg(branchTargetAddress));

				//At this point, we dump the function and the arguments
				ctx.getDataDumper().writeRoutineDumpLine(data);
				//Now we dump the current tainted memory
				std::vector<std::pair<ADDRINT, UINT16>> vec = taintController.getTaintedMemoryVector();
				//In the case we don't have tainted memory yet, we write nothing
				//THIS MAY GET DEPRECATED, REVISE IT LATER
				if (!vec.empty()) {
					ctx.getDataDumper().writeCurrentTaintedMemoryDump(ip, vec);
				}
				
			}
		}

		PIN_UnlockClient();
		
	}

	static void genericRoutineInstrumentExit(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, ADDRINT retVal, UINT32 instSize, CONTEXT* localCtx, THREADID tid)
	{
		PIN_LockClient();
		if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isMainExecutable(branchTargetAddress) ||
			scopeFilterer.isScopeImage(ip) || scopeFilterer.isScopeImage(branchTargetAddress))
		{
			if (branchTaken)
			{
				auto it = genericRoutineCalls.find(branchTargetAddress);
				if (it == genericRoutineCalls.end())
				{
					//LOG_ALERT("Tried to instrument generic routine at exit, but entry not found: " << to_hex_dbg(ip) << " | " << to_hex_dbg(branchTargetAddress));
				}
				else
				{
					//LOG_DEBUG("Found retIP in the generic routine calls map");
					
					//At this point, we dump the function and the arguments
					struct UTILS::IO::DataDumpLine::func_dll_names_dump_line_t data;
					data = it->second;
					ctx.getDataDumper().writeRoutineDumpLine(data);
					//Now we dump the current tainted memory
					std::vector<std::pair<ADDRINT, UINT16>> vec = taintController.getTaintedMemoryVector();
					//In the case we don't have tainted memory yet, we write nothing
					if (!vec.empty()) {
						ctx.getDataDumper().writeCurrentTaintedMemoryDump(branchTargetAddress, vec);
					}

					genericRoutineCalls.erase(branchTargetAddress);
				}
			}
		}

		//At this point, the reverse engineering module should have found a HL instruction
		//using the encoded heuristics. Otherwise, returning to another function signals the flush of the RevLog
		

		PIN_UnlockClient();
	}

};

#endif