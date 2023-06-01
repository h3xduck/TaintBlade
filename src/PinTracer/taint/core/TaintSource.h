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
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um
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
	//Args
	WINDOWS::LPVOID hFile;
	WINDOWS::LPVOID lpBuffer;
	WINDOWS::DWORD dwNumberOfBytesToRead;
	WINDOWS::LPDWORD lpdwNumberOfBytesRead;

	// https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile
};
static wininet_internetreadfile_t wininetInternetReadFile;

static std::tr1::unordered_map<ADDRINT, struct DataDumper::func_dll_names_dump_line_t> genericRoutineCalls;

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
	static VOID wsockRecvEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
	{
		int NUM_ARGS = 4;
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
		//LOG_DEBUG("Here0\n");
		ctx.updateLastMemoryValue(val, retVal);

		//LOG_DEBUG("Here1\n");

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
	};

	///////////////// WININET /////////////////
	static VOID wininetInternetReadFileEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
	{
		int NUM_ARGS = 4;

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

		std::string val = InstructionWorker::getMemoryValueHexString((ADDRINT)wininetInternetReadFile.lpBuffer, *(wininetInternetReadFile.lpdwNumberOfBytesRead));
		ctx.updateLastMemoryValue(val, *(wininetInternetReadFile.lpdwNumberOfBytesRead));

		std::vector<UINT16> colorVector = taintController.taintMemoryNewColor((ADDRINT)wininetInternetReadFile.lpBuffer, *(wininetInternetReadFile.lpdwNumberOfBytesRead));
		//LOG_DEBUG("Logging original color:: DLL:" << dllName << " FUNC:" << funcName);
		int offset = 0;
		for (auto color : colorVector)
		{
			//Each 1 byte, we get a different color
			taintController.registerOriginalColor(color, *dllNameStr, *funcNameStr, (ADDRINT)((char*)(wininetInternetReadFile.lpBuffer) + offset), (UINT8)(((char*)wininetInternetReadFile.lpBuffer)[offset]));
			offset++;
		}

	};



	///////////////// MAIN (FOR TESTING). Taints RAX and RBX /////////////////
	static VOID mainEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
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
	VOID(*enterHandler)(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6) = NULL;
	VOID(*exitHandler)(ADDRINT, VOID*, VOID*) = NULL;

	TaintSource() {};
	TaintSource(const std::string dllName, const std::string funcName, int numArgs, 
		VOID(*enter)(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6),
		VOID(*exit)(ADDRINT, VOID*, VOID*));

	void taintSourceLogAll();

	static VOID genericRoutineInstrumentEnter(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, UINT32 instSize, ADDRINT nextInstAddr, CONTEXT* localCtx, THREADID tid,
		VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
	{
		PIN_LockClient();
		
		//Only if we are going from main dll to another, or another scoped image
		if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isMainExecutable(branchTargetAddress) ||
			scopeFilterer.isScopeImage(ip) || scopeFilterer.isScopeImage(branchTargetAddress))
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
				genericRoutineCalls.insert(std::make_pair<ADDRINT, struct DataDumper::func_dll_names_dump_line_t>(nextInstAddr, data));
				//LOG_DEBUG("Inserted entry jump at " << to_hex_dbg(branchTargetAddress));

				//At this point, we dump the function and the arguments
				ctx.getDataDumper().writeRoutineDumpLine(data);
				//Now we dump the current tainted memory
				std::vector<std::pair<ADDRINT, UINT16>> vec = taintController.getTaintedMemoryVector();
				//In the case we don't have tainted memory yet, we write nothing
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
					struct DataDumper::func_dll_names_dump_line_t data;
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