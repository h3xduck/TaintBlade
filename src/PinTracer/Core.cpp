/*
 * Copyright (C) 2007-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

 /*! @file
  *  This is an example of the PIN tool that demonstrates some basic PIN APIs
  *  and could serve as the starting point for developing your first PIN tool
  */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <string>

//#include "config/GlobalConfig.h"
#include "utils/inst/SyscallParser.h"
#include "utils/inst/InstructionWorker.h"
#include "taint/core/TaintManager.h"
#include "engine/core/InstrumentationManager.h"
#include "utils/inst/ScopeFilterer.h"
#include "utils/inst/PerformanceOperator.h"
#include "config/Names.h"
#include "utils/io/DataDumper.h"
#include "taint/core/TaintSource.h"
#include "test/TestEngine.h"
#include "taint/data/TagLog.h"
#include "reversing/protocol/ProtocolReverser.h"

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

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT32 insCount = 0; //number of dynamically executed instructions
UINT32 bblCount = 0; //number of dynamically executed basic blocks
UINT32 threadCount = 0; //total number of threads, including main thread
UINT32 timeoutMillis = 0; //Number of milliseconds to wait until the tracer halts the program execution automatically. If set to 0, the timeout is not active

std::ostream* out = &std::cerr;
std::ostream* sysinfoOut = &std::cerr;
std::ostream* imageInfoOut = &std::cerr;
std::ofstream debugFile;

std::string mainImageName;
BOOL instructionLevelTracing = 0;

//Determines whether to ask for user input after detecting a new image, deciding whether it should be traced or not
bool settingAskForIndividualImageTrace = 0;
bool settingTraceAllImages = 0;

ScopeFilterer scopeFilterer;
extern TaintManager taintManager;
extern TestEngine globalTestEngine;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< std::string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for PinTracer output");

KNOB< std::string > KnobSyscallFile(KNOB_MODE_WRITEONCE, "pintool", "s", "", "specify file name for syscalls info output");

KNOB< std::string > KnobImageFile(KNOB_MODE_WRITEONCE, "pintool", "i", "", "specify file name for images info output");

KNOB< std::string > KnobFilterlistFile(KNOB_MODE_WRITEONCE, "pintool", "f", "", "specify file name containing filter list of dlls on which to ignore tracing");

KNOB< std::string > KnobDebugFile(KNOB_MODE_WRITEONCE, "pintool", "d", "", "specify file name where to store debug logs");

KNOB< BOOL > KnobInstLevelTrace(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "activate instruction level tracing, faster but more reliable");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
	"count instructions, basic blocks and threads in the application");

KNOB< std::string > KnobTestFile(KNOB_MODE_WRITEONCE, "pintool", "test", "", "activate test mode, specifies input file for reading tests");

KNOB< std::string > KnobTaintSourceFile(KNOB_MODE_WRITEONCE, "pintool", "taint", "", "specifies a file with dll+func combos to register as taint sources");
KNOB< std::string > KnobTracePointsFile(KNOB_MODE_WRITEONCE, "pintool", "trace", "tracepoints.txt", "specifies a file with dll+func+numargs combos to register as trace points");
KNOB< std::string > KnobNopSectionsFile(KNOB_MODE_WRITEONCE, "pintool", "nopsections", "nopsections.txt", "specifies a file with dll+func+start+end combos to register the code sections that will not be executed");
KNOB< std::string > KnobDllIncludeFile(KNOB_MODE_WRITEONCE, "pintool", "dllinclude", "dllinclude.txt", "specifies a file with dlls to be traced (and not just the main image)");


KNOB< BOOL > KnobAskForIndividualImageTrace(KNOB_MODE_WRITEONCE, "pintool", "choosetraceimages", "", "Ask for user before including any image in the list of images to trace. Otherwise, only main image is traced");
KNOB< BOOL > KnobTraceAllImages(KNOB_MODE_WRITEONCE, "pintool", "traceallimages", "", "Force program to trace all images, without asking user input. Overrides choosetraceimages flag.");

KNOB<UINT32> KnobAnalysisTimeout(KNOB_MODE_WRITEONCE, "pintool", "timeout", "", "If this flag is set, it specifies the number of milliseconds to wait until the analysis stops itself automatically");
/* ===================================================================== */
// Utilities
/* ===================================================================== */

/**
Print out help message.
*/
INT32 Usage()
{
	std::cerr << "This tool prints out the number of dynamically executed " << std::endl
		<< "instructions, basic blocks and threads in the application." << std::endl
		<< std::endl;

	std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

	return -1;
}

//Deletes all previous dfx files in the directory
void cleanDfxFiles()
{
	WINDOWS::HANDLE hFind;
	WINDOWS::WIN32_FIND_DATA FindFileData;

	if ((hFind = FindFirstFile("./*.dfx", &FindFileData)) != ((WINDOWS::HANDLE)(WINDOWS::LONG_PTR)-1)) 
	{
		do 
		{
			int res = std::remove(FindFileData.cFileName);
			LOG_DEBUG("Cleaning old output file " << FindFileData.cFileName << " (result: " << res << ")" << std::endl);
		} while (FindNextFile(hFind, &FindFileData));
		WINDOWS::FindClose(hFind);
	}
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */


EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
	EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
	EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
	std::string excStr = PIN_ExceptionToString(pExceptInfo);
	
	std::cerr << "Exception code: " << c << " | Exception class " << cl << "	Info: " << PIN_ExceptionToString(pExceptInfo) << std::endl << "Exception info: " << excStr << std::endl;
	return EHR_UNHANDLED;
}


EXCEPT_HANDLING_RESULT printInstructionOpcodesHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* appContextArg)
{
	std::cerr << "Caught an exception at the application level, code " << PIN_GetExceptionCode(pExceptInfo) << " | Info:" << PIN_ExceptionToString(pExceptInfo) << std::endl;
	// Get the application IP where the exception occurred from the application context
	CONTEXT* appCtxt = (CONTEXT*)appContextArg;
	ADDRINT faultIp = PIN_GetContextReg(appCtxt, REG_INST_PTR);

	// raise the exception at the application IP, so the application can handle it as it wants to
	PIN_SetExceptionAddress(pExceptInfo, faultIp);
	PIN_RaiseException(appCtxt, tid, pExceptInfo);

	return EHR_CONTINUE_SEARCH;
}

VOID printInstructionOpcodes(VOID* ip, /*std::string instAssembly,*/ uint32_t instSize, CONTEXT* ctx, THREADID tid)
{
	PIN_LockClient();
	PIN_TryStart(tid, printInstructionOpcodesHandler, ctx);
	
	std::stringstream tmpstr;
	tmpstr << std::hex << ip;
	uint8_t opcodes[15];
	PIN_SafeCopy(opcodes, ip, instSize);
	*out << tmpstr.str() << "\t";
	for (uint32_t ii = 0; ii < instSize; ii++)
	{
		*out << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(opcodes[ii]) << " ";
	}

	*out << std::endl;

	PIN_TryEnd(tid);
	PIN_UnlockClient();
}

VOID registerControlFlowInst(ADDRINT ip, ADDRINT branchTargetAddress, UINT32 instSize, CONTEXT* ctx, THREADID tid, 
	VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
	PIN_LockClient();

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
	
	//Filter by application
	//if (dllFrom.find("nc64") != std::string::npos)
	{
		*imageInfoOut << "--FROM-- DLL: " << std::hex << dllFrom << " | BaseAddr: " << baseAddrFrom << " | Addr: " << ip << " | RoutineName: " << routineNameFrom << std::endl;
		*imageInfoOut << "++ TO ++ DLL: " << dllTo << " | BaseAddr: " << baseAddrTo << " | Addr: " << branchTargetAddress << " | RoutineName: " << routineNameTo << std::endl;
		std::wstring res0 = InstructionWorker::printFunctionArgument((void*)arg0);
		std::string resW0(res0.begin(), res0.end());
		*imageInfoOut << resW0 << std::endl;
		std::wstring res1 = InstructionWorker::printFunctionArgument((void*)arg1);
		std::string resW1(res1.begin(), res1.end());
		*imageInfoOut << resW1 << std::endl;
		std::wstring res2 = InstructionWorker::printFunctionArgument((void*)arg2);
		std::string resW2(res2.begin(), res2.end());
		*imageInfoOut << resW2 << std::endl;
		std::wstring res3 = InstructionWorker::printFunctionArgument((void*)arg3);
		std::string resW3(res3.begin(), res3.end());
		*imageInfoOut << resW3 << std::endl;
		std::wstring res4 = InstructionWorker::printFunctionArgument((void*)arg4);
		std::string resW4(res4.begin(), res4.end());
		*imageInfoOut << resW4 << std::endl;
		std::wstring res5 = InstructionWorker::printFunctionArgument((void*)arg5);
		std::string resW5(res5.begin(), res5.end());
		*imageInfoOut << resW5 << std::endl;
		/**imageInfoOut << InstructionWorker::printFunctionArgument((void*)arg1) << std::endl;
		*imageInfoOut << InstructionWorker::printFunctionArgument((void*)arg2) << std::endl;
		*imageInfoOut << InstructionWorker::printFunctionArgument((void*)arg3) << std::endl;
		*imageInfoOut << InstructionWorker::printFunctionArgument((void*)arg4) << std::endl;
		*imageInfoOut << InstructionWorker::printFunctionArgument((void*)arg5) << std::endl;*/

	}

	PIN_UnlockClient();
}



VOID recvRoutineAnalyze(ADDRINT ip, THREADID tid, VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
	/*
		int recv(
	  [in]  SOCKET s,
	  [out] char   *buf,
	  [in]  int    len,
	  [in]  int    flags
		);
	*/
	PIN_LockClient();

	std::wstring bufres = InstructionWorker::printFunctionArgument((void*)arg1);
	std::string buf(bufres.begin(), bufres.end());
	std::wstring lenres = InstructionWorker::printFunctionArgument((void*)arg2);
	std::string len(lenres.begin(), lenres.end());
	std::wstring res0 = InstructionWorker::printFunctionArgument((void*)arg0);
	std::string resW0(res0.begin(), res0.end());
	std::cerr << resW0 << std::endl;
	std::wstring res1 = InstructionWorker::printFunctionArgument((void*)arg1);
	std::string resW1(res1.begin(), res1.end());
	std::cerr << resW1 << std::endl;
	std::wstring res2 = InstructionWorker::printFunctionArgument((void*)arg2);
	std::string resW2(res2.begin(), res2.end());
	std::cerr << resW2 << std::endl;
	std::wstring res3 = InstructionWorker::printFunctionArgument((void*)arg3);
	std::string resW3(res3.begin(), res3.end());
	std::cerr << resW3 << std::endl;
	std::wstring res4 = InstructionWorker::printFunctionArgument((void*)arg4);
	std::string resW4(res4.begin(), res4.end());
	std::cerr << resW4 << std::endl;
	std::wstring res5 = InstructionWorker::printFunctionArgument((void*)arg5);
	std::string resW5(res5.begin(), res5.end());
	std::cerr << resW5 << std::endl;
	std::cerr << "RECV::	 arg1(*buf): " << buf << " | len(arg2):" << std::endl;

	PIN_UnlockClient();
}


VOID registerIndirectControlFlowInst(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, UINT32 instSize, CONTEXT* ctx, THREADID tid,
	VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
	if (branchTaken) {
		registerControlFlowInst(ip, branchTargetAddress, instSize, ctx, tid, arg0, arg1, arg2, arg3, arg4, arg5);
	}
}

VOID InstructionTrace(INS inst, VOID* v)
{
	
	INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
		INS_Address(inst), IARG_UINT32, INS_Size(inst),
		IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

	//If it is a call, jump, ret, etc... We will register to which function and module the execution flow is going.
	//Note that far jumps are not covered under control flow, and sometimes appear in Windows
	if (INS_IsControlFlow(inst) || INS_IsFarJump(inst))
	{
		INS_InsertCall(
			inst, IPOINT_BEFORE, (AFUNPTR)registerControlFlowInst, 
			IARG_ADDRINT, INS_Address(inst), 
			IARG_BRANCH_TARGET_ADDR,
			IARG_UINT32, INS_Size(inst),
			IARG_CONST_CONTEXT, 
			IARG_THREAD_ID, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
			IARG_END);
	}
	
}

VOID SyscallTrace(THREADID threadIndex, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v)
{
	ADDRINT syscallNumber = PIN_GetSyscallNumber(ctx, std);
	*sysinfoOut << std::dec << "SYSCALL " << (int)syscallNumber << std::endl;
	ADDRINT syscallArgs[4];
	syscallArgs[0] = PIN_GetSyscallArgument(ctx, std, 0);
	syscallArgs[1] = PIN_GetSyscallArgument(ctx, std, 1);
	syscallArgs[2] = PIN_GetSyscallArgument(ctx, std, 2);
	syscallArgs[3] = PIN_GetSyscallArgument(ctx, std, 3);
	for (int ii = 0; ii < 4; ii++)
	{
		if (syscallArgs[ii] != NULL)
		{
			*sysinfoOut << "ARG " << ii << ":\n" << syscallArgs[ii] << std::endl;
		}
	}
	*sysinfoOut << "\n";

	SyscallParser::printSyscallAttempt(sysinfoOut, syscallNumber, syscallArgs);
	
	//cerr << "Syscall" << endl;
}

VOID ImageTrace(IMG img, VOID* v)
{
	PIN_LockClient();
	
	std::string dllName = IMG_Name(img);
	const ADDRINT entryAddr = IMG_EntryAddress(img);
	//tolower
	std::transform(dllName.begin(), dllName.end(), dllName.begin(), [](unsigned char c) { return std::tolower(c); });
	std::cerr << "NEW IMAGE DETECTED: " << dllName << " | Entry: " << std::hex << entryAddr << std::endl;
	LOG_DEBUG("NEW IMAGE DETECTED: " << dllName << " | Entry: " << std::hex << entryAddr << std::dec);

	//Register that we found a new image
	ctx.getExecutionManager().addImage(img);

	//Detect the name of the main image, and restrict all tracing to it
	if (mainImageName.empty() && IMG_IsMainExecutable(img)) {
		mainImageName = IMG_Name(img);
		//Only the specified program is to be instrumented
		scopeFilterer = ScopeFilterer(mainImageName);
	}
	//Check if we must trace all images because the user requested it like that via program flags
	else if (settingTraceAllImages) {
		scopeFilterer.addScopeImage(img);
	}
	//Check if we should trace this routine, even if it is not the main one
	else if (settingAskForIndividualImageTrace)
	{
		std::cout << "Should we trace the image \"" << dllName << "\"? y/n: ";
		char c;
		while (((c = getchar()) != 'y') && (c != 'n'));
		if (c == 'y')
		{
			//Add the image to traceable images
			scopeFilterer.addScopeImage(img);
			LOG_DEBUG("Added image " << dllName << " to the scopable images list");
		}
		else
		{
			LOG_DEBUG("Decided not to include image " << dllName << " to the scopable images list");
		}
	}

	PIN_UnlockClient();
}

VOID TraceTrace(TRACE trace, VOID* v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS inst = BBL_InsHead(bbl); INS_Valid(inst); inst = INS_Next(inst))
		{
			if (scopeFilterer.isMainExecutable(inst) || scopeFilterer.isScopeImage(inst) ||
				(scopeFilterer.wasMainExecutableReached() && !scopeFilterer.hasMainExecutableExited())) {
				INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
					INS_Address(inst), IARG_UINT32, INS_Size(inst),
					IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

				//Will only happen at the end of the BBL, although if it is a branch it may not be taken
				if (INS_IsControlFlow(inst) || INS_IsFarJump(inst))
				{
					INS_InsertCall(
						inst, IPOINT_BEFORE, (AFUNPTR)registerControlFlowInst,
						IARG_ADDRINT, INS_Address(inst),
						IARG_BRANCH_TARGET_ADDR,
						IARG_BRANCH_TAKEN,
						IARG_UINT32, INS_Size(inst),
						IARG_CONST_CONTEXT,
						IARG_THREAD_ID,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
						IARG_END);
				}
			}			
		}
	}
}

VOID ContextChangeTrace(THREADID tid, CONTEXT_CHANGE_REASON reason, const CONTEXT* ctxFrom, CONTEXT* ctxTo, INT32 info, VOID* v)
{
	std::cerr << "Detected ctx change" << std::endl;
	PIN_LockClient();

	//Get RIP at both contexts
	const ADDRINT addrFrom = PIN_GetContextReg(ctxFrom, REG_INST_PTR);
	const ADDRINT addrTo = PIN_GetContextReg(ctxTo, REG_INST_PTR);

	//Find corrresponding modules for those addresses
	IMG moduleFrom = IMG_FindByAddress(addrFrom);
	IMG moduleTo = IMG_FindByAddress(addrTo);
	std::string dllFrom = IMG_Name(moduleFrom);
	std::string dllTo = IMG_Name(moduleTo);

	*imageInfoOut << "ModuleFrom: " << dllFrom << " | " << addrFrom << std::endl;
	*imageInfoOut << "ModuleTo: " << dllTo << " | " << addrTo << "\n" << std::endl;


	PIN_UnlockClient();
}


VOID instrumentControlFlow(ADDRINT ip, ADDRINT branchTargetAddress, BOOL branchTaken, UINT32 instSize, CONTEXT* ctx, THREADID tid,
	VOID* arg0, VOID* arg1, VOID* arg2, VOID* arg3, VOID* arg4, VOID* arg5)
{
	PIN_LockClient();

	//We trace the control flow if it is the main image or one of the scoped images
	if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isMainExecutable(branchTargetAddress) ||
		scopeFilterer.isScopeImage(ip) || scopeFilterer.isScopeImage(branchTargetAddress))
	{
		if (branchTaken)
		{
			//If we are here, we are interested in logging this jump
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

			//Only print arguments if it the target is another function. Some random dll should not be calling any function from us
			if (scopeFilterer.isMainExecutable(ip) || scopeFilterer.isScopeImage(ip))
			{
				//Logging in imageinfo logs
				*imageInfoOut << "--FROM-- DLL: " << std::hex << dllFrom << " | BaseAddr: " << baseAddrFrom << " | Addr: " << ip << " | RoutineName: " << routineNameFrom << std::endl;
				*imageInfoOut << "++ TO ++ DLL: " << dllTo << " | BaseAddr: " << baseAddrTo << " | Addr: " << branchTargetAddress << " | RoutineName: " << routineNameTo << std::endl;
				std::wstring res0 = InstructionWorker::printFunctionArgument((void*)arg0);
				std::string resW0(res0.begin(), res0.end());
				*imageInfoOut << resW0 << std::endl;
				std::wstring res1 = InstructionWorker::printFunctionArgument((void*)arg1);
				std::string resW1(res1.begin(), res1.end());
				*imageInfoOut << resW1 << std::endl;
				std::wstring res2 = InstructionWorker::printFunctionArgument((void*)arg2);
				std::string resW2(res2.begin(), res2.end());
				*imageInfoOut << resW2 << std::endl;
				std::wstring res3 = InstructionWorker::printFunctionArgument((void*)arg3);
				std::string resW3(res3.begin(), res3.end());
				*imageInfoOut << resW3 << std::endl;
				std::wstring res4 = InstructionWorker::printFunctionArgument((void*)arg4);
				std::string resW4(res4.begin(), res4.end());
				*imageInfoOut << resW4 << std::endl;
				std::wstring res5 = InstructionWorker::printFunctionArgument((void*)arg5);
				std::string resW5(res5.begin(), res5.end());
				*imageInfoOut << resW5 << std::endl;
			}

			//Dumping routine in dumpfiles
			DataDumper::func_dll_names_dump_line_t data;
			data.dllFrom = dllFrom;
			data.funcFrom = routineNameFrom;
			data.memAddrFrom = baseAddrFrom;
			data.dllTo = dllTo;
			data.funcTo = routineNameTo;
			data.memAddrTo = baseAddrTo;

		}
		else
		{
			//LOG_DEBUG("Branch not taken");
		}
	}
	PIN_UnlockClient();

	return;
}

VOID RoutineTrace(RTN rtn, VOID* v)
{
	if (!RTN_Valid(rtn))
	{
		//std::cerr << "Null RTN" << std::endl;
		return;
	}

	std::string rtnName = RTN_Name(rtn);
	RTN_Open(rtn);

	ADDRINT firstAddr = RTN_Address(rtn);

	const INS insHead = RTN_InsHead(rtn);
	if (!INS_Valid(insHead))
	{
		RTN_Close(rtn);
		return;
	}
	InstrumentationManager instManager;
	/*if (!scopeFilterer.isMainExecutable(insHead)) {
		RTN_Close(rtn);
		return;
	}*/


	IMG module = IMG_FindByAddress(firstAddr);
	if (!IMG_Valid(module))
	{
		//std::cerr << "Null IMG" << std::endl;
		RTN_Close(rtn);
		return;
	}
	std::string dllName = IMG_Name(module);
	//tolower
	std::transform(dllName.begin(), dllName.end(), dllName.begin(), [](unsigned char c) { return std::tolower(c); });
	std::transform(rtnName.begin(), rtnName.end(), rtnName.begin(), [](unsigned char c) { return std::tolower(c); });

	//LOG_DEBUG("Routine: " << rtnName << " | DLLname: " << dllName);

	//Trace the function arguments, if the routine is selected to be traced by the user
	ctx.getTraceManager().traceFunction(rtn, dllName, rtnName);

	//Check if it should be tainted
	taintManager.routineLoadedEvent(rtn, dllName, rtnName);

	RTN_Close(rtn);
}

void TraceBase(TRACE trace, VOID* v)
{
	//Instrument each instruction on each basic block
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{		
			RTN rtn = INS_Rtn(ins);
			ADDRINT addr = INS_Address(ins);
			IMG dll = IMG_FindByAddress(addr);
			if (!IMG_Valid(dll))
			{
				return;
			}
			std::string dllName = IMG_Name(dll);
			//tolower
			std::transform(dllName.begin(), dllName.end(), dllName.begin(), [](unsigned char c) { return std::tolower(c); });

			//Track where we are in the execution
			PerformanceOperator::trackCurrentState(ins);

			//We will check if the instruction belongs to a NOP-ed section, and in this case we will jump over the nop-ed range
			if (ctx.getExecutionManager().isInNopSection(ins))
			{
				ctx.getExecutionManager().instrumentNopSection(ins);
				continue;
			}
			
			//Instrumentation of instructions - calls the tainting engine and all the underlaying analysis ones
			InstrumentationManager instManager;
			if (scopeFilterer.isMainExecutable(ins) || scopeFilterer.isScopeImage(ins)) {
				instManager.instrumentInstruction(ins);

			#if(CONFIG_INST_LOG_FILES==1)
				INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
					INS_Address(inst), IARG_UINT32, INS_Size(inst),
					IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);

				
			#endif
			}

			//Register jumps
			if (INS_IsControlFlow(ins) || INS_IsFarJump(ins))
				{
				//For debugging
					/*INS_InsertCall(
						inst, IPOINT_BEFORE, (AFUNPTR)instrumentControlFlow,
						IARG_ADDRINT, INS_Address(inst),
						IARG_BRANCH_TARGET_ADDR,
						IARG_BRANCH_TAKEN,
						IARG_UINT32, INS_Size(inst),
						IARG_CONST_CONTEXT,
						IARG_THREAD_ID,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
						IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
						IARG_END);*/

				//Data dumping
					if (INS_IsRet(ins))
					{
						INS_InsertCall(
							ins, IPOINT_BEFORE, (AFUNPTR)TaintSource::genericRoutineInstrumentExit,
							IARG_ADDRINT, INS_Address(ins),
							IARG_BRANCH_TARGET_ADDR,
							IARG_BRANCH_TAKEN,
							IARG_FUNCRET_EXITPOINT_VALUE,
							IARG_UINT32, INS_Size(ins),
							IARG_CONST_CONTEXT,
							IARG_THREAD_ID,
							IARG_END);
					}
					else
					{
						INS_InsertCall(
							ins, IPOINT_BEFORE, (AFUNPTR)TaintSource::genericRoutineInstrumentEnter,
							IARG_ADDRINT, INS_Address(ins),
							IARG_BRANCH_TARGET_ADDR,
							IARG_BRANCH_TAKEN,
							IARG_UINT32, INS_Size(ins),
							IARG_ADDRINT, INS_NextAddress(ins),
							IARG_CONST_CONTEXT,
							IARG_THREAD_ID,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
							IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
							IARG_END);
					}
			}
		}

	}
}

/**
Executed when the process executes another (or creates a child process)
*/
BOOL FollowChild(CHILD_PROCESS cProcess, VOID* userData)
{
	std::cout << "Now executing a child process with PID: " << PIN_GetPid() <<std::endl;
	return TRUE;
}

/**
 * Increase counter of threads in the application.
 * This function is called for every thread created by the application when it is
 * about to start running (including the root thread).
 * @param[in]   threadIndex     ID assigned by PIN to the new thread
 * @param[in]   ctxt            initial register state for the new thread
 * @param[in]   flags           thread creation flags (OS specific)
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddThreadStartFunction function call
 */
 //VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) { threadCount++; }


void dumpEndInfo()
{
	taintController.printTaint();
	taintController.dumpTaintLog();
	taintController.dumpTaintLogPrettified(29);
	taintController.dumpTagLogOriginalColors();
	PerformanceOperator::measureChrono();

	//Dump original colors vector
	std::vector<std::pair<UINT16, TagLog::original_color_data_t>> orgVec = taintController.getOriginalColorsVector();
	dataDumper.writeOriginalColorDump(orgVec);

	//Dump color transformations
	std::vector<Tag> colorTrans = taintController.getColorTransVector();
	dataDumper.writeColorTransformationDump(colorTrans);

	//Dump RevAtoms
	//ctx.getRevContext()->printRevLogCurrent();

	//Dump info about heuristics found
	ctx.getRevContext()->dumpFoundHeuristics();
}

void resolveProtocol()
{
	//Reverse the protocols using the found heuristics
	REVERSING::PROTOCOL::reverseProtocol();
}

 /*!
  * Print out analysis results.
  * This function is called when the application exits.
  * @param[in]   code            exit code of the application
  * @param[in]   v               value specified by the tool in the
  *                              PIN_AddFiniFunction function call
  */
VOID Fini(INT32 code, VOID* v)
{
	std::cerr << "Finished" << std::endl;

	//Dump relevant info about program execution, tainting, etc
	dumpEndInfo();

	//Resolve the final form of the protocol
	resolveProtocol();

	//Evaluate tests
	globalTestEngine.evaluateTests();
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
	//Start instruction counter
	PerformanceOperator::startChrono();

	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	//Clean all .dfx files that were left from previous runs
	cleanDfxFiles();

	std::string fileName = KnobOutputFile.Value();
	std::string sysinfoFilename = KnobSyscallFile.Value();
	std::string imageInfoFilename = KnobImageFile.Value();
	std::string filterlistFilename = KnobFilterlistFile.Value();
	std::string debugFileFilename = KnobDebugFile.Value();
	std::string testFileFilename = KnobTestFile.Value();
	std::string taintSourceFileFilename = KnobTaintSourceFile.Value();
	std::string tracePointsFileFilename = KnobTracePointsFile.Value();
	std::string nopSectionsFileFilename = KnobNopSectionsFile.Value();
	std::string dllIncludeFileFilename = KnobDllIncludeFile.Value();
	settingAskForIndividualImageTrace = KnobAskForIndividualImageTrace.Value();
	settingTraceAllImages = KnobTraceAllImages.Value();
	timeoutMillis = KnobAnalysisTimeout.Value();
	
	instructionLevelTracing = KnobInstLevelTrace.Value();
	
	if (!fileName.empty())
	{
		out = new std::ofstream(getFilenameFullName(fileName).c_str());
	}

	if (!sysinfoFilename.empty())
	{
		sysinfoOut = new std::ofstream(getFilenameFullName(sysinfoFilename).c_str());
	}

	if (!imageInfoFilename.empty())
	{
		imageInfoOut = new std::ofstream(getFilenameFullName(imageInfoFilename).c_str());
	}

	if (!debugFileFilename.empty())
	{
		debugFile.open(getFilenameFullName(debugFileFilename).c_str());
	}

	if (!testFileFilename.empty())
	{
		std::cerr << "Test mode now active" << std::endl;
		globalTestEngine.setTestLevel(TestEngine::ACTIVE);
		//Read the tests to perform
		globalTestEngine.loadTestsFromFile(testFileFilename);

		//Redirect all logging TODO?
		/*std::ostream* out = &std::cerr;
		std::ostream* sysinfoOut = &std::cerr;
		std::ostream* imageInfoOut = &std::cerr;
		std::ostream* debugFile = &std::cerr;*/

	}

	if (!taintSourceFileFilename.empty())
	{
		//If a taint source file was specified, we load DLL+FUNC combos from there
		std::cerr << "Loading taint sources dynamically from " << taintSourceFileFilename << std::endl;
		LOG_DEBUG("Loading taint sources from " << taintSourceFileFilename);

		std::ifstream infile(taintSourceFileFilename);
		std::string line;
		//The file is made of lines with FUNC DLL <num arguments>
		while (std::getline(infile, line))
		{
			std::istringstream isdata(line);
			std::string dllName;
			//DLL
			std::getline(isdata, dllName, ' ');
			//FUNC
			std::string funcName;
			std::getline(isdata, funcName, ' ');
			//FUNC
			std::string numArgs;
			std::getline(isdata, numArgs, ' ');
			taintManager.registerTaintSource(dllName, funcName, atoi(numArgs.c_str()));
		}

	}

	if (!tracePointsFileFilename.empty())
	{
		//If a taint source file was specified, we load DLL+FUNC combos from there
		std::cerr << "Loading trace points dynamically from " << tracePointsFileFilename << std::endl;
		LOG_DEBUG("Loading trace points from " << tracePointsFileFilename);

		std::ifstream infile(tracePointsFileFilename);
		std::string line;
		//The file is made of lines with FUNC DLL <num arguments> <user assembly lines>
		while (std::getline(infile, line))
		{
			std::istringstream isdata(line);
			std::string dllName;
			//DLL
			std::getline(isdata, dllName, ' ');
			std::transform(dllName.begin(), dllName.end(), dllName.begin(), [](unsigned char c) { return std::tolower(c); });
			//FUNC
			std::string funcName;
			std::getline(isdata, funcName, ' ');
			std::transform(funcName.begin(), funcName.end(), funcName.begin(), [](unsigned char c) { return std::tolower(c); });
			//args
			std::string numArgs;
			std::getline(isdata, numArgs, ' ');
			ctx.getTraceManager().addTracePoint(dllName, funcName, atoi(numArgs.c_str()));
		}
	}

	if (!nopSectionsFileFilename.empty())
	{
		//If a taint source file was specified, we load DLL+FUNC combos from there
		std::cerr << "Loading NOP sections from " << nopSectionsFileFilename << std::endl;
		LOG_DEBUG("Loading NOP sections from " << nopSectionsFileFilename);

		std::ifstream infile(nopSectionsFileFilename);
		std::string line;
		//The file is made of lines with DLL <start address> <end address>
		while (std::getline(infile, line))
		{
			std::istringstream isdata(line);
			std::string dllName;
			//DLL
			std::getline(isdata, dllName, ' ');
			//START
			std::string start;
			std::getline(isdata, start, ' ');
			//END
			std::string end;
			std::getline(isdata, end, ' ');

			//Finally, we get the lines of user assembly (if any) to be executed when NOP-ing the section
			std::string userAssemblyLines;
			std::vector<std::string> userAssemblyLinesVec;
			std::getline(isdata, userAssemblyLines, ' ');
			//We will parse them. They come separated with commas: instruction1,instruction2,instruction3,...instructionN
			std::istringstream isAssemblyLine(userAssemblyLines);

			std::string assemblyLine;
			while(std::getline(isAssemblyLine, assemblyLine, ','))
			{
				std::cerr << "LINE: " << assemblyLine << std::endl;
				if (!assemblyLine.empty())
				{
					userAssemblyLinesVec.push_back(assemblyLine);
					LOG_DEBUG("Found user assembly line: " << assemblyLine);
				}
			}

			ctx.getExecutionManager().registerNopSection(dllName, atoi(start.c_str()), atoi(end.c_str()), userAssemblyLinesVec);
		}
	}

	if (!dllIncludeFileFilename.empty())
	{
		//If a taint source file was specified, we load DLL+FUNC combos from there
		std::cerr << "Loading dll to trace from " << dllIncludeFileFilename << std::endl;
		LOG_DEBUG("Loading dlls from " << dllIncludeFileFilename);

		std::ifstream infile(dllIncludeFileFilename);
		std::string line;
		//The file is made of lines with FUNC DLL <num arguments> <user assembly lines>
		while (std::getline(infile, line))
		{
			std::istringstream isdata(line);
			std::string dllName;
			//DLL
			std::getline(isdata, dllName, ' ');

			std::cerr << dllName << " selected to be traced" << std::endl;
			LOG_DEBUG("Adding " << dllName << " to traced dlls");
			scopeFilterer.addScopeImage(dllName);
		}
	}
	
	//Registering analyzer timeout, if requested
	if (timeoutMillis != 0)
	{
		UTILS::IO::CommandCenter::registerAnalysisTimeout();
	}

	//Register taint sources - deprecated: now dynamically via flag
	//TODO - set program name dynamically
	taintManager.registerTaintSource(WS2_32_DLL, RECV_FUNC, 4);
	taintManager.registerTaintSource(WININET_DLL, INTERNET_READ_FILE_FUNC, 4);
	taintManager.registerTaintSource(HELLO_WORLD_PROG, ANY_FUNC_IN_DLL, 0);
	taintManager.registerTaintSource(TEST1_PROG, ANY_FUNC_IN_DLL, 0);
	taintManager.registerTaintSource(WSOCK32_DLL, RECV_FUNC, 4);

	PIN_InitSymbols();

	if (KnobCount)
	{
		// Register function to be called for every thread before it starts running
		//PIN_AddThreadStartFunction(ThreadStart, 0);

		//Instrumentation for every loaded process image (e.g. each loaded dll)
		IMG_AddInstrumentFunction(ImageTrace, 0);

		//PIN_AddContextChangeFunction(ContextChangeTrace, NULL);

		if (instructionLevelTracing == 0)
		{
			//Instrumenting from target of branch to unconditional branch (includes calls)
			//TRACE_AddInstrumentFunction(TraceTrace, 0);
			TRACE_AddInstrumentFunction(TraceBase, 0);
			RTN_AddInstrumentFunction(RoutineTrace, 0);
			
		}
		else if (instructionLevelTracing == 1)
		{
			//Instrumenting each instruction directly
			INS_AddInstrumentFunction(InstructionTrace, 0);
		}

		#ifdef _WIN32
		//Exception handling, Windows exclusive according to documentation
		PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);
		std::cerr << "Windows mode now active" << std::endl;
		#else
		PIN_AddSyscallEntryFunction(SyscallTrace, 0);
		std::cerr << "Linux mode now active" << std::endl;
		#endif

		//Follow any child process execution
		PIN_AddFollowChildProcessFunction(FollowChild, 0);

		// Register function to be called when the application exits
		PIN_AddFiniFunction(Fini, 0);
	}

	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by PinTracer" << std::endl;
	if(timeoutMillis!=0) std::cerr << "The analysis will stop itself in " << timeoutMillis/1000 << " seconds" << std::endl;
#ifdef TARGET_IA32E
	std::cerr << "Tracer running in x64 mode" << std::endl;
#else
	std::cerr << "Tracer running in x86 mode" << std::endl;
#endif 
	std::cerr << "Application PID: " << PIN_GetPid() << std::endl;
	std::cerr << "Instrumentating instructions directly: " << instructionLevelTracing << "" << std::endl;
	if (settingAskForIndividualImageTrace) {
		std::cerr << "Received request to ask for every new detected image" << std::endl;
	}else if (settingTraceAllImages) {
		std::cerr << "Received request to trace ALL images" << std::endl;
	}
	else {
		std::cerr << "Only the main image will be traced" << std::endl;
	}
	if (!KnobFilterlistFile.Value().empty())
	{
		std::cerr << "Using file " << KnobFilterlistFile.Value() << " for filtering traced DLL jumps" << std::endl;
	}
	if (!KnobOutputFile.Value().empty())
	{
		std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << std::endl;
	}
	if (!KnobSyscallFile.Value().empty())
	{
		std::cerr << "See file " << KnobSyscallFile.Value() << " for syscalls results" << std::endl;
	}
	if (!KnobDebugFile.Value().empty())
	{
		std::cerr << "See file " << KnobDebugFile.Value() << " for debug logs" << std::endl;
	}
	std::cerr << "===============================================" << std::endl;


	//Starts a background threat that periodically checks whether
	//we have any command from the user.
	UTILS::IO::CommandCenter::startCommandCenterJob();

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
