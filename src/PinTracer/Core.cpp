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

#include "utils/inst/SyscallParser.h"
#include "utils/inst/InstructionWorker.h"
#include "taint/core/TaintManager.h"
#include "engine/core/InstrumentationManager.h"
#include "utils/inst/ScopeFilterer.h"

using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 insCount = 0; //number of dynamically executed instructions
UINT64 bblCount = 0; //number of dynamically executed basic blocks
UINT64 threadCount = 0; //total number of threads, including main thread

std::ostream* out = &std::cerr;
std::ostream* sysinfoOut = &std::cerr;
std::ostream* imageInfoOut = &std::cerr;

BOOL instructionLevelTracing = 0;
ScopeFilterer scopeFilterer;
extern TaintManager taintManager;

//ScopeFilterer scopeFilterer = NULL;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for PinTracer output");

KNOB< string > KnobSyscallFile(KNOB_MODE_WRITEONCE, "pintool", "s", "", "specify file name for syscalls info output");

KNOB< string > KnobImageFile(KNOB_MODE_WRITEONCE, "pintool", "i", "", "specify file name for images info output");

KNOB< string > KnobFilterlistFile(KNOB_MODE_WRITEONCE, "pintool", "f", "", "specify file name containing filter list of dlls on which to ignore tracing");

KNOB< BOOL > KnobInstLevelTrace(KNOB_MODE_WRITEONCE, "pintool", "t", "0", "activate instruction level tracing, faster but more reliable");

KNOB< BOOL > KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1",
	"count instructions, basic blocks and threads in the application");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
	std::cerr << "This tool prints out the number of dynamically executed " << std::endl
		<< "instructions, basic blocks and threads in the application." << std::endl
		<< std::endl;

	std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

	return -1;
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
	std::string dllName = IMG_Name(img);
	const ADDRINT entryAddr = IMG_EntryAddress(img);
	std::cerr << "NEW IMAGE DETECTED: " << dllName << " | Entry: " << std::hex << entryAddr << std::endl;
}

VOID RoutineTrace(RTN rtn, VOID* v)
{
	if(!RTN_Valid(rtn))
	{
		//std::cerr << "Null RTN" << std::endl;
		return;
	}

	const std::string rtnName = RTN_Name(rtn);
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
	if(!IMG_Valid(module))
	{
		//std::cerr << "Null IMG" << std::endl;
		return;
	}
	std::string dllName = IMG_Name(module);

	LOG_DEBUG("Routine: " << rtnName << " | DLLname: " << dllName);

	//Check if it should be tainted
	taintManager.routineLoadedEvent(rtn, dllName, rtnName);
	

	RTN_Close(rtn);
}

VOID TraceTrace(TRACE trace, VOID* v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS inst = BBL_InsHead(bbl); INS_Valid(inst); inst = INS_Next(inst))
		{
			if (scopeFilterer.isMainExecutable(inst) || (scopeFilterer.wasMainExecutableReached() &&
				!scopeFilterer.hasMainExecutableExited())) {
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


void TraceBase(TRACE trace, VOID* v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS inst = BBL_InsHead(bbl); INS_Valid(inst); inst = INS_Next(inst))
		{		
			RTN rtn = INS_Rtn(inst);
			ADDRINT addr = INS_Address(inst);
			IMG dll = IMG_FindByAddress(addr);
			if (!IMG_Valid(dll))
			{
			
				return;
			}
			std::string dllName = IMG_Name(dll);
			
			if (RTN_Name(rtn) == "recv")
			{
				//LOG_ALERT("FOUND RECV, dll:"<<dllName);
			}

			InstrumentationManager instManager;
			//if (scopeFilterer.isMainExecutable(inst)) {
			instManager.instrumentInstruction(inst);
			INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
				INS_Address(inst), IARG_UINT32, INS_Size(inst),
				IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
			//}
		}
	}
}



/*!
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

 /*!
  * Print out analysis results.
  * This function is called when the application exits.
  * @param[in]   code            exit code of the application
  * @param[in]   v               value specified by the tool in the
  *                              PIN_AddFiniFunction function call
  */
VOID Fini(INT32 code, VOID* v)
{
	/**out << "===============================================" << endl;
	*out << "MyPinTool analysis results: " << endl;
	*out << "Number of instructions: " << insCount << endl;
	*out << "Number of basic blocks: " << bblCount << endl;
	*out << "Number of threads: " << threadCount << endl;
	*out << "===============================================" << endl;*/
	std::cerr << "Finished" << std::endl;
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
	taintManager.registerTaintSource("C:\\Windows\\System32\\WS2_32.dll", "recv", 4);
	//taintManager.registerTaintSource("C:\\Users\\Marcos\\source\\repos\\h3xduck\\TFM\\samples\\tcp_client.exe", "ANY_FUNC_IN_DLL", 0);

	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	string fileName = KnobOutputFile.Value();
	string sysinfoFilename = KnobSyscallFile.Value();
	string imageInfoFilename = KnobImageFile.Value();
	string filterlistFilename = KnobFilterlistFile.Value();
	instructionLevelTracing = KnobInstLevelTrace.Value();

	if (!fileName.empty())
	{
		out = new std::ofstream(fileName.c_str());
	}

	if (!sysinfoFilename.empty())
	{
		sysinfoOut = new std::ofstream(sysinfoFilename.c_str());
	}

	if (!imageInfoFilename.empty())
	{
		imageInfoOut = new std::ofstream(imageInfoFilename.c_str());
	}

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
			RTN_AddInstrumentFunction(RoutineTrace, 0);
			TRACE_AddInstrumentFunction(TraceBase, 0);
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

		// Register function to be called when the application exits
		PIN_AddFiniFunction(Fini, 0);
	}

	std::cerr << "===============================================" << std::endl;
	std::cerr << "This application is instrumented by PinTracer" << std::endl;
	std::cerr << "Instrumentating instructions directly: " << instructionLevelTracing << "" << std::endl;
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
	std::cerr << "===============================================" << std::endl;

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
