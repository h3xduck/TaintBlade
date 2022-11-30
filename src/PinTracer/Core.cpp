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

#include "utils/SyscallParser.h"


using std::string;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 insCount = 0; //number of dynamically executed instructions
UINT64 bblCount = 0; //number of dynamically executed basic blocks
UINT64 threadCount = 0; //total number of threads, including main thread

std::ostream* out = &cerr;
std::ostream* sysinfoOut = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for PinTracer output");

KNOB< string > KnobSyscallFile(KNOB_MODE_WRITEONCE, "pintool", "s", "", "specify file name for syscalls info output");

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
	cerr << "This tool prints out the number of dynamically executed " << endl
		<< "instructions, basic blocks and threads in the application." << endl
		<< endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

/*!
 * Increase counter of the executed basic blocks and instructions.
 * This function is called for every basic block when it is about to be executed.
 * @param[in]   numInstInBbl    number of instructions in the basic block
 * @note use atomic operations for multi-threaded applications
 */
 /*VOID CountBbl(UINT32 numInstInBbl)
 {
	 bblCount++;
	 insCount += numInstInBbl;
 }*/

 /* ===================================================================== */
 // Instrumentation callbacks
 /* ===================================================================== */

 /*!
  * Insert call to the CountBbl() analysis routine before every basic block
  * of the trace.
  * This function is called every time a new trace is encountered.
  * @param[in]   trace    trace to be instrumented
  * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
  *                       function call
  */
  /*VOID Trace(TRACE trace, VOID* v)
  {
	  // Visit every basic block in the trace
	  for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	  {
		  // Insert a call to CountBbl() before every basic bloc, passing the number of instructions
		  BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)CountBbl, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
	  }
  }*/

EXCEPT_HANDLING_RESULT ExceptionHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* v)
{
	EXCEPTION_CODE c = PIN_GetExceptionCode(pExceptInfo);
	EXCEPTION_CLASS cl = PIN_GetExceptionClass(c);
	cerr << "Exception class " << cl << "	Info: " << PIN_ExceptionToString(pExceptInfo) << std::endl;
	return EHR_UNHANDLED;
}


EXCEPT_HANDLING_RESULT printInstructionOpcodesHandler(THREADID tid, EXCEPTION_INFO* pExceptInfo, PHYSICAL_CONTEXT* pPhysCtxt, VOID* appContextArg)
{
	cerr << "Caught an exception at the application level, code " << PIN_GetExceptionCode(pExceptInfo) << " | Info:" << PIN_ExceptionToString(pExceptInfo) << endl;
	// Get the application IP where the exception occurred from the application context
	CONTEXT* appCtxt = (CONTEXT*)appContextArg;
	ADDRINT faultIp = PIN_GetContextReg(appCtxt, REG_INST_PTR);

	// raise the exception at the application IP, so the application can handle it as it wants to
	PIN_SetExceptionAddress(pExceptInfo, faultIp);
	PIN_RaiseException(appCtxt, tid, pExceptInfo);

	return EHR_CONTINUE_SEARCH;
}

void printInstructionOpcodes(void* ip, std::string instAssembly, uint32_t instSize, CONTEXT* ctx, THREADID tid)
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
	*out << "\t" << instAssembly << std::endl;

	//*out << std::endl;

	PIN_TryEnd(tid);
	PIN_UnlockClient();
}

VOID InstructionTrace(INS inst, VOID* v)
{
	//cerr << "started" << std::endl;
	std::string disassemble = INS_Disassemble(inst);
	INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
		INS_Address(inst), IARG_PTR, new string(disassemble), IARG_UINT32, INS_Size(inst), 
		IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_END);
	//cerr << "ended" << std::endl;
}


VOID SyscallTrace(THREADID threadIndex, CONTEXT* ctx, SYSCALL_STANDARD std, VOID* v)
{
	SyscallParser sys_parser;
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

	sys_parser.print_syscall_attempt(sysinfoOut, syscallNumber, syscallArgs);
	
	//cerr << "Syscall" << endl;
}

void ImageTrace(IMG img, VOID* v)
{
	std::string dll_name = IMG_Name(img);
	cerr << "NEW IMAGE DETECTED: " << dll_name << std::endl;
}

VOID TraceTrace(TRACE trace, VOID* v)
{
	cerr << "started" << std::endl;
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		for (INS inst = BBL_InsHead(bbl); INS_Valid(inst); inst = INS_Next(inst))
		{
				INS_InsertCall(inst, IPOINT_BEFORE, (AFUNPTR)printInstructionOpcodes, IARG_ADDRINT,
					INS_Address(inst), /*IARG_PTR, new string(INS_Disassemble(inst)),*/ IARG_UINT32, INS_Size(inst), IARG_END);
			
		}
	}
	cerr << "ended" << std::endl;
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

	cerr << "Finished" << endl;

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
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	string fileName = KnobOutputFile.Value();
	string sysinfo_filename = KnobSyscallFile.Value();

	if (!fileName.empty())
	{
		out = new std::ofstream(fileName.c_str());
	}

	if (!sysinfo_filename.empty())
	{
		sysinfoOut = new std::ofstream(sysinfo_filename.c_str());
	}

	if (KnobCount)
	{
		// Register function to be called to instrument traces
		//TRACE_AddInstrumentFunction(Trace, 0);

		//Instrumenting each instruction
		INS_AddInstrumentFunction(InstructionTrace, 0);

		// Register function to be called for every thread before it starts running
		//PIN_AddThreadStartFunction(ThreadStart, 0);

		//Instrumentation for every loaded process image (e.g. each loaded dll)
		//IMG_AddInstrumentFunction(ImageTrace, 0);

		//TRACE_AddInstrumentFunction(TraceTrace, 0);

		#if defined(WIN32) || defined(_WIN32) || defined(__WIN32)
		//Exception handling, Windows exclusive according to documentation
		PIN_AddInternalExceptionHandler(ExceptionHandler, NULL);
		#else
		PIN_AddSyscallEntryFunction(SyscallTrace, 0);
		#endif

		// Register function to be called when the application exits
		PIN_AddFiniFunction(Fini, 0);
	}

	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by PinTracer" << endl;
	if (!KnobOutputFile.Value().empty())
	{
		cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
	}
	if (!KnobSyscallFile.Value().empty())
	{
		cerr << "See file " << KnobSyscallFile.Value() << " for syscalls results" << endl;
	}
	cerr << "===============================================" << endl;

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
