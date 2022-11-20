/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include "pin.H"
#include <iostream>
#include <fstream>
#include <errno.h>
#include <sys/syscall.h>
using namespace std;

/**
 * @brief This tool asserts that the value of RCX register, after returning from syscall
 * is the value of the address of the instruction after the syscall.
 */

/* ================================================================== */
// Global variables
/* ================================================================== */

BOOL tEnteredSyscall[PIN_MAX_THREADS];
std::ostream* out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for the tool's output");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool asserts that the return value of the RCX register" << endl
         << "after a syscall is exited, is the address of the instruction" << endl
         << "right after the syscall" << endl
         << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

VOID EnterSyscall(THREADID tid) { tEnteredSyscall[tid] = TRUE; }

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID SyscallExit(THREADID threadIndex, CONTEXT* ctxt, SYSCALL_STANDARD std, VOID* v)
{
    if (tEnteredSyscall[threadIndex])
    {
        ADDRINT rip = PIN_GetContextReg(ctxt, REG_RIP);
        ADDRINT rcx = PIN_GetContextReg(ctxt, REG_RCX);
        ASSERT(rcx == rip, "RCX = " + std::to_string(rcx) + "\nRIP (next instruction ptr) = " + std::to_string(rip));
        tEnteredSyscall[threadIndex] = FALSE;
    }
}

VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) { tEnteredSyscall[threadid] = FALSE; }

VOID Instruction(INS ins, VOID* v)
{
    RTN insRtn = INS_Rtn(ins);
    // We check NtAllocateVirtualMemory because this syscall is emulated and NtOpenFile is a syscall
    // that is directly dispatched. Both of these syscalls do not modify the context of the current thread.
    // We expect a fall through path from the entry point instruction to the corresponding syscall instruction.
    if (RTN_Valid(insRtn) && (RTN_Name(insRtn) == "NtAllocateVirtualMemory" || RTN_Name(insRtn) == "NtOpenFile"))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)EnterSyscall, IARG_THREAD_ID, IARG_END);
    }
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
    PIN_InitSymbolsAlt(EXPORT_SYMBOLS);
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();

    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
    }

    PIN_AddThreadStartFunction(ThreadStart, NULL);
    PIN_AddSyscallExitFunction(SyscallExit, NULL);
    INS_AddInstrumentFunction(Instruction, NULL);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */