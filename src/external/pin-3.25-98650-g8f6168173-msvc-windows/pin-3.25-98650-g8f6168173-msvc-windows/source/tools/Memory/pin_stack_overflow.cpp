/*
 * Copyright (C) 2020-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include "pin.H"
using std::cerr;
using std::cout;
using std::endl;
using std::flush;
using std::ofstream;
using std::string;

// This tool causes Pin stack overflow exception and validates its proper handling.

// This knob defines Pin stack size in the same units as -thread_stack_size Pin knob.
// It is assumed that values of these knobs match for the test to work properly.
// Test launcher should ensure this.
KNOB< UINT32 > KnobStackSize(KNOB_MODE_WRITEONCE, "pintool", "stack_size", "1021",
                                                  "Size of the thread stack in KBytes when in PIN state");

// Exception handler
static void OnException(THREADID threadIndex, CONTEXT_CHANGE_REASON reason,
                        const CONTEXT* ctxtFrom, CONTEXT* ctxtTo, INT32 info, VOID* v)
{
    if (reason == CONTEXT_CHANGE_REASON_EXCEPTION || reason == CONTEXT_CHANGE_REASON_SIGNAL)
    {
        cerr << "Tool: Start handling exception." << endl;
        cerr.flush();
        UINT32 exceptionCode = info;
        ADDRINT exceptAddr   = PIN_GetContextReg(ctxtFrom, REG_INST_PTR);
        cerr << "Tool: Exception code " << std::hex << exceptionCode << "."
             << " Context IP " << std::hex << exceptAddr << "." << endl;
        cerr.flush();
    }
}

ADDRINT stackAlloc(UINT32 depth)
{
    ADDRINT arr[1024];
    // It is necessary to fill the array using external non-inlineable function invocation 
    // in order to avoid compiler optimizations that may eliminate array allocation in function stack frame.
    memset(arr, (int)depth, sizeof(arr));
    if (depth > 0)
    {
        // Use access to array to further supress compiler optimizations.
        return stackAlloc(depth - 1) + arr[depth];
    }
    else
    {
        return arr[0];
    }
}

VOID doStackOverflow()
{
    static BOOL runOnce = TRUE;
    if (runOnce)
    {
        runOnce = FALSE;
        // Call stack overflow function once before first executed instruction.
        // The test fills stack in units of 1K ADDRINT entries.
        // Recursion depth is specified in the stack fill units.
        // The number of stack fill units, corresponding to the specified stack size,
        // should confidently exceed actual stack size to guarantee stack overflow condition.
        cerr << stackAlloc((KnobStackSize.Value() / sizeof(ADDRINT)) + 16);
    }
}

VOID insCallback(INS ins, void* v) { INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(doStackOverflow), IARG_END); }

int main(INT32 argc, CHAR** argv)
{
    PIN_Init(argc, argv);
    cerr << std::hex;
    cerr.setf(std::ios::showbase);

    INS_AddInstrumentFunction(insCallback, 0);
    PIN_AddContextChangeFunction(OnException, 0);
    // Never returns
    PIN_StartProgram();

    return 0;
}
