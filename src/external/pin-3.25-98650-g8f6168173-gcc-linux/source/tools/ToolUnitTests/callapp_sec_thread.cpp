/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include "pin.H"

/*
 * This pintool validates that the flow for destructing a spill area succeeds.
 * Pin calls an explicit destruction of the spill area for secondary threads,
 * this is why foo() is called from a secondary thread.
 *
 * Pintool mode of operation:
 *  o   The pintool saves the address of application function bar().
 *  o   The pintool instruments foo() with IPOINT_BEFORE.
 *  o   In the analysis routine the pintool calls bar() using PIN_CallApplicationFunction.
 *
 *  Success criteria:
 *  o   The application terminates successfully.
 */

STATIC KNOB< BOOL > KnobVerbose(KNOB_MODE_WRITEONCE, "pintool", "verbose", "0", "verbose mode");

static VOID BeforeFoo(CONTEXT* context, THREADID tid, ADDRINT addrBar)
{
    OS_THREAD_ID os_tid = PIN_GetTid();

    if (KnobVerbose) std::cout << std::dec << "[ tid " << os_tid << " ] BEFORE foo()" << std::endl;

    // Call the application function bar()
    if (KnobVerbose) std::cout << std::dec << "[ tid " << os_tid << " ] Calling PIN_CallApplicationFunction( bar )" << std::endl;
    PIN_CallApplicationFunction(context, tid, CALLINGSTD_DEFAULT, (AFUNPTR)addrBar, NULL, PIN_PARG_END());
}

VOID Image(IMG img, VOID* v)
{
    if (IMG_IsMainExecutable(img))
    {
        // Find foo() and bar().
        // Instrument foo() (IPOINT_BEFORE) and pass the address of bar() so that the analysis routine can call bar().
        RTN rtnBar = RTN_FindByName(img, "bar");
        ASSERT(RTN_Valid(rtnBar), "Failed to find function \"bar\" in " + IMG_Name(img) + "\n");

        RTN rtnFoo = RTN_FindByName(img, "foo");
        ASSERT(RTN_Valid(rtnFoo), "Failed to find function \"foo\" in " + IMG_Name(img) + "\n");

        RTN_Open(rtnFoo);
        RTN_InsertCall(rtnFoo, IPOINT_BEFORE, (AFUNPTR)BeforeFoo, // analysis routine
                       IARG_CONST_CONTEXT,                        // context
                       IARG_THREAD_ID,                            // thread id
                       IARG_ADDRINT, RTN_Address(rtnBar),         // the address of bar()
                       IARG_END);
        RTN_Close(rtnFoo);
    }
}

INT32 Usage()
{
    std::cerr << "This Pintool tests that calling an application function from a secondary thread succeeds." << std::endl;
    std::cerr << std::endl << KNOB_BASE::StringKnobSummary() << std::endl;
    return 1;
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    IMG_AddInstrumentFunction(Image, 0);
    PIN_StartProgram();
    return 0;
}
