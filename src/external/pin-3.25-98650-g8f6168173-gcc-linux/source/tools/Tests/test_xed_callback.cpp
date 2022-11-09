/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  Use XED decode callback to look for CLDEMOTE
 */

#include <iostream>
#include <assert.h>
#include "pin.H"

using std::cout;
using std::endl;

static BOOL cldemote_found = FALSE;

VOID Ins(INS ins, VOID* v)
{
    xed_decoded_inst_t const* const xedd = INS_XedDec(ins);
    xed_iclass_enum_t ic                 = xed_decoded_inst_get_iclass(xedd);
    if (ic == XED_ICLASS_CLDEMOTE) cldemote_found = TRUE;
}

VOID Fini(INT32 code, VOID* v)
{
    if (cldemote_found)
        cout << "SUCCESS" << endl;
    else
        cout << "ERROR" << endl;
}

void XedSettings(xed_decoded_inst_t* xedd) { xed3_operand_set_cldemote(xedd, 1); }

int main(INT32 argc, CHAR** argv)
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);

    INS_AddInstrumentFunction(Ins, 0);
    PIN_AddFiniFunction(Fini, 0);

    PIN_AddXedDecodeCallbackFunction(XedSettings);

    // Never returns
    PIN_StartProgram();

    return 0;
}
