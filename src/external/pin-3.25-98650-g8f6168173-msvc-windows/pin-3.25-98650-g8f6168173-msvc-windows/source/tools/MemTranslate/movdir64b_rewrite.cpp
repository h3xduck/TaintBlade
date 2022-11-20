/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include "pin.H"

/*
 * This tool tests Pin's support for MOVDIR64B cpu instruction which
 * copies 64 bytes from one memory operand to another.
 * In this tool we rewrite both memory operands so that the copying of
 * the 64 bytes occurs in the arrays that this tool defined (NewSrc and NewDst)
 * instead of the ones in the application.
 */

#if defined(TARGET_LINUX)
static char NewSrc[3][64] __attribute__((aligned(64)));
static char NewDst[3][64] __attribute__((aligned(64)));
#elif defined(TARGET_WINDOWS)
__declspec(align(64)) static char NewSrc[3][64];
__declspec(align(64)) static char NewDst[3][64];
#endif

char OriginalSrcBuff[3][64], OriginalDstBuff[3][64], *OriginalSrcAddr[3], *OriginalDstAddr[3], SrcSymbols[3] = {'4', '5', '6'},
                                                                                               DstSymbols[3] = {'a', 'b', 'c'};

int CountInst = 0;

ADDRINT CalcRewrittenAddressSrc(int iteration) { return (ADDRINT)NewSrc[iteration]; }

ADDRINT CalcRewrittenAddressDst(int iteration) { return (ADDRINT)NewDst[iteration]; }

/**
 * @brief Records original source and destination buffer contents and save their addresses.
 * 
 * @param addrSrc 
 * @param addrDst 
 */
VOID SetupBeforeMovdirInstrumentation(char* addrSrc, char* addrDst, int iteration)
{
    memcpy(OriginalSrcBuff[iteration], addrSrc, 64);
    OriginalSrcAddr[iteration] = addrSrc;
    memcpy(OriginalDstBuff[iteration], addrDst, 64);
    OriginalDstAddr[iteration] = addrDst;
}

/**
 * @brief Need to add this check after each memory rewrite instead of fini function
 *        because at fini the original strings are overriden 
 * 
 * @param iteration - The count of movdir64b rewrite
 */
void CheckAppBuffersAfterMovdir64b(char* srcPtr, char* dstPtr, int iteration)
{
    if (iteration < 3)
    {
        ASSERTX(strcmp(OriginalSrcAddr[iteration], OriginalDstAddr[iteration]) !=
                0); // verify that the original movdir64b didn't happen
        ASSERTX(strcmp(OriginalSrcBuff[iteration], OriginalSrcAddr[iteration]) ==
                0); // verify that the original source string didn't change
        ASSERTX(strcmp(OriginalSrcBuff[iteration], NewSrc[iteration]) !=
                0); // verify that the original source buffer and the new source buffer of each rewrite contain different values
    }
    switch (iteration)
    {
        case 0:
            ASSERTX(srcPtr == NewSrc[0]); // verify that the rewritten address is the correct one
            ASSERTX(dstPtr == NewDst[0]); // verify that the rewritten address is the correct one
            ASSERTX(strcmp(NewSrc[0], NewDst[0]) ==
                    0); // verify that the first rewrite of movdir64b happened correctly (both source and destination)
            ASSERTX(strcmp(OriginalDstBuff[0], OriginalDstAddr[0]) ==
                    0); // verify that the original destination string of the first movdir64b didn't change
            break;
        case 1:
            ASSERTX(srcPtr == NewSrc[1]);          // verify that the source address is the one we put in the rewrite
            ASSERTX(dstPtr == OriginalDstAddr[1]); // verify that the destination address is the original address
            ASSERTX(strcmp(NewSrc[1], OriginalDstAddr[1]) ==
                    0); // verify that the second rewrite of movdir64b happened correctly (only source)
            ASSERTX(strcmp(OriginalDstBuff[1], OriginalDstAddr[1]) !=
                    0); // verify that the original destination address of the second movdir64b changed
            break;
        case 2:
            ASSERTX(srcPtr == OriginalSrcAddr[2]); // verify that the destination address is the original address
            ASSERTX(dstPtr == NewDst[2]);          // verify that the destination address is the one we put in the rewrite
            ASSERTX(strcmp(OriginalSrcAddr[2], NewDst[2]) ==
                    0); // verify that the third  rewrite of movdir64b happened correctly (only destination)
            ASSERTX(strcmp(OriginalDstBuff[2], OriginalDstAddr[2]) ==
                    0); // verify that the original destination address of the third movdir64b didn't change
    }
}

VOID RewriteIns(INS ins) // movdir dst, src
{
    if (INS_IsMovdir64b(ins))
    {
        REG scratchRegSrc = REG_INST_G0;
        REG scratchRegDst = REG_INST_G1;

        ASSERTX(INS_MemoryOperandCount(ins) == 2);

        switch (CountInst)
        {
            case 0: // Rewrite both source and destination addresses
                INS_RewriteMemoryOperand(ins, 0, scratchRegSrc);
                INS_RewriteMemoryOperand(ins, 1, scratchRegDst);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetupBeforeMovdirInstrumentation), IARG_CALL_ORDER, CALL_ORDER_FIRST,
                               IARG_MEMORYOP_EA, 0, IARG_MEMORYOP_EA, 1, IARG_UINT32, CountInst, IARG_END);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CalcRewrittenAddressSrc), IARG_UINT32, CountInst, IARG_RETURN_REGS,
                               scratchRegSrc, IARG_END);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CalcRewrittenAddressDst), IARG_UINT32, CountInst, IARG_RETURN_REGS,
                               scratchRegDst, IARG_END);
                INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(CheckAppBuffersAfterMovdir64b), IARG_MEMORYOP_PTR, 0, IARG_MEMORYOP_PTR,
                               1, IARG_UINT32, CountInst, IARG_END);
                break;
            case 1: // Rewrite only source address
                INS_RewriteMemoryOperand(ins, 0, scratchRegSrc);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetupBeforeMovdirInstrumentation), IARG_CALL_ORDER, CALL_ORDER_FIRST,
                               IARG_MEMORYOP_EA, 0, IARG_MEMORYOP_EA, 1, IARG_UINT32, CountInst, IARG_END);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CalcRewrittenAddressSrc), IARG_UINT32, CountInst, IARG_RETURN_REGS,
                               scratchRegSrc, IARG_END);
                INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(CheckAppBuffersAfterMovdir64b), IARG_MEMORYOP_PTR, 0, IARG_MEMORYOP_PTR,
                               1, IARG_UINT32, CountInst, IARG_END);
                break;
            case 2: // Rewrite Only destination address
                INS_RewriteMemoryOperand(ins, 1, scratchRegDst);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(SetupBeforeMovdirInstrumentation), IARG_CALL_ORDER, CALL_ORDER_FIRST,
                               IARG_MEMORYOP_EA, 0, IARG_MEMORYOP_EA, 1, IARG_UINT32, CountInst, IARG_END);
                INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(CalcRewrittenAddressDst), IARG_UINT32, CountInst, IARG_RETURN_REGS,
                               scratchRegDst, IARG_END);
                INS_InsertCall(ins, IPOINT_AFTER, AFUNPTR(CheckAppBuffersAfterMovdir64b), IARG_MEMORYOP_PTR, 0, IARG_MEMORYOP_PTR,
                               1, IARG_UINT32, CountInst, IARG_END);
        }

        CountInst++;
    }
}

VOID Trace(TRACE trace, VOID* v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            RewriteIns(ins);
        }
    }
}

int main(int argc, char* argv[])
{
    PIN_InitSymbols();
    PIN_Init(argc, argv);
    for (int i = 0; i < 3; i++)
    {
        memset(NewSrc[i], SrcSymbols[i], 63);
        NewSrc[i][63] = '\0';
        memset(NewDst[i], DstSymbols[i], 63);
        NewDst[i][63] = '\0';
    }

    TRACE_AddInstrumentFunction(Trace, 0);

    // Never returns
    PIN_StartProgram();

    return 0;
}
