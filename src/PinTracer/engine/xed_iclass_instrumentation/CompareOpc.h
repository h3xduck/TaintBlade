#ifndef _COMPAREOPC_H
#define _COMPAREOPC_H

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	void cmp_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest);
	void cmp_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest);
	void cmp_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen);

	void cmp_imm2reg(THREADID tid, ADDRINT ip, REG regDest, UINT64 immSrc);
	void cmp_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen, UINT64 immSrc);


	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* CMP - https://www.felixcloutier.com/x86/cmp
	*	cmp reg, imm
	*	cmp mem, imm
	*	cmp mem, reg
	*	cmp reg, reg
	*	cmp reg, mem
	*
	*/
	void instrumentCompareOpc(INS ins);
}

#endif