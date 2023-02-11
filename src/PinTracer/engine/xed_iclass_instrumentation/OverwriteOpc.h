#ifndef _MOVOPC_H
#define _MOVOPC_H

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	void ovw_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest);
	void ovw_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest);
	void ovw_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen);

	void ovw_imm2reg(THREADID tid, ADDRINT ip, REG regDest);
	void ovw_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen);


	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* MOV - https://www.felixcloutier.com/x86/and
	*	mov reg, imm
	*	mov mem, imm
	*	mov mem, reg
	*	mov reg, reg
	*	mov reg, mem
	*
	*/
	void instrumentOverwriteOpc(INS ins);
}



#endif
