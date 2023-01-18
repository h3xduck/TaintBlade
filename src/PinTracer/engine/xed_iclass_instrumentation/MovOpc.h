#ifndef _MOVOPC_H
#define _MOVOPC_H

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	//mov
	void mov_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest);
	void mov_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest);
	void mov_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen);

	void mov_imm2reg(THREADID tid, ADDRINT ip, REG regDest);
	void mov_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen);


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
	void instrumentMovOpc(INS ins);
}



#endif
