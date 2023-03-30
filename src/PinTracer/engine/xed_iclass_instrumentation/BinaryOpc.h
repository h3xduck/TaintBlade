#ifndef _LOGICAL_OPC_H_
#define _LOGICAL_OPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	//and, or
	void binary_mem2reg(THREADID tid, ADDRINT ip, ADDRINT mem_src, INT32 mem_src_len, REG reg_dest, UINT32 opc);
	void binary_reg2reg(THREADID tid, ADDRINT ip, REG reg_src, REG reg_dest, UINT32 opc);
	void binary_reg2mem(THREADID tid, ADDRINT ip, REG reg_src, ADDRINT mem_dest, INT32 mem_dest_len, UINT32 opc);
	
	//xor
	void binary_clr_reg2reg(THREADID tid, ADDRINT ip, REG reg_src, REG reg_dest, UINT32 opc);

	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* Template instruction:
	* AND - https://www.felixcloutier.com/x86/and
	*	and reg, imm
	*	and mem, imm
	*	and mem, reg
	*	and reg, reg
	*	and reg, mem
	* 
	*/
	void instrumentBinaryOpc(INS ins);

	/*
	* Template instruction:
	* XOR - https://www.felixcloutier.com/x86/and
	*	xor reg, imm
	*	xor mem, imm
	*	xor mem, reg
	*	xor reg, reg
	*	xor reg, mem
	* 
	* Notes: Not always spreads taint
	*/
	void instrumentBinaryIfEqualRegClearOpc(INS ins);
};



#endif