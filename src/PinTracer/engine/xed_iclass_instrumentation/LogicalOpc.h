#ifndef _LOGICAL_OPC_H_
#define _LOGICAL_OPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	//and, or
	void logical_mem2reg(THREADID tid, const std::string dis, ADDRINT ip, ADDRINT mem_src, INT32 mem_src_len, REG reg_dest);
	void logical_reg2reg(THREADID tid, const std::string dis, ADDRINT ip, REG reg_src, REG reg_dest);
	void logical_reg2mem(THREADID tid, const std::string dis, ADDRINT ip, REG reg_src, ADDRINT mem_dest, INT32 mem_dest_len);
	
	//xor
	void logical_clr_reg2reg(THREADID tid, const std::string dis, ADDRINT ip, REG reg_src, REG reg_dest);

	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* AND - https://www.felixcloutier.com/x86/and
	*	and reg, imm
	*	and mem, imm
	*	and mem, reg
	*	and reg, reg
	*	and reg, mem
	* 
	* OR - https://www.felixcloutier.com/x86/or
	*	or reg, imm
	*	or mem, imm
	*	or mem, reg
	*	or reg, reg
	*	or reg, mem
	* 
	*/
	void instrumentLogicalOpc(INS ins);

	/*
	* XOR - https://www.felixcloutier.com/x86/and
	*	xor reg, imm
	*	xor mem, imm
	*	xor mem, reg
	*	xor reg, reg
	*	xor reg, mem
	* 
	* Notes: Not always spreads taint
	*/
	void instrumentLogicalOpcXor(INS ins);
};



#endif