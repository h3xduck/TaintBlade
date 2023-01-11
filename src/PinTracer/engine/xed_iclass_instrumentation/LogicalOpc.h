#ifndef _LOGICAL_OPC_H_
#define _LOGICAL_OPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	void logical_mem2reg();
	void logical_reg2reg();
	void logical_imm2reg();
	void logical_imm2mem();
	void logical_reg2mem();





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
	*	and reg, imm
	*	and mem, imm
	*	and mem, reg
	*	and reg, reg
	*	and reg, mem
	* 
	* Notes: Not always spreads taint
	*/
	void instrumentLogicalOpcXor(INS ins);
};



#endif