#ifndef _SPECIALOPC_H_
#define _SPECIALOPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	void lea_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis, UINT32 opc);
	
	//After function, since LEAs needs to be instrumented in two parts. The second one gets the value put into destReg
	void lea_after(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, REG destReg, UINT32 opc);


	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* LEA - https://www.felixcloutier.com/x86/lea
	*	mov reg, mem
	* --> mem =  base + (index * scale) + displacement
	*
	*/
	void instrumentLeaOpc(INS ins);

}


#endif