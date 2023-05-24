#ifndef _SHIFTOPC_H_
#define _SHIFTOPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	void shr_imm2reg(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, UINT64 immSrc, REG regDest, UINT32 opc);



	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* SHR - https://www.felixcloutier.com/x86/sal:sar:shl:shr
	*	SHR reg, imm
	* 
	*/
	void instrumentShrOpc(INS ins);

}


#endif