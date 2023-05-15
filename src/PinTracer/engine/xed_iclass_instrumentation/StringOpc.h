#ifndef _STRING_OPC_H_
#define _STRING_OPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {
	////////////////////////////////////////////////////////
	//Taint functions, called from instrumentation functions

	//REPNE SCAS
	void repnescas_mem(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, ADDRINT mem, INT32 mem_len, REG reg_ax, REG reg_xdi, REG reg_xcx, UINT32 opc);

	///////////////////////////////////////////////////////////////
	//Instrumentation functions, called from InstrumentationManager

	/*
	* Template instruction:
	* REPNE SCAS - https://www.felixcloutier.com/x86/rep:repe:repz:repne:repnz
	*	mem
	*
	*/
	void instrumentRepneScasOpc(INS ins);

	/**
	* Instrument generic SCAS operation
	*/
	void instrumentScasGeneric(INS ins);

};



#endif