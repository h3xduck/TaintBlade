#ifndef _CONTROL_FLOW_OPC_H_
#define _CONTROL_FLOW_OPC_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "Common.h"
#include "../../taint/core/TaintManager.h"
#include "../../utils/inst/InstructionWorker.h"

extern TaintManager taintManager;

namespace OPC_INST {

	void controlFlow_empty(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip);

	/**
	Empty instrumentation, no tainting. We will just keep track of current instruction
	*/
	void instrumentControlFlowOpc(INS ins);

}


#endif