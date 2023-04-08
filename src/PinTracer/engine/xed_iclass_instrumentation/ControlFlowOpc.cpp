#include "ControlFlowOpc.h"

extern Context ctx;

void OPC_INST::controlFlow_empty(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	
	//If in a control flow instruction, we check if the RevLog has surpassed some limit
	//If it did, we proceed to erase the truncate it.
	int revLogLength = ctx.getRevContext()->getRevLogCurrentLength();
	if (revLogLength >= REVLOG_TRUNCATE_THRESHOLD)
	{
		LOG_DEBUG("Truncated the RevLog at "<<revLogLength);
		//We surpassed the limit. Truncate the revlog, forgetting about the oldest instructions
		ctx.getRevContext()->cleanRangeRevLogCurrent(revLogLength - REVLOG_TRUNCATE_THRESHOLD + REVLOG_TRUNCATE_ADDITIONAL);
	}
	
	PIN_UnlockClient();
}

void OPC_INST::instrumentControlFlowOpc(INS ins) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)controlFlow_empty, IARG_CONST_CONTEXT, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
}