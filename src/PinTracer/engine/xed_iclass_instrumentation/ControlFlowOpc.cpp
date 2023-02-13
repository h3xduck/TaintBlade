#include "ControlFlowOpc.h"

extern Context ctx;

void OPC_INST::controlFlow_empty(THREADID tid, ADDRINT ip)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
}

void OPC_INST::instrumentControlFlowOpc(INS ins) {
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)controlFlow_empty, IARG_THREAD_ID, IARG_INST_PTR, IARG_END);
}