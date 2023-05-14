#include "StringOpc.h"

extern Context ctx;

//REPNE SCAS
void repnescas_mem(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, ADDRINT mem, INT32 mem_len, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
}





void OPC_INST::instrumentRepneScasOpc(INS ins)
{
	//REPNE SCAS always uses DI / EDI / RDI as the pointer of the string over to which iterate
	//and AL / AX / EAX / RAX as the value where to store the length (after negating it)
	//Checkout https://www.felixcloutier.com/x86/rep:repe:repz:repne:repnz
	//and page 1776 of Intel developers manual

	//Get the value of the memory read on each iteration, from DI / EDI / RDI and AL / AX / EAX / RAX
	
	const ADDRINT stringReadLength = INS_MemoryReadSize(ins);
	LOG_DEBUG("REPNE:: R:" << stringReadLength);
	
	REG reg0 = INS_OperandReg(ins, 0); //XAX
	UINT32 reg1 = INS_OperandReg(ins, 1);
	UINT32 reg2 = INS_OperandReg(ins, 2);
	UINT32 reg3 = INS_OperandReg(ins, 3); //RCX
	UINT32 reg4 = INS_OperandReg(ins, 4);



}

void OPC_INST::instrumentScasGeneric(INS ins)
{
	if (INS_RepnePrefix(ins))
	{
		instrumentRepneScasOpc(ins);
	}
	else
	{
		//Otherwise, not supported
		LOG_DEBUG("Ignored a non-supported SCAS operation");
	}
}