#include "SpecialOpc.h"

extern Context ctx;

void OPC_INST::lea_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis)
{
	//LOG_DEBUG("LEA:: destreg:" << destReg << std::hex << " leabase:0x" << leaBase << " leaindex:0x" << leaIndex << " leascale:0x" << leaScale << " leadis:0x" << leaDis << std::dec);
	//4 different cases:
	//leaBase valid, leaIndex valid --> overwrite with mix
	//leaBase valid, leaIndex invalid --> overwrite taint with leaBase
	//leaBase invalid, leaIndex valid --> overwrite taint with leaIndex
	//leaBase invalid, leaIndex invalid --> error

	//Taint value is always overwritten
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().untaintReg(destReg);

	if (leaBase != REG_INVALID() && leaIndex != REG_INVALID())
	{
		//Might not be the best to manage ternary operation, but works for now (it's mixing colors)
		taintManager.getController().taintRegWithReg(destReg, leaIndex, true);
		taintManager.getController().taintRegWithReg(destReg, leaBase, true);
	}
	else if(leaBase != REG_INVALID() && leaIndex == REG_INVALID())
	{
		taintManager.getController().taintRegWithReg(destReg, leaBase, true);
	}
	else if (leaBase == REG_INVALID() && leaIndex != REG_INVALID())
	{
		taintManager.getController().taintRegWithReg(destReg, leaIndex, true);
	}
	//If both invalid, memory was just untainted
	
	//The memory address itself will be tainted when it is used

	INST_COMMON::revLogInst_lea_mem2reg(lctx, ip, destReg, leaBase, leaIndex);
}


void OPC_INST::instrumentLeaOpc(INS ins)
{
	//LOG_DEBUG("OPC: " << INS_Disassemble(ins));
	//mem =  base + (index * scale) + displacement
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)lea_mem2reg, IARG_CONTEXT, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0),
		IARG_UINT32, INS_MemoryBaseReg(ins), IARG_UINT32, INS_MemoryIndexReg(ins), IARG_UINT32, INS_MemoryScale(ins),
		IARG_UINT32, INS_MemoryDisplacement(ins), IARG_END);
}