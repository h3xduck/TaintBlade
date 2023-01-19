#include "SpecialOpc.h"

void OPC_INST::lea_mem2reg(THREADID tid, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis)
{
	LOG_DEBUG("LEA:: destreg:" << destReg << std::hex << " leabase:0x" << leaBase << " leaindex:0x" << leaIndex << " leascale:0x" << leaScale << " leadis:0x" << leaDis << std::dec);
	//4 different cases:
	//leaBase valid, leaIndex valid --> overwrite with mix
	//leaBase valid, leaIndex invalid --> overwrite taint with leaBase
	//leaBase invalid, leaIndex valid --> overwrite taint with leaIndex
	//leaBase invalid, leaIndex invalid --> error
	if (leaBase != REG_INVALID() && leaIndex != REG_INVALID())
	{
		//Might not be the best to manage ternary operation, but works for now
		taintManager.getController().untaintReg(destReg);
		taintManager.getController().taintRegWithReg(destReg, leaIndex);
		taintManager.getController().taintRegWithReg(destReg, leaBase);

		//Also we taint with the memory address itself
		//TODO
	}
	else if(leaBase == REG_INVALID())
	{
		taintManager.getController().untaintReg(destReg);
		taintManager.getController().taintRegWithReg(destReg, leaIndex);
	}
	else if (leaIndex == REG_INVALID())
	{
		taintManager.getController().untaintReg(destReg);
		taintManager.getController().taintRegWithReg(destReg, leaBase);
	}
	else
	{
		LOG_ERR("Received request to taint double invalid lea instruction");
	}
}


void OPC_INST::instrumentLeaOpc(INS ins)
{
	LOG_DEBUG("LEAINST: " << INS_Disassemble(ins));
	//mem =  base + (index * scale) + displacement
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)lea_mem2reg, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0),
		IARG_UINT32, INS_MemoryBaseReg(ins), IARG_UINT32, INS_MemoryIndexReg(ins), IARG_UINT32, INS_MemoryScale(ins),
		IARG_UINT32, INS_MemoryDisplacement(ins), IARG_END);
}