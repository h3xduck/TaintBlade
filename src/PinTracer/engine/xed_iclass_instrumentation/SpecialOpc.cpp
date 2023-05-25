#include "SpecialOpc.h"

extern Context ctx;

void manageLeaIndirectTaints(LEVEL_VM::CONTEXT* lctx, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis)
{
	UINT8* leaBaseBuffer = (UINT8*)calloc(REG_Size(leaBase), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, leaBase, leaBaseBuffer, true);
	UINT8* leaIndexBuffer = (UINT8*)calloc(REG_Size(leaIndex), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, leaIndex, leaIndexBuffer, true);
	ADDRINT leaBaseValue;
	ADDRINT leaBaseAddr = 0;
	UINT16 leaBaseColor;
	//Now, we add to that value the value of leaDis
	switch (REG_Size(leaBase))
	{
	case 1:
		leaBaseValue = (UINT32) *((UINT8*)leaBaseBuffer);
		leaBaseAddr = leaBaseValue + leaDis;
		leaBaseColor = taintController.memGetColor(leaBaseAddr);
		if (leaBaseColor != EMPTY_COLOR) LOG_DEBUG("Detected indirect taint color: "<<leaBaseColor);
		break;
	case 2:
		leaBaseValue = (UINT32) *((UINT16*)leaBaseBuffer);
		leaBaseAddr = leaBaseValue + leaDis;
		leaBaseColor = taintController.memGetColor(leaBaseAddr);
		if (leaBaseColor != EMPTY_COLOR) LOG_DEBUG("Detected indirect taint color: " << leaBaseColor);
		break;
	case 4:
		leaBaseValue = (UINT32) *((UINT32*)leaBaseBuffer);
		leaBaseAddr = leaBaseValue + leaDis;
		leaBaseColor = taintController.memGetColor(leaBaseAddr);
		if (leaBaseColor != EMPTY_COLOR) LOG_DEBUG("Detected indirect taint color: " << leaBaseColor);
		break;
	case 8:
		UINT64 mid = *((UINT64*)leaBaseBuffer);
		leaBaseValue = mid;
		leaBaseAddr = leaBaseValue + leaDis;
		LOG_DEBUG("leaBaseAddr = " << to_hex_dbg(leaBaseAddr) << " leaBaseValue = " << to_hex_dbg(leaBaseValue) << " leaDis = " << to_hex_dbg(leaDis));
		leaBaseColor = taintController.memGetColor(leaBaseAddr);
		if (leaBaseColor != EMPTY_COLOR) LOG_DEBUG("Detected indirect taint color: " << leaBaseColor);
		break;
	}
	free(leaBaseBuffer);
	free(leaIndexBuffer);
}

void OPC_INST::lea_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis)
{
	//LOG_DEBUG("LEA:: destreg:" << destReg << std::hex << " leabase:0x" << leaBase << " leaindex:0x" << leaIndex << " leascale:0x" << leaScale << " leadis:0x" << leaDis << std::dec);
	//4 different cases:
	//leaBase valid, leaIndex valid --> overwrite with mix
	//leaBase valid, leaIndex invalid --> overwrite taint with leaBase
	//leaBase invalid, leaIndex valid --> overwrite taint with leaIndex
	//leaBase invalid, leaIndex invalid --> error
	LOG_DEBUG("LEA:: destreg:" << REG_StringShort(destReg) << " leabase:" << REG_StringShort(leaBase) << " leaindex:" << REG_StringShort(leaIndex) << " leascale:0x" << to_hex_dbg(leaScale) << " leadis:0x" << to_hex_dbg(leaDis));
	//IMPORTANT: We are considering that getting the pointer to a tainted address does not involve tainting
	//The memory address itself will be tainted when it is used
	
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

		//Although pointers do not transfer taint, we do want to know when a register pointing to an address which
		//is tainted gets into an operation (e.g. a pointer is added to another), and we want to instrument that 
		//e.g.: for getting pointer fields. We manage this here.
		//Specifically, we will control:
		//--> leaBase+leaDis is indirectly tainted and leaIndex*leaScale is indirectly tainted
		manageLeaIndirectTaints(lctx, destReg, leaBase, leaIndex, leaScale, leaDis);
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