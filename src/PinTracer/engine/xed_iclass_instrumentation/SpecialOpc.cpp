#include "SpecialOpc.h"

extern Context ctx;

void OPC_INST::lea_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis, UINT32 opc)
{
	//LOG_DEBUG("LEA:: destreg:" << destReg << std::hex << " leabase:0x" << leaBase << " leaindex:0x" << leaIndex << " leascale:0x" << leaScale << " leadis:0x" << leaDis << std::dec);
	//4 different cases:
	//leaBase valid, leaIndex valid --> overwrite with mix
	//leaBase valid, leaIndex invalid --> overwrite taint with leaBase
	//leaBase invalid, leaIndex valid --> overwrite taint with leaIndex
	//leaBase invalid, leaIndex invalid --> error
	//LOG_DEBUG("LEA:: destreg:" << REG_StringShort(destReg) << " leabase:" << REG_StringShort(leaBase) << " leaindex:" << REG_StringShort(leaIndex) << " leascale:0x" << to_hex_dbg(leaScale) << " leadis:0x" << to_hex_dbg(leaDis));
	//IMPORTANT: We are considering that getting the pointer to a tainted address does not involve tainting
	//The memory address itself will be tainted when it is used
	
	//Taint value is always overwritten
	PIN_LockClient();
	ctx.updateCurrentInstructionFullAddress(ip);
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();

	//In LEAs, we will instrument the instruction before the taint moving because of two reasons:
	//First, the destReg is not instrumented until the LEA is executed, LEAs are instrumented in 2 parts
	//Secondly, we would lose the color on destReg for the indirect taint calculation
	INST_COMMON::revLogInst_lea_mem2reg(lctx, ip, destReg, leaBase, leaIndex, leaScale, leaDis, opc, true);

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
}

void OPC_INST::lea_after(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, REG destReg, UINT32 opc)
{
	//This is called after executing the LEA instruction. Now, get the value of regDest and insert the atom in the log
	INST_COMMON::revLogInst_after(lctx, ip, destReg);
}


void OPC_INST::instrumentLeaOpc(INS ins)
{
	//LOG_DEBUG("OPC: " << INS_Disassemble(ins));
	//mem =  base + (index * scale) + displacement

	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)lea_mem2reg, IARG_CONTEXT, IARG_THREAD_ID, IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0),
		IARG_UINT32, INS_MemoryBaseReg(ins), IARG_UINT32, INS_MemoryIndexReg(ins), IARG_UINT32, INS_MemoryScale(ins),
		IARG_UINT32, INS_MemoryDisplacement(ins), IARG_UINT32, INS_Opcode(ins), IARG_END);
	INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)lea_after, IARG_CONST_CONTEXT, IARG_THREAD_ID, \
		IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0), IARG_UINT32, INS_Opcode(ins), IARG_END);
}