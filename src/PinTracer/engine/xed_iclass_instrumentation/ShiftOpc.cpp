#include "ShiftOpc.h"

extern Context ctx;

void OPC_INST::shr_imm2reg(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, UINT64 immSrc, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstructionFullAddress(ip);
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//Tainting depends on the value of the IMM
	//This is shifting to the right. Also, flags not considered
	
	//If it is a multiple of 8, we just move colors to the right byte
	if (immSrc % 8 == 0)
	{
		int shiftLen = immSrc / 8;
		taintController.shiftRegTaint(regDest, true, shiftLen);
	}
	else
	{
		//Not supported yet
		//We would need to mix colors between bytes
	}

	INST_COMMON::revLogInst_imm2reg(lctx, ip, immSrc, regDest, opc, true);
}


void OPC_INST::instrumentShrOpc(INS ins)
{
	const BOOL isImmSrc = INS_OperandIsImmediate(ins, 1);
	const BOOL isRegDest = INS_OperandIsReg(ins, 0);

	if (isImmSrc && isRegDest)
	{
		INS_CALL_NOWRITE_I2R_N(shr_imm2reg, ins);
	}
	else
	{
		//This type of shift is not supported yet
		//There are just too many, will add them as we find them in binaries
	}
}