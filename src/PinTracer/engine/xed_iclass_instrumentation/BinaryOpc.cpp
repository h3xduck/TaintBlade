#include "BinaryOpc.h"

extern Context ctx;

//and, or
void OPC_INST::binary_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		memSrc, memSrcLen, 0, 0, REG_INVALID_, regDest
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	taintManager.getController().taintRegWithMem(regDest, regDest, memSrc, memSrcLen);
}
void OPC_INST::binary_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, 0, 0, regSrc, regDest
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	taintManager.getController().taintRegWithReg(regDest, regSrc, false);
}
void OPC_INST::binary_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, memDest, memDestLen, regSrc
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	taintManager.getController().taintMemWithReg(memDest, memDestLen, regSrc);
}

//xor
void OPC_INST::binary_clr_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, 0, 0, regSrc, regDest
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	taintManager.getController().untaintReg(regDest);
}


void OPC_INST::instrumentBinaryOpc(INS ins)
{
	//Only src operand can be imm
	const BOOL isImmSrc = INS_OperandIsImmediate(ins, 1);
	//If dest operand is mem, src cannot be mem
	const BOOL isMemDest = INS_IsMemoryWrite(ins);

	if (!isImmSrc)
	{
		if (isMemDest)
		{
			//mem, reg
			INS_CALL_R2M_N(binary_reg2mem, ins);
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R_N(binary_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				INS_CALL_R2R_N(binary_reg2reg, ins);
				return;
			}
		}
	}

	//reg, imm
	//mem, imm

	//Does not spread taint (or rather keeps the taint if any)

	
	return;
}

void OPC_INST::instrumentBinaryIfEqualRegClearOpc(INS ins)
{
	//Only src operand can be imm
	const BOOL isImmSrc = INS_OperandIsImmediate(ins, 1);
	//If dest operand is mem, src cannot be mem
	const BOOL isMemDest = INS_IsMemoryWrite(ins);

	if (!isImmSrc)
	{
		if (isMemDest)
		{
			//mem, reg
			INS_CALL_R2M_N(binary_reg2mem, ins);
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R_N(binary_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				if (INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1))
				{
					//The value is reset to 0
					INS_CALL_R2R_N(binary_clr_reg2reg, ins);
					return;
				}
				else
				{
					//Not equal, normal tianting
					INS_CALL_R2R_N(binary_reg2reg, ins);
				}
			}
		}
	}

	//reg, imm
	//mem, imm

	//Does not spread taint (or rather keeps the taint if any)
	return;
}
