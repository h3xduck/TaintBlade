#include "BinaryOpc.h"

extern Context ctx;

//and, or
void OPC_INST::binary_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().taintRegWithMem(regDest, regDest, memSrc, memSrcLen);
	INST_COMMON::revLogInst_mem2reg(lctx, ip, memSrc, memSrcLen, regDest, opc);
}
void OPC_INST::binary_reg2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().taintRegWithReg(regDest, regSrc, false);
	INST_COMMON::revLogInst_reg2reg(lctx, ip, regSrc, regDest, opc);
}
void OPC_INST::binary_reg2mem(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValueHexString(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	PIN_UnlockClient();
	taintManager.getController().taintMemWithReg(memDest, memDestLen, regSrc);
	INST_COMMON::revLogInst_reg2mem(lctx, ip, regSrc, memDest, memDestLen, opc);
}

//xor
void OPC_INST::binary_clr_reg2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().untaintReg(regDest);
	INST_COMMON::revLogInst_reg2reg(lctx, ip, regSrc, regDest, opc);
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
