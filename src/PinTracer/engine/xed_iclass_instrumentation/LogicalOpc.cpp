#include "LogicalOpc.h"

//and, or
void OPC_INST::logical_mem2reg(THREADID tid, const std::string dis, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	LOG_DEBUG("OPC: " << dis);
	taintManager.getController().taintRegWithMem(regDest, regDest, memSrc, memSrcLen);
}
void OPC_INST::logical_reg2reg(THREADID tid, const std::string dis, ADDRINT ip, REG regSrc, REG regDest)
{
	LOG_DEBUG("OPC: " << dis);
	taintManager.getController().taintRegWithReg(regDest, regSrc);
}
void OPC_INST::logical_reg2mem(THREADID tid, const std::string dis, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen)
{
	LOG_DEBUG("OPC: " << dis);
	taintManager.getController().taintMemWithReg(memDest, memDestLen, regSrc);
}

//xor
void OPC_INST::logical_clr_reg2reg(THREADID tid, const std::string dis, ADDRINT ip, REG regSrc, REG regDest)
{
	LOG_DEBUG("OPC: " << dis);
	taintManager.getController().untaintReg(regDest);
}


void OPC_INST::instrumentLogicalOpc(INS ins)
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
			INS_CALL_R2M(logical_reg2mem, ins);
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R(logical_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				INS_CALL_R2R(logical_reg2reg, ins);
				return;
			}
		}
	}

	//reg, imm
	//mem, imm

	//Does not spread taint (or rather keeps the taint if any)

	
	return;
}

void OPC_INST::instrumentLogicalOpcXor(INS ins)
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
			INS_CALL_R2M(logical_reg2mem, ins);
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R(logical_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				//The value is reset to 0
				INS_CALL_R2R(logical_clr_reg2reg, ins);
				return;
			}
		}
	}

	//reg, imm
	//mem, imm

	//Does not spread taint (or rather keeps the taint if any)
	return;
}
