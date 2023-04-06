#include "CompareOpc.h"

extern Context ctx;

void OPC_INST::cmp_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_mem2reg(memSrc, memSrcLen, regDest, opc);
}

void OPC_INST::cmp_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_reg2reg(regSrc, regDest, opc);
}

void OPC_INST::cmp_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_reg2mem(regSrc, memDest, memDestLen, opc);
}

void OPC_INST::cmp_imm2reg(THREADID tid, ADDRINT ip, REG regDest, UINT64 immSrc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
}

void OPC_INST::cmp_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen, UINT64 immSrc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	PIN_UnlockClient();
	//No taint
}


void OPC_INST::instrumentCompareOpc(INS ins)
{
	//Only src operand can be imm
	const BOOL isImmSrc = INS_OperandIsImmediate(ins, 1);
	//If dest operand is mem, src cannot be mem
	const BOOL isMemDest = INS_OperandIsMemory(ins, 0);
	const BOOL isMemSrc = INS_OperandIsMemory(ins, 1);
	const BOOL isRegDest = INS_OperandIsReg(ins, 0);
	const BOOL isRegSrc = INS_OperandIsReg(ins, 1);

	LOG_DEBUG("CMP:: mS:" << isMemSrc << " mD:" << isMemDest << " rS:"<<isRegSrc<<" rD:"<<isRegDest);


	if (!isImmSrc)
	{
		if (isRegSrc)
		{
			if (isRegDest)
			{
				//reg, reg
				INS_CALL_R2R_N(cmp_reg2reg, ins);
				return;
			}
			else
			{
				//mem, reg
				INS_CALL_NOWRITE_R2M_N(cmp_reg2mem, ins);
			}
		}
		else
		{
			//reg, mem
			INS_CALL_M2R_N(cmp_mem2reg, ins);
			return;

			//mem, mem not possible
		}
	}
	else
	{
		//TODO imms
		if (isRegDest)
		{
			//reg, imm
			//INS_CALL_I2R_N(cmp_imm2reg, ins);
			return;
		}
		else 
		{
			//mem, imm
			//INS_CALL_I2M_N(cmp_imm2mem, ins);
			return;
		}

		//imm, imm not possible
	}

}