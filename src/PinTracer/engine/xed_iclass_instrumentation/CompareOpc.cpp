#include "CompareOpc.h"

void OPC_INST::cmp_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		memSrc, memSrcLen, 0, 0, REG_INVALID_, regDest
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	//No taint
}

void OPC_INST::cmp_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, 0, 0, regSrc, regDest
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	//No taint
}

void OPC_INST::cmp_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen)
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
	//No taint
}

void OPC_INST::cmp_imm2reg(THREADID tid, ADDRINT ip, REG regDest, UINT64 immSrc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, 0, 0, REG_INVALID_, regDest,
		REG_INVALID_, REG_INVALID_, 0, 0, immSrc
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	//No taint
}

void OPC_INST::cmp_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen, UINT64 immSrc)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	RevAtom atom(
		ctx.getCurrentInstructionClass(),
		0, 0, memDest, memDestLen, REG_INVALID_, REG_INVALID_,
		REG_INVALID_, REG_INVALID_, 0, 0, immSrc
	);
	ctx.getRevContext()->insertRevLog(atom);
	PIN_UnlockClient();
	//No taint
}


void OPC_INST::instrumentCompareOpc(INS ins)
{
	//Only src operand can be imm
	const BOOL isImmSrc = INS_OperandIsImmediate(ins, 1);
	//If dest operand is mem, src cannot be mem
	const BOOL isMemDest = INS_IsMemoryWrite(ins);
	const BOOL isMemSrc = INS_IsMemoryRead(ins);

	if (!isImmSrc)
	{
		if (isMemDest)
		{
			if (isMemSrc)
			{
				//mem, mem
				LOG_ALERT("Unsupported case of MOV instruction: mem2mem");
			}
			else
			{
				//mem, reg
				INS_CALL_R2M_N(cmp_reg2mem, ins);
			}
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R_N(cmp_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				INS_CALL_R2R_N(cmp_reg2reg, ins);
				return;
			}
		}
	}
	else
	{
		const BOOL isRegDest = INS_OperandIsReg(ins, 0);
		if (isMemDest)
		{
			//mem, imm
			INS_CALL_I2M_N(cmp_imm2mem, ins);
			return;
		}
		else if (isRegDest)
		{
			//reg, imm
			INS_CALL_I2R_N(cmp_imm2reg, ins);
			return;
		}
		else
		{
			//LOG_ALERT("Unsupported case of CMP instruction");
		}
	}

}