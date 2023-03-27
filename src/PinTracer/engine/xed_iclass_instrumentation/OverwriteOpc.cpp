#include "OverwriteOpc.h"

extern Context ctx;

void OPC_INST::ovw_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().untaintReg(regDest);
	taintManager.getController().taintRegWithMem(regDest, regDest, memSrc, memSrcLen);
}

void OPC_INST::ovw_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().untaintReg(regDest);
	taintManager.getController().taintRegWithReg(regDest, regSrc, true);
}

void OPC_INST::ovw_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	//LOG_DEBUG("Moved mem of len " << memDestLen << " : " << val);
	PIN_UnlockClient();
	taintManager.getController().taintMemWithReg(memDest, memDestLen, regSrc, true);
}

void OPC_INST::ovw_imm2reg(THREADID tid, ADDRINT ip, REG regDest)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	taintManager.getController().untaintReg(regDest);
}

void OPC_INST::ovw_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen)
{
	PIN_LockClient();
	ctx.updateCurrentInstruction(InstructionWorker::getBaseAddress(ip));
	std::string val = InstructionWorker::getMemoryValue(memDest, memDestLen);
	ctx.updateLastMemoryValue(val, memDestLen);
	PIN_UnlockClient();
	taintManager.getController().untaintMem(memDest, memDestLen);
}


void OPC_INST::instrumentOverwriteOpc(INS ins)
{
	//LOG_DEBUG("OPC: " << INS_Disassemble(ins));
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
				INS_CALL_R2M_N(ovw_reg2mem, ins);
			}
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R_N(ovw_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				INS_CALL_R2R_N(ovw_reg2reg, ins);
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
			INS_CALL_ZERO2M_N(ovw_imm2mem, ins);
			return;
		}
		else if (isRegDest)
		{
			//reg, imm
			INS_CALL_ZERO2R_N(ovw_imm2reg, ins);
			return;
		}
		else
		{
			//LOG_ALERT("Unsupported case of MOV instruction");
		}
	}

}