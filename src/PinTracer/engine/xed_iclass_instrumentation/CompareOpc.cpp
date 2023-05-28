#include "CompareOpc.h"

extern Context ctx;

//CMP instructions are instrumented in two parts: one to get the memory and reg operands,
//another to get the result of the CMP and how it affects the flags: cmp_after

void OPC_INST::cmp_mem2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint

	//First part, store in the atom the relevant values. We will insert the atom in the second part.
	INST_COMMON::revLogInst_mem2reg(lctx, ip, memSrc, memSrcLen, regDest, opc, true);
}

void OPC_INST::cmp_reg2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_reg2reg(lctx, ip, regSrc, regDest, opc, true);
}

void OPC_INST::cmp_reg2mem(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	//std::string val = InstructionWorker::getMemoryValueHexString(memDest, memDestLen);
	//ctx.updateLastMemoryValue(val, memDestLen);
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_reg2mem(lctx, ip, regSrc, memDest, memDestLen, opc, true);
}

void OPC_INST::cmp_imm2reg(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, UINT64 immSrc, REG regDest, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_imm2reg(lctx, ip, immSrc, regDest, opc, true);
}

void OPC_INST::cmp_imm2mem(LEVEL_VM::CONTEXT *lctx, THREADID tid, ADDRINT ip, UINT64 immSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//No taint
	INST_COMMON::revLogInst_imm2mem(lctx, ip, immSrc, memDest, memDestLen, opc, true);
}

void OPC_INST::cmp_after(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, UINT32 opc)
{
	//This is called after executing the CMP instruction. Now, insert the atom in the log
	INST_COMMON::revLogInst_after(lctx, ip, REG_INVALID());
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

	//LOG_DEBUG("CMP:: mS:" << isMemSrc << " mD:" << isMemDest << " rS:"<<isRegSrc<<" rD:"<<isRegDest);


	if (!isImmSrc)
	{
		if (isRegSrc)
		{
			if (isRegDest)
			{
				//reg, reg
				INS_CALL_CMP_R2R_N(cmp_reg2reg, ins);
				return;
			}
			else
			{
				//mem, reg
				INS_CALL_CMP_R2M_N(cmp_reg2mem, ins);
			}
		}
		else
		{
			//reg, mem
			INS_CALL_CMP_M2R_N(cmp_mem2reg, ins);
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
			INS_CALL_CMP_I2R_N(cmp_imm2reg, ins);
			return;
		}
		else 
		{
			//mem, imm
			INS_CALL_CMP_I2M_N(cmp_imm2mem, ins);
			return;
		}

		//imm, imm not possible
	}

}