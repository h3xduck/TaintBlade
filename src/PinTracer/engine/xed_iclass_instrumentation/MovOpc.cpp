#include "MovOpc.h"

void OPC_INST::mov_mem2reg(THREADID tid, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	//LOG_DEBUG("OPC: " << dis);
	taintManager.getController().untaintReg(regDest);
	taintManager.getController().taintRegWithMem(regDest, regDest, memSrc, memSrcLen);
}

void OPC_INST::mov_reg2reg(THREADID tid, ADDRINT ip, REG regSrc, REG regDest)
{
	//LOG_DEBUG("OPC: " << dis);
	taintManager.getController().untaintReg(regDest);
	taintManager.getController().taintRegWithReg(regDest, regSrc);
}

void OPC_INST::mov_reg2mem(THREADID tid, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen)
{
	//LOG_DEBUG("OPC: " << dis);
	taintManager.getController().untaintMem(memDest, memDestLen);
	taintManager.getController().taintMemWithReg(memDest, memDestLen, regSrc);
}

void OPC_INST::mov_imm2reg(THREADID tid, ADDRINT ip, REG regDest)
{
	//LOG_DEBUG("OPC: " << dis<< " REG: "<<regDest);
	taintManager.getController().untaintReg(regDest);
}

void OPC_INST::mov_imm2mem(THREADID tid, ADDRINT ip, ADDRINT memDest, INT32 memDestLen)
{
	//LOG_DEBUG("OPC: " << dis);
	taintManager.getController().untaintMem(memDest, memDestLen);
}


void OPC_INST::instrumentMovOpc(INS ins)
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
			INS_CALL_R2M_N(mov_reg2mem, ins);
		}
		else
		{
			const BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R_N(mov_mem2reg, ins);
				return;
			}
			else
			{
				//reg, reg
				INS_CALL_R2R_N(mov_reg2reg, ins);
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
			INS_CALL_ZERO2M_N(mov_imm2mem, ins);
			return;
		}
		else if (isRegDest)
		{
			//reg, imm
			INS_CALL_ZERO2R_N(mov_imm2reg, ins);
			return;
		}
		else
		{
			//LOG_ALERT("Unsupported case of MOV instruction");
		}
	}

}