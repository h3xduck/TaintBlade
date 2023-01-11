#include "LogicalOpc.h"


void OPC_INST::logical_mem2reg(THREADID tid, ADDRINT ip, ADDRINT mem_src, INT32 mem_src_len, REG reg_dest)
{
	
}

void OPC_INST::logical_reg2reg(THREADID tid, ADDRINT ip, REG reg_src, REG reg_dest)
{

}

void OPC_INST::logical_reg2mem(THREADID tid, ADDRINT ip, REG reg_src, ADDRINT mem_dest, INT32 mem_dest_len)
{

}


void OPC_INST::instrumentLogicalOpc(INS ins)
{
	//Only src operand can be imm
	const BOOL isImmSrc = INS_OperandImmediate(ins, 1);
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
				INS_CALL_M2R(logical_reg2reg, ins);
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

	//Does not spread taint

	
	return;
}

void OPC_INST::instrumentLogicalOpcXor(INS ins)
{

	return;
}
