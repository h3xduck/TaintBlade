#include "LogicalOpc.h"


void OPC_INST::logical_mem2reg()
{

}

void OPC_INST::logical_reg2reg()
{

}

void OPC_INST::logical_imm2reg()
{

}

void OPC_INST::logical_imm2mem()
{

}

void OPC_INST::logical_reg2mem()
{

}


void OPC_INST::instrumentLogicalOpc(INS ins)
{
	//Only src operand can be imm
	BOOL isImmSrc = INS_OperandImmediate(ins, 1);
	//If dest operand is mem, src cannot be mem
	BOOL isMemDest = INS_IsMemoryWrite(ins);

	if (!isImmSrc)
	{
		if (isMemDest)
		{
			//mem, reg
			
		}
		else
		{
			BOOL isMemSrc = INS_IsMemoryRead(ins);
			if (isMemSrc)
			{
				//reg, mem
				INS_CALL_M2R(logical_reg2reg, ins);
			}
			else
			{
				//reg, reg
				INS_CALL_R2R(logical_reg2reg, ins);
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
