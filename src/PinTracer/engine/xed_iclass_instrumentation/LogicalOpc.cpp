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
	BOOL isImm = INS_OperandImmediate(ins, 1);
	//If src operand is mem, second cannot be mem
	BOOL isMem0 = INS_IsMemoryWrite(ins);
	
	return;
}

void OPC_INST::instrumentLogicalOpcXor(INS ins)
{

	return;
}
