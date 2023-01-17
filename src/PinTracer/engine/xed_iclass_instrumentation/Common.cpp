#include "Common.h"

BOOL ins_regs_equal(INS ins)
{
	return !INS_OperandIsImmediate(ins, 1) && INS_MemoryOperandCount(ins) == 0 && (INS_OperandReg(ins, 0) == INS_OperandReg(ins, 1));
}