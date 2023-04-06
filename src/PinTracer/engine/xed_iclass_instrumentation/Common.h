#ifndef _COMMON_H_
#define _COMMON_H_

#include "pin.H"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "../../common/Context.h"
#include "../../utils/inst/InstructionWorker.h"
#include "../../taint/core/TaintController.h"
#include "../../taint/core/TaintManager.h"

extern Context ctx;
extern TaintManager taintManager;

//With disassembling
//Does not work for AMD processors
#define INS_CALL_R2R(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_PTR, new std::string(INS_Disassemble(ins)), \
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_R2M(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_PTR, new std::string(INS_Disassemble(ins)),\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	\
}

#define INS_CALL_M2R(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_PTR, new std::string(INS_Disassemble(ins)),\
	IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_ZERO2R(proc_func, ins)	\
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_PTR, new std::string(INS_Disassemble(ins)),\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_ZERO2M(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_PTR, new std::string(INS_Disassemble(ins)),\
	IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	\
}


//Without disassemble

#define INS_CALL_R2R_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, \
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_UINT32, INS_OperandReg(ins, 0), \
	IARG_UINT32, INS_Opcode(ins), IARG_END);	\
}

#define INS_CALL_R2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, \
	IARG_UINT32, INS_Opcode(ins), IARG_END);	\
}

#define INS_CALL_M2R_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_OperandReg(ins, 0), \
	IARG_UINT32, INS_Opcode(ins), IARG_END);	\
}

/**
Deprecated
*/
#define INS_CALL_ZERO2R_N(proc_func, ins)	\
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

/**
Deprecated
*/
#define INS_CALL_ZERO2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	\
}

#define INS_CALL_I2R_N(proc_func, ins)	\
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0), \
	IARG_UINT64, INS_OperandImmediate(ins, 1), IARG_END);	\
}

#define INS_CALL_I2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, \
	IARG_UINT64, INS_OperandImmediate(ins, 1), IARG_END);	\
}

//For instructions that use memory but do not write to it

#define INS_CALL_NOWRITE_R2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_MEMORYOP_EA, 0, IARG_MEMORYOP_SIZE, 0, \
	IARG_UINT32, INS_Opcode(ins), IARG_END);	\
}



namespace INST_COMMON
{
	/**
	Instruction that puts a value from one memory address to a register.
	Checks tainted elements, and creates an atom in the RevLog if any.
	*/
	void revLogInst_mem2reg(ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc);
	
	/**
	Instruction that puts a value from one register to another register.
	Checks tainted elements, and creates an atom in the RevLog if any.
	*/
	void revLogInst_reg2reg(REG regSrc, REG regDest, UINT32 opc);

	/**
	Instruction that puts a value from a register to a memory address.
	Checks tainted elements, and creates an atom in the RevLog if any.
	*/
	void revLogInst_reg2mem(REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc);

	/**
	Instruction that describes a lea instruction, from a memory address to a register.
	Checks tainted elements, and creates an atom in the RevLog if any.
	*/
	void revLogInst_lea_mem2reg(REG destReg, REG leaBase, REG leaIndex);
}



#endif
