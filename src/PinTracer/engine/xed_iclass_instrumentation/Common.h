#ifndef _COMMON_H_
#define _COMMON_H_

#include "pin.H"

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
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_R2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 1), IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	\
}

#define INS_CALL_M2R_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_ZERO2R_N(proc_func, ins)	\
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_UINT32, INS_OperandReg(ins, 0), IARG_END);	\
}

#define INS_CALL_ZERO2M_N(proc_func, ins) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID,\
	IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);	\
}


BOOL ins_regs_equal(INS ins);



#endif
