#ifndef _COMMON_H_
#define _COMMON_H_

#include "pin.H"

#define INS_CALL_R2R(proc_func, reg_src) \
{	\
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR) proc_func, IARG_THREAD_ID, IARG_INST_PTR, op1, op2, op3, op4, IARG_END);	\
}

#endif
