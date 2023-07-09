#include "StringOpc.h"

extern Context ctx;

//REPNE SCAS
void OPC_INST::repnescas_mem(LEVEL_VM::CONTEXT* lctx, THREADID tid, ADDRINT ip, ADDRINT mem, INT32 mem_len, REG reg_ax, REG reg_xdi, REG reg_xcx, UINT32 opc)
{
	PIN_LockClient();
	ctx.updateCurrentInstructionFullAddress(ip);
	ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(ip));
	PIN_UnlockClient();
	//LOG_DEBUG("Called repnescas at mem: " << to_hex_dbg(mem) << " with memlen: " << mem_len);

	if (taintManager.getController().memRangeIsTainted(mem, mem_len))
	{
		//If the memory is tainted, then the register XDI directly points to the value of that memory region, so must be tainted with that color
		//Also, XCX will probably hold the length of the in-memory string, so must be tainted too (and it will be mixed in each repetition)
		LOG_DEBUG("REPNE SCAS TAINTED MEM DETECTED");
		taintManager.getController().taintRegWithMem(reg_ax, reg_ax, mem, mem_len);
		taintManager.getController().taintRegWithMem(reg_xcx, reg_xcx, mem, mem_len);
	}

	//Put this instruction into the revlogs if anything was tainted
	INST_COMMON::revLogInst_repnescas(lctx, ip, mem, mem_len, reg_ax, reg_xcx, reg_xdi, opc);
	

}





void OPC_INST::instrumentRepneScasOpc(INS ins)
{
	//REPNE SCAS always uses DI / EDI / RDI as the pointer of the string over to which iterate
	//and AL / AX / EAX / RAX as the value where to store the length (after negating it)
	//Checkout https://www.felixcloutier.com/x86/rep:repe:repz:repne:repnz
	//and page 1776 of Intel developers manual

	//Get the value of the memory read on each iteration, from DI / EDI / RDI and AL / AX / EAX / RAX
	
	const ADDRINT stringReadLength = INS_MemoryReadSize(ins);
	LOG_DEBUG("REPNE:: R:" << stringReadLength);
	
	REG reg0 = INS_OperandReg(ins, 0); //XAX
	if (INS_SegmentPrefix(ins))
	{
		//This case is not supported
		LOG_DEBUG("Instrumenting REPNE SCAS with "<< INS_SegmentRegPrefix(ins) <<" segment prefix");
	}

	if (stringReadLength == 1 && reg0 != REG::REG_AL)
	{
		//This should not be possible
		LOG_ALERT("Registered a REPNE SCAS of memory read length " << stringReadLength << " and using accumulator register " << reg0);
		return;
	}

	LOG_DEBUG("Registering REPNE with read length " << stringReadLength);

	if (stringReadLength == 1)
	{
#ifdef TARGET_IA32
		INS_CALL_REPXE_M8_x32(repnescas_mem, ins);
#else
		INS_CALL_REPXE_M8_x64(repnescas_mem, ins);
#endif
	}
	else if (stringReadLength == 2)
	{
		INS_CALL_REPXE_M16(repnescas_mem, ins);
	}
	else if (stringReadLength == 4)
	{
		INS_CALL_REPXE_M32(repnescas_mem, ins);
	}
#ifdef TARGET_IA32E
	else if (stringReadLength == 8)
	{
		INS_CALL_REPXE_M64(repnescas_mem, ins);
	}
#endif
}

void OPC_INST::instrumentScasGeneric(INS ins)
{
	if (INS_RepnePrefix(ins))
	{
		instrumentRepneScasOpc(ins);
	}
	else
	{
		//Otherwise, not supported
		LOG_DEBUG("Ignored a non-supported SCAS operation");
	}
}