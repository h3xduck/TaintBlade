#include "Common.h"

void INST_COMMON::revLogInst_mem2reg(LEVEL_VM::CONTEXT *lctx, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom *atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(memSrc, memSrcLen))
	{
		atom->setInstType((xed_iclass_enum_t) opc);
		atom->setMemSrc(memSrc);
		atom->setMemSrcLen(memSrcLen);
		atomColor->memSrcColor = tController.memRangeGetColor(memSrc, memSrcLen);
		atomColor->memSrcLen = memSrcLen;
		atomChanged = true;
		PIN_LockClient();
		atomData->setMemSrcValueBytes(InstructionWorker::getMemoryValue(memSrc, memSrcLen));
		PIN_UnlockClient();
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomColor->regDestColor = tController.regGetColor(regDest);
		atomChanged = true;
		PIN_LockClient();
		UINT8 valBuffer[8];
		InstructionWorker::getRegisterValue(lctx, regDest, valBuffer);
		atomData->setRegDestValue(valBuffer, REG_Size(regDest));
		PIN_UnlockClient();
	}
	if (atomChanged)
	{
		atom->setInstAddress(ip);
		//atom->setInstType((xed_iclass_enum_t)opc);
		LOG_DEBUG("Inserting atom m2r:" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
		//Once instrumented and tainted, we try to see if the RevLog corresponds to some
		//HL operation using the heuristics.
		ctx.getRevContext()->operateRevLog();
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2reg(LEVEL_VM::CONTEXT *lctx, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegSrc(regSrc);
		atomColor->regDestColor = tController.regGetColor(regSrc);
		atomChanged = true;
		PIN_LockClient();
		UINT8 valBuffer[8];
		InstructionWorker::getRegisterValue(lctx, regSrc, valBuffer);
		atomData->setRegSrcValue(valBuffer, REG_Size(regSrc));
		PIN_UnlockClient();
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomColor->regDestColor = tController.regGetColor(regDest);
		atomChanged = true;
		PIN_LockClient();
		UINT8 valBuffer[8];
		InstructionWorker::getRegisterValue(lctx, regDest, valBuffer);
		atomData->setRegDestValue(valBuffer, REG_Size(regDest));
		PIN_UnlockClient();
	}
	if (atomChanged)
	{
		atom->setInstAddress(ip);
		LOG_DEBUG("Inserting atom r2r:" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
		//Once instrumented and tainted, we try to see if the RevLog corresponds to some
		//HL operation using the heuristics.
		ctx.getRevContext()->operateRevLog();
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2mem(LEVEL_VM::CONTEXT *lctx, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegSrc(regSrc);
		atomColor->regSrcColor = tController.regGetColor(regSrc);
		atomChanged = true;
		PIN_LockClient();
		UINT8 valBuffer[8];
		InstructionWorker::getRegisterValue(lctx, regSrc, valBuffer);
		atomData->setRegSrcValue(valBuffer, REG_Size(regSrc));
		PIN_UnlockClient();
	}
	if (tController.memRangeIsTainted(memDest, memDestLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setMemDest(memDest);
		atom->setMemDestLen(memDestLen);
		atomColor->memDestColor = tController.memRangeGetColor(memDest, memDestLen);
		atomColor->memDestLen = memDestLen;
		atomChanged = true;
		PIN_LockClient();
		atomData->setMemDestValueBytes(InstructionWorker::getMemoryValue(memDest, memDestLen));
		PIN_UnlockClient();
	}
	if (atomChanged)
	{
		atom->setInstAddress(ip);
		LOG_DEBUG("Inserting atom r2m:" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
		//Once instrumented and tainted, we try to see if the RevLog corresponds to some
		//HL operation using the heuristics.
		ctx.getRevContext()->operateRevLog();
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_lea_mem2reg(LEVEL_VM::CONTEXT *lctx, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex)
{
	//TODO control if the memory address is tainted
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(destReg))
	{
		//TODO
		//atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(destReg);
		atomChanged = true;
	}
	if (tController.regIsTainted(leaBase))
	{
		//TODO
		//atom->setInstType((xed_iclass_enum_t)opc);
		atom->setLeaBase(leaBase);
		atomChanged = true;
	}
	if (tController.regIsTainted(leaIndex))
	{
		//TODO
		//atom->setInstType((xed_iclass_enum_t)opc);
		atom->setLeaBase(leaIndex);
		atomChanged = true;
	}

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		LOG_DEBUG("Inserting atom TODO:" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
		//Once instrumented and tainted, we try to see if the RevLog corresponds to some
		//HL operation using the heuristics.
		ctx.getRevContext()->operateRevLog();
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

//TODO support IMMs