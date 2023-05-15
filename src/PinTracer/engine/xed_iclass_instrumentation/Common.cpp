#include "Common.h"

void INST_COMMON::revLogInst_mem2reg(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc, bool needsAfterInstruction)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(memSrc, memSrcLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setMemSrc(memSrc);
		atom->setMemSrcLen(memSrcLen);
		atomColor->memSrcColor = tController.memRangeGetColor(memSrc, memSrcLen);
		atomColor->memSrcLen = memSrcLen;
		atomChanged = true;
	}
	//The data is stored into the atom even if it is not tainted
	PIN_LockClient();
	atomData->setMemSrcValueBytes(InstructionWorker::getMemoryValue(memSrc, memSrcLen));
	PIN_UnlockClient();

	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomColor->regDestColor = tController.regGetColor(regDest);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer = (UINT8*)calloc(REG_Size(regDest), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regDest, valBuffer);
	atomData->setRegDestValue(valBuffer, REG_Size(regDest));
	free(valBuffer);
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::MEM2REG);
		//atom->setInstType((xed_iclass_enum_t)opc);
		if (!needsAfterInstruction)
		{
			LOG_DEBUG("Inserting atom m2r:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if(!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2reg(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, REG regSrc, REG regDest, UINT32 opc, bool needsAfterInstruction)
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
	}
	PIN_LockClient();
	UINT8 *valBuffer = (UINT8*)calloc(REG_Size(regSrc), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regSrc, valBuffer);
	atomData->setRegSrcValue(valBuffer, REG_Size(regSrc));
	//LOG_DEBUG("RegSrcValueSize of reg " << regSrc << ": " << atomData->getRegSrcValue().size());
	free(valBuffer);
	PIN_UnlockClient();

	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomColor->regDestColor = tController.regGetColor(regDest);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer2 = (UINT8*)calloc(REG_Size(regDest), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regDest, valBuffer2);
	atomData->setRegDestValue(valBuffer2, REG_Size(regDest));
	free(valBuffer2);
	//LOG_DEBUG("RegDestValueSize: " << atomData->getRegDestValue().size());
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::REG2REG);
		//LOG_DEBUG("R2R WITH RegDestByte[0]: " << atomData->getRegDestValue().at(0) << " | RegSrcByte[0]: " << atomData->getRegSrcValue().at(0));
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		if (!needsAfterInstruction)
		{
			LOG_DEBUG("Inserting atom r2r:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if (!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2mem(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc, bool needsAfterInstruction)
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
	}
	PIN_LockClient();
	UINT8* valBuffer = (UINT8*)calloc(REG_Size(regSrc), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regSrc, valBuffer);
	atomData->setRegSrcValue(valBuffer, REG_Size(regSrc));
	free(valBuffer);
	PIN_UnlockClient();

	if (tController.memRangeIsTainted(memDest, memDestLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setMemDest(memDest);
		atom->setMemDestLen(memDestLen);
		atomColor->memDestColor = tController.memRangeGetColor(memDest, memDestLen);
		atomColor->memDestLen = memDestLen;
		atomChanged = true;
	}
	PIN_LockClient();
	atomData->setMemDestValueBytes(InstructionWorker::getMemoryValue(memDest, memDestLen));
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::REG2MEM);
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		if (!needsAfterInstruction)
		{
			LOG_DEBUG("Inserting atom r2m:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if (!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_lea_mem2reg(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, bool needsAfterInstruction)
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
		atom->setOperandsType(RevHeuristicAtom::MEM2REG_LEA);
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		if (!needsAfterInstruction)
		{
			LOG_DEBUG("Inserting atom TODO:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if (!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_imm2reg(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, UINT64 immSrc, REG regDest, UINT32 opc, bool needsAfterInstruction)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomColor->regDestColor = tController.regGetColor(regDest);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer = (UINT8*)calloc(REG_Size(regDest), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regDest, valBuffer);
	atomData->setRegDestValue(valBuffer, REG_Size(regDest));
	atomData->setImmSrcValue(immSrc);
	free(valBuffer);
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::IMM2REG);
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		if (!needsAfterInstruction)
		{
			//imm values
			atom->setImmSrc(immSrc);
			LOG_DEBUG("Inserting atom i2r:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if (!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_imm2mem(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, UINT64 immSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc, bool needsAfterInstruction)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(memDest, memDestLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setMemDest(memDest);
		atom->setMemDestLen(memDestLen);
		atomColor->memDestColor = tController.memRangeGetColor(memDest, memDestLen);
		atomColor->memDestLen = memDestLen;
		atomChanged = true;
	}
	PIN_LockClient();
	atomData->setMemDestValueBytes(InstructionWorker::getMemoryValue(memDest, memDestLen));
	atomData->setImmSrcValue(immSrc);
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::IMM2MEM);
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		if (!needsAfterInstruction)
		{
			//imm value
			atom->setImmSrc(immSrc);
			LOG_DEBUG("Inserting atom i2m:" << atom->getInstType());
			ctx.getRevContext()->insertRevLog(*atom);
			//Once instrumented and tainted, we try to see if the RevLog corresponds to some
			//HL operation using the heuristics.
			ctx.getRevContext()->operateRevLog();
		}
	}
	if (!needsAfterInstruction) ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_after(LEVEL_VM::CONTEXT* lctx, ADDRINT ip)
{
	RevContext* rctx = ctx.getRevContext();
	//Take the current atom. If anything is tainted, we insert it in the RevLog.
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevHeuristicAtom* hAtom = atom->getRevHeuristicAtom();
	RevDataAtom* dataAtom = atom->getRevDataAtom();

	if (hAtom->containsAnyData())
	{
		//At this point, and only after the execution of the CMP, we can get the value of the flags
		PIN_LockClient();
		RevDataAtom* dataAtom = atom->getRevDataAtom();
		UINT8* valBuffer = (UINT8*)calloc(REG_Size(REG::REG_FLAGS), sizeof(UINT8));
		InstructionWorker::getRegisterValue(lctx, REG::REG_FLAGS, valBuffer, true);
		dataAtom->setFlagsValue(valBuffer);
		free(valBuffer);
		PIN_UnlockClient();

		LOG_DEBUG("Inserting atom at after:" << atom->getInstType());
		rctx->insertRevLog(*atom);
		rctx->operateRevLog();
	}
	else
	{
		//LOG_DEBUG("After clause ignored");
	}

	rctx->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_repnescas(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, ADDRINT mem, INT32 memLen, REG regXAX, REG regXCX, REG regXDI, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(mem, memLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setScasMem(mem);
		atom->setScasMemLen(memLen);
		atomColor->scasMemColor = tController.memRangeGetColor(mem, memLen);
		atomColor->scasMemLen = memLen;
		atomChanged = true;
	}
	PIN_LockClient();
	atomData->setMemDestValueBytes(InstructionWorker::getMemoryValue(mem, memLen));
	PIN_UnlockClient();

	if (tController.regIsTainted(regXAX))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegScasXAX(regXAX);
		atomColor->regScasXAXColor = tController.regGetColor(regXAX);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer = (UINT8*)calloc(REG_Size(regXAX), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regXAX, valBuffer);
	atomData->setRegScasXAXBytes(valBuffer, REG_Size(regXAX));
	free(valBuffer);
	PIN_UnlockClient();

	if (tController.regIsTainted(regXCX))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegScasXCX(regXCX);
		atomColor->regScasXCXColor = tController.regGetColor(regXCX);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer2 = (UINT8*)calloc(REG_Size(regXCX), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regXCX, valBuffer2);
	atomData->setRegScasXCXBytes(valBuffer2, REG_Size(regXCX));
	free(valBuffer2);
	PIN_UnlockClient();

	if (tController.regIsTainted(regXDI))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegScasXDI(regXDI);
		atomColor->regScasXDIColor = tController.regGetColor(regXDI);
		atomChanged = true;
	}
	PIN_LockClient();
	UINT8* valBuffer3 = (UINT8*)calloc(REG_Size(regXDI), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, regXDI, valBuffer3);
	atomData->setRegScasXDIBytes(valBuffer3, REG_Size(regXDI));
	free(valBuffer3);
	PIN_UnlockClient();

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::REG2MEM);
		LOG_DEBUG("Inserting atom repne scas:" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
		//Once instrumented and tainted, we try to see if the RevLog corresponds to some
		//HL operation using the heuristics.
		ctx.getRevContext()->operateRevLog();
	}
	ctx.getRevContext()->cleanCurrentRevAtom();

}
