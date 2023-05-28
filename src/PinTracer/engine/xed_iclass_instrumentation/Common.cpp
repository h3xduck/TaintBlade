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
		atomColor->regSrcColor = tController.regGetColor(regSrc);
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

/**
Calculates and resolves whether the LEA instruction features any indirect taint (a pointer to a tainted address)
It introduces the corresponding values of the atoms in the atoms objects passed as an argument.
*/
void manageLeaIndirectTaints(LEVEL_VM::CONTEXT* lctx, RevAtom* atom, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis, UINT32 opc)
{
	UINT8* leaBaseBuffer = (UINT8*)calloc(REG_Size(leaBase), sizeof(UINT8));
	InstructionWorker::getRegisterValue(lctx, leaBase, leaBaseBuffer, true);
	ADDRINT leaBaseValue = 0;
	//Now, we add to that value the value of leaDis
	switch (REG_Size(leaBase))
	{
	case 1:
		leaBaseValue = (UINT32) * ((UINT8*)leaBaseBuffer);
		break;
	case 2:
		leaBaseValue = (UINT32) * ((UINT16*)leaBaseBuffer);
		break;
	case 4:
		leaBaseValue = (UINT32) * ((UINT32*)leaBaseBuffer);
		break;
	case 8:
		leaBaseValue = (UINT64) * ((UINT64*)leaBaseBuffer);
		break;
	}

	//Check the color of leaBase + leaDis
	ADDRINT leaBaseDisAddr = leaBaseValue + leaDis;
	UINT16 leaBaseDisColor = taintController.memGetColor(leaBaseDisAddr);
	if (leaBaseDisColor != EMPTY_COLOR) {
		LOG_DEBUG("Detected indirect taint color: " << leaBaseDisColor << " with leaBase+leaDis");

		//At this point, we will instrument this event, noting that:
		//leaBaseAddr + leaDis is a tainted address
		//leaIndex * leaScale is used to indicate an offset from the tainted address
		//Then, if leaIndex is a tainted register, it is a possible pointer field, and we must instrument it as so
		if (taintController.regIsTainted(leaIndex))
		{
			LOG_DEBUG("LeaIndex is tainted!");
			UINT8* leaIndexBuffer = (UINT8*)calloc(REG_Size(leaIndex), sizeof(UINT8));
			InstructionWorker::getRegisterValue(lctx, leaIndex, leaIndexBuffer, true);
			ADDRINT leaIndexValue = 0;
			switch (REG_Size(leaIndex))
			{
			case 1:
				leaIndexValue = (UINT32) * ((UINT8*)leaIndexBuffer);
				break;
			case 2:
				leaIndexValue = (UINT32) * ((UINT16*)leaIndexBuffer);
				break;
			case 4:
				leaIndexValue = (UINT32) * ((UINT32*)leaIndexBuffer);
				break;
			case 8:
				leaIndexValue = (UINT64) * ((UINT64*)leaIndexBuffer);
				break;
			}

			//If tainted, as we explained, leaIndexValue * leaScale is the value of the possible pointer field, remit it to heuristics section
			std::vector<UINT16> leaIndexColors = taintController.regGetColor(leaIndex);
			bool nonEmptyColorFound = false;
			for (UINT16 color : leaIndexColors)
			{
				nonEmptyColorFound = true;
				LOG_DEBUG("LeaIndex at indirect taint LEA has color " << color);
			}

			if (nonEmptyColorFound)
			{
				//At this point, we've got that leaIndex was a tainted register (with leaIndex * leaScale) used to be added/substracted to the
				//value leaBase + leaDis, where leaBase was tainted
				//NOTE: LeaScale is never negative, or that's what I saw wandering around
				RevColorAtom* atomColor = atom->getRevColorAtom();
				RevDataAtom* atomData = atom->getRevDataAtom();
				RevHeuristicAtom* hData = atom->getRevHeuristicAtom();
				ADDRINT leaIndexScaleAddr = leaIndexValue * leaScale;

				//Set elements relative to indirect taint
				hData->leaIndirectTaint = true;
				atom->setRegDest(destReg);
				atom->setLeaBase(leaBase);
				atom->setLeaIndex(leaIndex);
				atom->setLeaDis(leaDis);
				atom->setLeaScale(leaScale);

				std::vector<UINT16> leaBaseDisColorVec;
				leaBaseDisColorVec.push_back(leaBaseDisColor);
				std::vector<UINT16> leaBaseColorVec = taintController.regGetColor(leaBase);
				atomColor->leaBaseColor = leaBaseColorVec;
				atomColor->leaBaseDisColor = leaBaseDisColorVec;
				atomColor->leaIndexColor = leaIndexColors;

				//Get the bytes in reversed order, going from MSB (at [0]) to LSB (at [size-1])
				InstructionWorker::getRegisterValue(lctx, leaIndex, leaIndexBuffer);
				atomData->setLeaBaseValue(leaBaseBuffer, REG_Size(leaBase));
				atomData->setLeaIndexValue(leaIndexBuffer, REG_Size(leaIndex));
			}

			free(leaIndexBuffer);
		}

	}

	//TODO - Check the color of leaBase only - This is discarded for now, but might get added
	//leaBaseColor = taintController.memGetColor(leaBaseValue);
	//if (leaBaseColor != EMPTY_COLOR) LOG_DEBUG("Detected indirect taint color: " << leaBaseColor << " with leaBase");

	LOG_DEBUG("leaBaseAddr = " << to_hex_dbg(leaBaseDisAddr) << " leaBaseValue = " << to_hex_dbg(leaBaseValue) << " leaDis = " << to_hex_dbg(leaDis) << " leaIndex = " << REG_StringShort(leaIndex));
	free(leaBaseBuffer);
}

void INST_COMMON::revLogInst_lea_mem2reg(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, REG destReg, REG leaBase, REG leaIndex, UINT32 leaScale, UINT32 leaDis, UINT32 opc, bool needsAfterInstruction)
{
	//If the memory address is tainted (dest of lea)
	TaintController tController = taintManager.getController();
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	//Log instruction for the reverse engineering module, in case params were tainteds
	RevColorAtom* atomColor = atom->getRevColorAtom();
	RevDataAtom* atomData = atom->getRevDataAtom();
	bool atomChanged = false;
	if (destReg != REG_INVALID())
	{
		if (tController.regIsTainted(destReg))
		{
			atom->setInstType((xed_iclass_enum_t)opc);
			atom->setRegDest(destReg);
			atomColor->regDestColor = tController.regGetColor(destReg);
			atomChanged = true;
		}
		PIN_LockClient();
		UINT8* valBuffer = (UINT8*)calloc(REG_Size(destReg), sizeof(UINT8));
		InstructionWorker::getRegisterValue(lctx, destReg, valBuffer);
		atomData->setRegDestValue(valBuffer, REG_Size(destReg));
		free(valBuffer);
		PIN_UnlockClient();
	}
	

	if (leaBase != REG_INVALID())
	{
		if (tController.regIsTainted(leaBase))
		{
			atom->setInstType((xed_iclass_enum_t)opc);
			atom->setLeaBase(leaBase);
			atomChanged = true;
		}
		PIN_LockClient();
		UINT8* valBuffer2 = (UINT8*)calloc(REG_Size(leaBase), sizeof(UINT8));
		InstructionWorker::getRegisterValue(lctx, leaBase, valBuffer2);
		atomData->setLeaBaseValue(valBuffer2, REG_Size(leaBase));
		free(valBuffer2);
		PIN_UnlockClient();
	}

	if (leaIndex != REG_INVALID())
	{
		if(tController.regIsTainted(leaIndex))
		{
			atom->setInstType((xed_iclass_enum_t)opc);
			atom->setLeaBase(leaIndex);
			atomChanged = true;
		}
		PIN_LockClient();
		UINT8* valBuffer3 = (UINT8*)calloc(REG_Size(leaIndex), sizeof(UINT8));
		InstructionWorker::getRegisterValue(lctx, leaIndex, valBuffer3);
		atomData->setLeaIndexValue(valBuffer3, REG_Size(leaIndex));
		free(valBuffer3);
		PIN_UnlockClient();
	}

	//Although pointers do not transfer taint, we do want to know when a register pointing to an address which
	//is tainted gets into an operation (e.g. a pointer is added to another), and we want to instrument that 
	//e.g.: for getting pointer fields. We manage this here.
	//Specifically, we will control:
	//--> leaBase+leaDis is indirectly tainted and leaIndex*leaScale is indirectly tainted
	//NOTE: Only the above is managed for now. The example where:
	//	mem = leaBase + (leaIndex * leaScale) + leaDis
	//is NOT considered, since for now we did not find any purpose for its instrumentation
	if (destReg != REG_INVALID() && leaBase != REG_INVALID() && leaIndex != REG_INVALID())
	{
		manageLeaIndirectTaints(lctx, atom, destReg, leaBase, leaIndex, leaScale, leaDis, opc);
	}

	if (atomChanged)
	{
		atom->setInstAddress(ip);
		atom->setOperandsType(RevHeuristicAtom::MEM2REG_LEA);
		//Only if this is an instruction that is instrumented in one part (e.g., not like a CMP)
		//we take tainted data and insert the atom in the RevLog.
		//LEAs always need two stages, since we need to take the value put into the destReg. It could be calculated, but
		//this simplifies things in case displacement is negative or other cases
		if (!needsAfterInstruction)
		{
			LOG_DEBUG("Inserting atom LEA:" << atom->getInstType());
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

void INST_COMMON::revLogInst_after(LEVEL_VM::CONTEXT* lctx, ADDRINT ip, REG destReg)
{
	RevContext* rctx = ctx.getRevContext();
	//Take the current atom. If anything is tainted, we insert it in the RevLog.
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	RevHeuristicAtom* hAtom = atom->getRevHeuristicAtom();
	RevDataAtom* dataAtom = atom->getRevDataAtom();

	if (hAtom->containsAnyData())
	{
		//Depending on the instruction, we may instrument it differently
		if (atom->getInstType() == XED_ICLASS_CMP) {
			//At this point, and only after the execution of the CMP, we can get the value of the flags
			PIN_LockClient();
			RevDataAtom* dataAtom = atom->getRevDataAtom();
			UINT8* valBuffer = (UINT8*)calloc(REG_Size(REG::REG_FLAGS), sizeof(UINT8));
			InstructionWorker::getRegisterValue(lctx, REG::REG_FLAGS, valBuffer, true);
			dataAtom->setFlagsValue(valBuffer);
			free(valBuffer);
			PIN_UnlockClient();

			LOG_DEBUG("Inserting CMP atom at after:" << atom->getInstType());
			rctx->insertRevLog(*atom);
			rctx->operateRevLog();
		}
		else if (atom->getInstType() == XED_ICLASS_LEA)
		{
			//Only after the execution of the LEA we can get the value at destReg
			PIN_LockClient();
			RevDataAtom* dataAtom = atom->getRevDataAtom();
			RevColorAtom* colorAtom = atom->getRevColorAtom();
			UINT8* valBuffer = (UINT8*)calloc(REG_Size(destReg), sizeof(UINT8));
			InstructionWorker::getRegisterValue(lctx, destReg, valBuffer, true);
			dataAtom->setRegDestValue(valBuffer, REG_Size(destReg));
			if (taintController.regIsTainted(destReg))
			{
				atom->setRegDest(destReg);
				colorAtom->regDestColor = taintController.regGetColor(destReg);
			}

			//Now, we check if the destination memory address encoded as a pointer in destReg is tainted
			ADDRINT destRegValue = 0;
			switch (REG_Size(destReg))
			{
			case 1:
				destRegValue = (UINT32) * ((UINT8*)valBuffer);
				break;
			case 2:
				destRegValue = (UINT32) * ((UINT16*)valBuffer);
				break;
			case 4:
				destRegValue = (UINT32) * ((UINT32*)valBuffer);
				break;
			case 8:
				destRegValue = (UINT64) * ((UINT64*)valBuffer);
				break;
			}
			UINT16 destRegMemColor = taintController.memGetColor(destRegValue);
			atom->setMemDest(destRegValue);
			atom->setMemDestLen(1);
			std::vector<UINT16> destRegMemColorVec;
			destRegMemColorVec.push_back(destRegMemColor);
			colorAtom->memDestColor = destRegMemColorVec;

			LOG_DEBUG("LEA DESTREGCOLOR:" << destRegMemColor << " DESTREGVALUE:" << to_hex_dbg(destRegValue));

			free(valBuffer);
			PIN_UnlockClient();

			LOG_DEBUG("Inserting LEA atom at after:" << atom->getInstType());
			rctx->insertRevLog(*atom);
			rctx->operateRevLog();

		}
		
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