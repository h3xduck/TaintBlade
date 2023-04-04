#include "Common.h"

void INST_COMMON::revLogInst_mem2reg(ADDRINT memSrc, INT32 memSrcLen, REG regDest, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(memSrc, memSrcLen))
	{
		atom->setInstType((xed_iclass_enum_t) opc);
		atom->setMemSrc(memSrc);
		atom->setMemSrcLen(memSrcLen);
		atomChanged = true;
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomChanged = true;
	}
	if (atomChanged)
	{
		//atom->setInstType((xed_iclass_enum_t)opc);
		LOG_DEBUG("Inserting atom :" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2reg(REG regSrc, REG regDest, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegSrc(regSrc);
		atomChanged = true;
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegDest(regDest);
		atomChanged = true;
	}
	if (atomChanged)
	{
		LOG_DEBUG("Inserting atom :" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2mem(REG regSrc, ADDRINT memDest, INT32 memDestLen, UINT32 opc)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setRegSrc(regSrc);
		atomChanged = true;
	}
	if (tController.memRangeIsTainted(memDest, memDestLen))
	{
		atom->setInstType((xed_iclass_enum_t)opc);
		atom->setMemDest(memDest);
		atom->setMemDestLen(memDestLen);
		atomChanged = true;
	}
	if (atomChanged)
	{
		LOG_DEBUG("Inserting atom :" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_lea_mem2reg(REG destReg, REG leaBase, REG leaIndex)
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
		LOG_DEBUG("Inserting atom :" << atom->getInstType());
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}