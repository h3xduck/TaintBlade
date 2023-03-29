#include "Common.h"

void INST_COMMON::revLogInst_mem2reg(ADDRINT memSrc, INT32 memSrcLen, REG regDest)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.memRangeIsTainted(memSrc, memSrcLen))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setMemSrc(memSrc);
		atom->setMemSrcLen(memSrcLen);
		atomChanged = true;
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setRegDest(regDest);
		atomChanged = true;
	}
	if (atomChanged)
	{
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2reg(REG regSrc, REG regDest)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setRegSrc(regSrc);
		atomChanged = true;
	}
	if (tController.regIsTainted(regDest))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setRegDest(regDest);
		atomChanged = true;
	}
	if (atomChanged)
	{
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}

void INST_COMMON::revLogInst_reg2mem(REG regSrc, ADDRINT memDest, INT32 memDestLen)
{
	TaintController tController = taintManager.getController();
	//Log instruction for the reverse engineering module, in case params were tainted
	RevAtom* atom = ctx.getRevContext()->getCurrentRevAtom();
	bool atomChanged = false;
	if (tController.regIsTainted(regSrc))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setRegSrc(regSrc);
		atomChanged = true;
	}
	if (tController.memRangeIsTainted(memDest, memDestLen))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setMemDest(memDest);
		atom->setMemDestLen(memDestLen);
		atomChanged = true;
	}
	if (atomChanged)
	{
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
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setRegDest(destReg);
		atomChanged = true;
	}
	if (tController.regIsTainted(leaBase))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setLeaBase(leaBase);
		atomChanged = true;
	}
	if (tController.regIsTainted(leaIndex))
	{
		atom->setInstType(ctx.getCurrentInstructionClass());
		atom->setLeaBase(leaIndex);
		atomChanged = true;
	}

	if (atomChanged)
	{
		ctx.getRevContext()->insertRevLog(*atom);
	}
	ctx.getRevContext()->cleanCurrentRevAtom();
}