#include "TaintController.h"


TaintController taintController;

TaintController::TaintController()
{
	LOG_INFO("TaintController initialized");
}

void TaintController::taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes)
{
	ADDRINT memIt = memAddr;
	for (int ii = 0; ii < bytes - 1; ii++)
	{
		//Different color for each byte
		const UINT16 newColor = this->tagMap.getNextTagColor();
		//LOG_DEBUG("Tainting addr " << memIt << " with color " << newColor);
		this->tagMap.taintMem(memIt, newColor);
		memIt += 1;
	}
}

void TaintController::taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes)
{
	//src and dest should be of the same size
	//If destMem is tainted, then colors are mixed
	ADDRINT srcMemIt = srcMem;
	ADDRINT destMemIt = destMem;
	std::vector<UINT16> srcMemColor;
	for (int ii = 0; ii < destBytes; ii++)
	{
		const UINT16 colorSrc = this->tagMap.getTaintColorMem(srcMemIt);
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);
		if (colorDest == EMPTY_COLOR)
		{
			this->tagMap.taintMem(destMemIt, colorSrc);
		}
		else
		{
			this->tagMap.mixTaintMem(destMemIt, destMemIt, srcMemIt);
		}

		srcMemIt += 8;
		destMemIt += 8;
	}
}

void TaintController::taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg)
{
	//TODO: Check if destBytes and srcRegLength are the same
	const UINT32 srcRegLength = this->tagMap.tReg.getTaintLength(srcReg);
	//LOG_DEBUG("M2R --> M:" << destMem << "(len:" << destBytes << ")  R:" << REG_StringShort(srcReg) << "(code:" << srcReg << ")");
	ADDRINT destMemIt = destMem;
	std::vector<Tag> srcRegColorVector = this->tagMap.getTaintColorReg(srcReg);

	for (int ii = 0; ii < destBytes; ii++)
	{
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);
		if (colorDest == EMPTY_COLOR)
		{
			UINT16 color = srcRegColorVector[ii].color;
			//LOG_DEBUG("Empty color, tainting " << destMemIt << " with color " << unsigned(color) << " from reg " << REG_StringShort(srcReg));
			this->tagMap.taintMem(destMemIt, color);
		}
		else
		{
			//LOG_DEBUG("Mixing colors");
			this->tagMap.mixTaintMemRegAllBytes(destMemIt, destBytes, destMemIt, srcReg);
			return;
		}

		destMemIt += 1;
	}

}

//TODO: Think about taking the byte complexity of TagMap out to this functions
//like in the taintregwithmem
void TaintController::taintRegNewColor(const LEVEL_BASE::REG reg)
{
	this->tagMap.taintRegNew(reg);
}

void TaintController::taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg)
{
	this->tagMap.mixTaintReg(destReg, destReg, srcReg);
}

void TaintController::taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes)
{
	const UINT32 destRegLength = this->tagMap.tReg.getTaintLength(destReg);
	const UINT16 colorSrc2Mem = this->tagMap.getTaintColorMem(src2Mem);

	for (int ii = 0; ii < destRegLength; ii++)
	{
		UINT16 colorReg = this->tagMap.getTaintColorReg(src1Reg).at(ii).color;

		this->tagMap.mixTaintRegByte(destReg, ii, colorReg, colorSrc2Mem);
	}

}

void TaintController::printTaint()
{
	this->tagMap.printMemTaintComplete();
	this->tagMap.printRegTaintComplete();
}

void TaintController::dumpTaintLog()
{
	this->tagMap.dumpTaintLog();
}

void TaintController::dumpTaintLogPrettified(UINT16 color)
{
	this->tagMap.dumpTaintLogPrettified(color);
}