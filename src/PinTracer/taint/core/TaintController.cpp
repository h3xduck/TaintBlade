#include "TaintController.h"


TaintController taintController;

TaintController::TaintController()
{
	LOG_INFO("TaintController initialized");
}

std::vector<UINT16> TaintController::taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes)
{
	ADDRINT memIt = memAddr;
	std::vector<UINT16> usedColors;
	for (int ii = 0; ii < bytes; ii++)
	{
		//Different color for each byte
		const UINT16 newColor = this->tagMap.getNextTagColor();
		usedColors.push_back(newColor);
		//LOG_DEBUG("Tainting addr " << memIt << " with color " << newColor);
		this->tagMap.taintMem(memIt, newColor, true);
		memIt += 1;
	}
	return usedColors;
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

		srcMemIt += 1;
		destMemIt += 1;
	}
}

void TaintController::taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg, BOOL colorOverwrite)
{
	//TODO: Check if destBytes and srcRegLength are the same
	const UINT32 srcRegLength = this->tagMap.tReg.getTaintLength(srcReg);
	//LOG_DEBUG("M2R --> M:" << destMem << "(len:" << destBytes << ")  R:" << REG_StringShort(srcReg) << "(code:" << srcReg << ")");
	ADDRINT destMemIt = destMem;
	std::vector<Tag> srcRegColorVector = this->tagMap.getTaintColorReg(srcReg);

	for (int ii = 0; ii < destBytes; ii++)
	{
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);

		//No mixes to created if dest is empty or we must overwrite the color anyway
		if (colorDest == EMPTY_COLOR || colorOverwrite == true)
		{
			UINT16 color = srcRegColorVector[ii].color;

			//Ignore color overwrite if the color is already there
			if (colorDest == color)
			{
				//LOG_DEBUG("Ignored color overwrite for " << to_hex_dbg(destMemIt) << " since it's the same one");
				return;
			}

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

void TaintController::untaintMem(const ADDRINT destMem, const UINT32 destBytes)
{
	for (int ii = 0; ii < destBytes; ii++)
	{
		this->tagMap.untaintMem(destMem+ii);
	}
}

void TaintController::taintRegNewColor(const LEVEL_BASE::REG reg)
{
	this->tagMap.taintRegNew(reg);
}

void TaintController::taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg, BOOL srcExtension)
{
	if (srcExtension)
	{
		this->tagMap.mixTaintRegWithExtension(destReg, destReg, srcReg);
	}
	else
	{
		this->tagMap.mixTaintReg(destReg, destReg, srcReg);
	}
	
}

void TaintController::taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes)
{
	const UINT32 destRegLength = this->tagMap.tReg.getTaintLength(destReg);
	const UINT16 colorSrc2Mem = this->tagMap.getTaintColorMem(src2Mem);
	const UINT32 destPos = this->tagMap.tReg.getPos(destReg);

	//LOG_DEBUG("M2R:: REG:" << destReg << " POS:" << destPos << " src2Mem:" << to_hex_dbg(src2Mem) << " len:" << src2Bytes);
	LOG_DEBUG("REGLEN: " << destRegLength << " | MEMLEN: " << src2Bytes);
	for (int ii = 0; ii < src2Bytes; ii++)
	{
		UINT16 colorReg = this->tagMap.getTaintColorReg(src1Reg).at(destRegLength-src2Bytes+ii).color;
		this->tagMap.mixTaintRegByte(destReg, destRegLength - src2Bytes + ii, colorReg, colorSrc2Mem);
	}

}

void TaintController::untaintReg(const LEVEL_BASE::REG reg)
{	
	const UINT32 taintLength = this->tagMap.tReg.getTaintLength(reg);
	for (int ii=0; ii<taintLength; ii++)
	{
		this->tagMap.untaintReg(reg, ii);
	}
}

void TaintController::registerOriginalColor(UINT16 color, std::string dllName, std::string funcName, ADDRINT memAddress, UINT8 byteValue)
{
	this->tagMap.tagLog.logTagOriginal(color, dllName, funcName, memAddress, byteValue);
}

std::vector<UINT16> TaintController::getColorParents(UINT16 color)
{
	return this->tagMap.tagLog.getColorParentsRecursive(color);
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

void TaintController::dumpTagLogOriginalColors()
{
	this->tagMap.dumpTagLogOriginalColors();
}

std::vector<std::pair<ADDRINT, UINT16>> TaintController::getTaintedMemoryVector()
{
	return this->tagMap.getTaintedMemoryVector();
}

std::vector<std::pair<UINT16, TagLog::original_color_data_t>> TaintController::getOriginalColorsVector()
{
	return this->tagMap.getOriginalColorsVector();
}

std::vector<Tag> TaintController::getColorTransVector()
{
	return this->tagMap.getColorTransVector();
}

bool TaintController::regIsTainted(REG reg)
{
	return this->tagMap.regIsTainted(reg);
}

bool TaintController::memIsTainted(ADDRINT mem)
{
	return this->tagMap.memIsTainted(mem);
}

bool TaintController::memRangeIsTainted(ADDRINT mem, int bytes)
{
	return this->tagMap.memRangeIsTainted(mem, bytes);
}

std::vector<UINT16> TaintController::regGetColor(REG reg)
{
	return this->tagMap.regGetColor(reg);
}

UINT16 TaintController::memGetColor(ADDRINT mem)
{
	return this->tagMap.memGetColor(mem);
}

std::vector<UINT16> TaintController::memRangeGetColor(ADDRINT mem, int bytes)
{
	return this->tagMap.memRangeGetColor(mem, bytes);
}