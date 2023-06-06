#include "TaintController.h"


TaintController taintController;

TaintController::TaintController()
{
	LOG_INFO("TaintController initialized");
}

std::vector<UINT16> TaintController::taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes)
{
	ADDRINT memIt = memAddr;
	std::vector<UINT16> usedColors = std::vector<UINT16>();
	for (int ii = 0; ii < bytes; ii++)
	{
		//Different color for each byte
		const UINT16 newColor = this->tagMap.getNextTagColor();
		usedColors.push_back(newColor);
		LOG_DEBUG("Tainting addr " << memIt << " with color " << newColor);
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

void TaintController::taintMemByteWithColor(const ADDRINT destMem, UINT16 color, BOOL manualTaint)
{
	this->tagMap.taintMem(destMem, color, manualTaint);
}

void TaintController::taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg, BOOL colorOverwrite)
{
	//TODO: Check if destBytes and srcRegLength are the same
	const UINT32 srcRegLength = this->tagMap.tReg.getTaintLength(srcReg);
	//LOG_DEBUG("R2M --> M:" << destMem << "(len:" << destBytes << ")  R:" << REG_StringShort(srcReg) << "(code:" << srcReg << ")");
	ADDRINT destMemIt = destMem + destBytes -1;
	std::vector<Tag> srcRegColorVector = this->tagMap.getTaintColorReg(srcReg);

	//We start from the end just in case the register or the memory value are smaller
	//IMPORTANT: The order of bytes is reflected inside the register when loading from memory, so here it's the reverse
	for (int ii = destBytes - 1; ii >= 0; ii--)
	{
		const UINT16 colorDest = this->tagMap.getTaintColorMem(destMemIt);

		//No mixes to created if dest is empty or we must overwrite the color anyway
		if (colorDest == EMPTY_COLOR || colorOverwrite == true)
		{
			//If the memory position is already greater than the register, it means we covered all bytes
			//from the register already so we halt
			if (destBytes - (ii + 1) > srcRegColorVector.size())
			{
				return;
			}

			//Taint starting from the start, going forward, so that the register LSB taints the memory LSB one contents reversed
			UINT16 color = srcRegColorVector[destBytes - 1 - ii].color;

			//Ignore color overwrite if the color is already there
			if (colorDest == color)
			{
				//LOG_DEBUG("Ignored color overwrite for " << to_hex_dbg(destMemIt) << " since it's the same one");
				destMemIt -= 1;
				continue;
			}

			//LOG_DEBUG("Empty color, tainting " << destMemIt << " with color " << unsigned(color) << " from reg " << REG_StringShort(srcReg));
			this->tagMap.taintMem(destMemIt, color);
		}
		else
		{
			//LOG_DEBUG("Mixing colors");
			this->tagMap.mixTaintMemRegAllBytes(destMemIt, destBytes, destMemIt, srcReg);
		}

		destMemIt -= 1;
	}

}

void TaintController::untaintMem(const ADDRINT destMem, const UINT32 destBytes)
{
	for (int ii = 0; ii < destBytes; ii++)
	{
		this->tagMap.untaintMem(destMem + ii);
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
	const UINT32 destPos = this->tagMap.tReg.getPos(destReg);

	//LOG_DEBUG("M2R:: REG:" << destReg << " POS:" << destPos << " src2Mem:" << to_hex_dbg(src2Mem) << " len:" << src2Bytes);
	//LOG_DEBUG("REGLEN: " << destRegLength << " | MEMLEN: " << src2Bytes);

	//We iterate considering that we want to fix the bytes we will access to the LSBs of the registers
	//IMPORTANT: The order of bytes is reflected inside the register when loading from memory
	for (int ii = 0; ii < src2Bytes; ii++)
	{
		//If the memory position is already greater than the register's, it means we covered all bytes
		//from the register already so we halt
		if (ii >= destRegLength)
		{
			LOG_DEBUG("Memory limit reached compared to register");
			return;
		}
		UINT16 colorReg = this->tagMap.getTaintColorReg(src1Reg).at((src2Bytes - ii - 1) + (destRegLength - src2Bytes)).color;
		const UINT16 colorSrc2Mem = this->tagMap.getTaintColorMem(src2Mem + ii);
		this->tagMap.mixTaintRegByte(destReg, (src2Bytes - ii - 1) + (destRegLength - src2Bytes), colorReg, colorSrc2Mem);
	}

}

void TaintController::shiftRegTaint(const LEVEL_BASE::REG destReg, bool rightDirection, const UINT32 numPositions)
{
	const UINT32 taintLength = this->tagMap.tReg.getTaintLength(destReg);
	if (this->tagMap.regIsTainted(destReg)) {
		if (!rightDirection)
		{
			LOG_DEBUG("Starting left shift for "<<numPositions<<" positions");
			for (int ii = 0; ii < taintLength; ii++)
			{
				UINT16 color = this->tagMap.getTaintColorReg(destReg).at(ii).color;

				//We get the destination byte to taint with that color
				UINT32 destByteIndex = ii - numPositions;
				if (destByteIndex >= taintLength)
				{
					//If it goes out of the register, then the color at the initial byte is just lost
					this->tagMap.untaintReg(destReg, ii);
				}
				else
				{
					//If it is in the register even after the shift, we move the color to that byte before removing the original one
					this->tagMap.taintRegByte(destReg, destByteIndex, color);
					this->tagMap.untaintReg(destReg, ii);
				}
			}
			LOG_DEBUG("Ending left shift");
		}
		else
		{
			LOG_DEBUG("Starting right shift for "<<numPositions<<" positions");
			for (int ii = taintLength-1; ii >=0; ii--)
			{
				UINT16 color = this->tagMap.getTaintColorReg(destReg).at(ii).color;

				//We get the destination byte to taint with that color
				UINT32 destByteIndex = ii + numPositions;
				if (destByteIndex < 0)
				{
					//If it goes out of the register, then the color at the initial byte is just lost
					this->tagMap.untaintReg(destReg, ii);
				}
				else
				{
					//If it is in the register even after the shift, we move the color to that byte before removing the original one
					this->tagMap.taintRegByte(destReg, destByteIndex, color);
					this->tagMap.untaintReg(destReg, ii);
				}
			}
			LOG_DEBUG("Ending right shift");
		}
		
	}
}

void TaintController::untaintReg(const LEVEL_BASE::REG reg)
{
	const UINT32 taintLength = this->tagMap.tReg.getTaintLength(reg);
	for (int ii = 0; ii < taintLength; ii++)
	{
		this->tagMap.untaintReg(reg, ii);
	}
}

void TaintController::registerOriginalColor(UINT16 color, std::string dllName, std::string funcName, ADDRINT memAddress, UINT8 byteValue)
{
	this->tagMap.tagLog.logTagOriginal(color, dllName, funcName, memAddress, byteValue);
}

void TaintController::registerColorReason(UINT16 color, TagLog::color_taint_reason_t reason)
{
	this->tagMap.tagLog.logColorTaintReason(color, reason);
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

std::vector<std::pair<UINT16, TagLog::color_taint_reason_t>> TaintController::getColorReasonsVector()
{
	return this->tagMap.getColorReasonsVector();
}

TagLog::color_taint_reason_t TaintController::getColorTaintReason(UINT16 color)
{
	return this->tagMap.getColorTaintReason(color);
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