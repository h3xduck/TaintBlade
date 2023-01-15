#include "TagMap.h"

TagMap::TagMap()
{
	this->tReg = TReg();
	for (int ii = 0; ii < REG_TAINT_FIELD_LEN; ii++)
	{
		this->regTaintField[ii] = Tag(0);
	}
	
	//this->memTaintField.insert({ 0, memInfo });
	//this->regTaintField = { 0 };
	LOG_INFO("TagMap initialized");
}

size_t TagMap::tagMapCount()
{
	size_t count = this->memTaintField.size();
	return count;
}


UINT16 TagMap::taintMemNew(ADDRINT addr)
{
	auto it = this->memTaintField.find(addr);
	Tag tag = Tag();
	if (it == this->memTaintField.end())
	{
		//Byte not in map yet
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, tag));

	}
	else
	{
		it->second.color = tag.color;
		it->second.derivate1 = EMPTY_COLOR;
		it->second.derivate2 = EMPTY_COLOR;
	}

	return tag.color;
}

void TagMap::taintMem(ADDRINT addr, UINT16 color) 
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		if (color != EMPTY_COLOR)
		{
			LOG_DEBUG("New memory taint--> ADDR:" << addr << " COL:" << color);
		}
		//Byte not in map yet
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, Tag(color)));
		//this->printMemTaintComplete();
	}
	else
	{
		if (color != EMPTY_COLOR)
		{
			LOG_DEBUG("Memory taint--> ADDR:" << addr << " COL:" << color);
		}
		it->second.color = color;
	}
}

void TagMap::untaintMem(ADDRINT addr)
{
	this->memTaintField.erase(addr);
}

UINT16 TagMap::getTaintColorMem(ADDRINT addr)
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		return EMPTY_COLOR;
	}
	else
	{
		return it->second.color;
	}
}

Tag TagMap::mixTaintMem(ADDRINT dest, ADDRINT src1, ADDRINT src2)
{
	Tag src1MemTag = getTaintColorMem(src1);
	Tag src2MemTag = getTaintColorMem(src2);

	//TODO IMPORTANT: add search in mixed colors collection, now it's generating a new color for each mix
	//TODO: Check if dest is empty color
	auto it = this->memTaintField.find(dest);
	Tag tag;
	if (it == this->memTaintField.end())
	{
		//Byte not in map yet, no mix
		tag = Tag(src2MemTag.color);
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest, tag));
	}
	else
	{
		tag = Tag(src1MemTag.color, src2MemTag.color);
		it->second = tag;
	}

	return tag;
}


UINT16 TagMap::taintRegNew(LEVEL_BASE::REG reg)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	Tag tag = Tag::tagNext();

	LOG_DEBUG("Tainting new register:: POS:" << posStart << " LEN:" << taintLength << " COL:" << tag.color << " LCOL:" << tag.lastColor);

	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		this->regTaintField[ii] = tag;
	}

	return tag.color;
}

void TagMap::taintReg(LEVEL_BASE::REG reg, UINT16 color)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	for (INT ii = posStart; ii < taintLength; ii++)
	{
		this->regTaintField[ii] = Tag(color);
	}
}

void TagMap::untaintReg(LEVEL_BASE::REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	for (INT ii = posStart; ii < taintLength; ii++)
	{
		//0 is considered the 'untainted' color
		this->regTaintField[ii] = Tag(0);
	}
}

std::vector<Tag> TagMap::getTaintColorReg(LEVEL_BASE::REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);

	std::vector<Tag> colorVector;
	for (UINT32 ii = posStart; ii < posStart+taintLength; ii++)
	{
		colorVector.push_back(this->regTaintField[ii]);
	}

	return colorVector;
}

void TagMap::mixTaintReg(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2)
{
	//Mandatory that the registers are of the same size
	std::vector<Tag> src1RegColorVector = getTaintColorReg(src1);
	std::vector<Tag> src2RegColorVector = getTaintColorReg(src2);
	const UINT32 posStart = this->tReg.getPos(dest);
	const UINT32 taintLength = this->tReg.getTaintLength(dest);

	if (src1RegColorVector.size() != src2RegColorVector.size() ||
		src1RegColorVector.size() != taintLength)
	{
		LOG_ERR("Tried to mix taint between registers of different lengths");
		return;
	}
	
	//TODO IMPORTANT: add search in mixed colors collection, now it's generating a new color for each mix

	for (int ii = 0; ii < src1RegColorVector.size(); ii++)
	{
		UINT16 colorSrc1 = src1RegColorVector.at(ii).color;
		UINT16 colorSrc2 = src2RegColorVector.at(ii).color;
		if (colorSrc1 != EMPTY_COLOR)
		{
			//Mix colors
			LOG_DEBUG("MIX R2R--> SRC2COL:" << colorSrc2 << " DEST/SRC1COL:" << colorSrc1);
			Tag tag(colorSrc1, colorSrc2);
			this->regTaintField[posStart+ii] = tag;
			LOG_DEBUG("NEW DEST/SRC1COL:" << tag.color);
		}
		else
		{
			//Src was untainted, taint it now
			LOG_DEBUG("MIX R2R--> Dest was untainted, tainting with SRC2COL:"<<colorSrc2);
			this->regTaintField[posStart+ii] = Tag(colorSrc2);
		}
		
	}

}

void TagMap::mixTaintRegByte(LEVEL_BASE::REG dest, UINT32 byteIndex, UINT16 color1, UINT16 color2)
{
	const UINT32 posStart = this->tReg.getPos(dest) + byteIndex;
	if (color1 == EMPTY_COLOR)
	{
		if (color2 == EMPTY_COLOR)
		{
			return;
		}
		else
		{
			this->regTaintField[posStart] = Tag(color2);
		}
	}
	else if (color2 == EMPTY_COLOR)
	{
		this->regTaintField[posStart] = Tag(color1);
	}
	else
	{
		//mix
		this->regTaintField[posStart] = Tag(color1, color2);
	}
}

void TagMap::mixTaintRegColors(LEVEL_BASE::REG dest, UINT32 length, std::vector<UINT16> colorV1, std::vector<UINT16> colorV2)
{
	const UINT32 posStart = this->tReg.getPos(dest);
	const UINT32 taintLength = this->tReg.getTaintLength(dest);

	for (int ii = 0; ii < length; ii++)
	{
		UINT16 color1 = colorV1.at(ii);
		if (color1 == EMPTY_COLOR)
		{
			this->regTaintField[ii] = Tag(colorV2.at(ii));
		}
		else
		{
			this->regTaintField[ii] = Tag(color1, colorV2.at(ii));
		}
	}
}

void TagMap::mixTaintMemRegAllBytes(ADDRINT dest, UINT32 length, ADDRINT src1, LEVEL_BASE::REG src2)
{
	//Supported only if dest and src1 are the same memory address
	if (dest != src1)
	{
		LOG_ERR("Dest and src1 were not the same");
		return;
	}

	const ADDRINT memIt = dest;
	std::vector<Tag> src2RegColorVector = getTaintColorReg(src2);
	
	for (int ii = 0; ii < length; ii++)
	{
		auto it = this->memTaintField.find(dest+ii);
		UINT16 color = src2RegColorVector.at(ii).color;
		if (it == this->memTaintField.end())
		{
			taintMem(dest + ii, color);
			continue;
		}
		LOG_DEBUG("MIX R2M--> MEMCOL:" << it->second.color << " REGCOL:" << color);
		it->second = Tag(it->second.color, color);
		LOG_DEBUG("NEW MEMCOL:" << it->second.color);
	}
}


void TagMap::printMemTaintComplete()
{
	std::cerr << "MEM_TAINT_FIELD PRINT START" << std::endl;
	for (auto const& pair : this->memTaintField) {
		std::cerr << "{" << pair.first << ": " << pair.second.color << "}\n";
	}
	std::cerr << std::endl << "MEM_TAINT_FIELD PRINT END" << std::endl;
}

void TagMap::printRegTaintComplete()
{
	std::cerr << "REG_TAINT_FIELD PRINT START" << std::endl;
	const int NUM_COLUMNS = 8;
	for (int ii = 0; ii < 128; ii+=NUM_COLUMNS)
	{
		for (int jj = 0; jj < NUM_COLUMNS; jj++)
		{
			std::cerr << "{" << ii+jj << ": " << this->regTaintField[ii+jj].color << "} ";
		}
		std::cerr << std::endl;
	}
	std::cerr << std::endl << "REG_TAINT_FIELD PRINT END" << std::endl;
}

UINT16 TagMap::getNextTagColor()
{
	Tag tag = Tag::tagNext();
	return tag.color;
}