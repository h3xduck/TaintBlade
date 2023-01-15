#include "TagMap.h"

TagMap::TagMap()
{
	this->tReg = TReg();
	this->tagLog = TagLog();
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
		LOG_DEBUG("New memory taint taintMemNew(" << addr << ") --> mem.ins(" << addr << ", T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
	}
	else
	{
		it->second.color = tag.color;
		it->second.derivate1 = EMPTY_COLOR;
		it->second.derivate2 = EMPTY_COLOR;
		LOG_DEBUG("New color for existing memory taint taintMemNew(" << addr << ") --> modified T(" << it->second.color << "," << it->second.derivate1 << "," << it->second.derivate2 << "))");
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
			//LOG_DEBUG("New memory taint--> ADDR:" << addr << " COL:" << color);
			//Byte not in map yet
			Tag tag(color);
			this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, tag));
			//this->printMemTaintComplete();
			LOG_DEBUG("New memory taint taintMem(" << addr << ", "<<color<<") --> mem.ins(" << addr << ", T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
		}
		//No empty color tainting
	}
	else
	{
		//LOG_DEBUG("Memory taint--> ADDR:" << addr << " COL:" << color);
		it->second.color = color;
		LOG_DEBUG("New color for existing memory taint taintMem(" << addr << ", " << color << ") --> mem.ins(" << addr << ", T(" << it->second.color << ", X, X ))");

	}
}

void TagMap::untaintMem(ADDRINT addr)
{
	LOG_DEBUG("Untainted mem untaintMem(" << addr << ") --> mem.erase(" << addr << ")");
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

	auto it = this->memTaintField.find(dest);
	Tag tag;
	if (it == this->memTaintField.end())
	{
		//Byte of dest not in map yet, no mix since src1=empty_color
		if (src2MemTag.color != EMPTY_COLOR)
		{
			//Dest=src1 is tainted with color of src2
			tag = Tag(src2MemTag.color);
			this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest, tag));
			LOG_DEBUG("New memory taint mixTaintMem(" << dest << ", " << src1 << ", "<<src2<<") --> mem.ins(" << dest << ", T(" << tag.color << ", "<<tag.derivate1<<", "<<tag.derivate2<<"))");
		}
		//else, nothing, since src2=empty_color and dest=src1 was not tainted
	}
	else
	{
		//Dest=src1 != empty_color
		if (src2MemTag.color != EMPTY_COLOR)
		{
			//We need to mix both colors, log the generated tag
			tag = Tag(src1MemTag.color, src2MemTag.color);
			it->second = tag;
			this->tagLog.logTag(tag);
			LOG_DEBUG("Mixed memory taint mixTaintMem(" << dest << ", " << src1 << ", " << src2 << ") --> modified T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << "))");
		}
		else
		{
			//src2 is an empty_color, thus we directly taint dest=src1 with empty_color
			it->second.color = EMPTY_COLOR;
			LOG_DEBUG("New color for existing memory taint mixTaintMem(" << dest << ", " << src1 << ", " << src2 << ") --> modified T(" << tag.color << ", X, X))");
		}
	}

	return tag;
}


void TagMap::taintRegNew(LEVEL_BASE::REG reg)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	Tag tag = Tag::tagNext();
	UINT16 firstColor = tag.color;

	//LOG_DEBUG("Tainting new register:: POS:" << posStart << " LEN:" << taintLength << " COL:" << tag.color << " LCOL:" << tag.lastColor);

	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		this->regTaintField[ii] = tag;
	}

	LOG_DEBUG("New reg taint taintRegNew(" << reg << ") --> modified Tags of reg(R:"<<reg<<" PI:" <<posStart<<" PF:"<<posStart+taintLength << ") with new color from PI:" << firstColor << " to PF:" << tag.color);
}

void TagMap::taintReg(LEVEL_BASE::REG reg, UINT16 color)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		this->regTaintField[ii] = Tag(color);
	}
	LOG_DEBUG("New reg taint taintReg(" << reg << ", "<<color<<") --> modified Tags of reg(R:" << reg << " PI:" << posStart << " PF:" << posStart + taintLength << ") with new color "<<color);
}

void TagMap::untaintReg(LEVEL_BASE::REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		//0 is considered the 'untainted' color
		this->regTaintField[ii] = Tag(0);
	}
	LOG_DEBUG("Untainted regs untaintReg(" << reg <<") --> modified Tags of reg(R:" << reg << " PI:" << posStart << " PF:" << posStart + taintLength << ") with empty color");
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
	
	for (int ii = 0; ii < src1RegColorVector.size(); ii++)
	{
		UINT16 colorSrc1 = src1RegColorVector.at(ii).color;
		UINT16 colorSrc2 = src2RegColorVector.at(ii).color;
		if (colorSrc1 != EMPTY_COLOR)
		{
			//src1=dest is not empty_color
			if (colorSrc2 == EMPTY_COLOR)
			{
				//src2=empty_color, thus just untaint that reg byte
				Tag tag(0);
				this->regTaintField[posStart + ii] = tag;
				LOG_DEBUG("(in loop) Untainted reg mixTaintReg(" << dest << ", "<<src1<<", "<< src2<<") --> modified Tag of reg(R:" << dest << " P:"<< posStart + ii << ") with full empty color");
			}
			else
			{
				//src2 is not empty_color, then we need to mix the colors
				//LOG_DEBUG("MIX R2R--> SRC2COL:" << colorSrc2 << " DEST/SRC1COL:" << colorSrc1);
				Tag tag(colorSrc1, colorSrc2);
				this->regTaintField[posStart + ii] = tag;
				//LOG_DEBUG("NEW DEST/SRC1COL:" << tag.color);
				this->tagLog.logTag(tag);
				LOG_DEBUG("(in loop) Mixed reg taint mixTaintReg(" << dest << ", " << src1 << ", " << src2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart + ii << ") with T("<<tag.color<<", " <<tag.derivate1<<", " <<tag.derivate2<< ")");
			}
		}
		else
		{
			//dest=src1 was untainted, taint it now with whatever color is at src2
			//LOG_DEBUG("MIX R2R--> Dest was untainted, tainting with SRC2COL:"<<colorSrc2);
			if (colorSrc2 != EMPTY_COLOR)
			{
				Tag tag(colorSrc2);
				this->regTaintField[posStart + ii] = tag;
				LOG_DEBUG("(in loop) Tainted reg with new color mixTaintReg(" << dest << ", " << src1 << ", " << src2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
			}
			//else nothing, no changes in color
			
		}
		
	}

}

void TagMap::mixTaintRegByte(LEVEL_BASE::REG dest, UINT32 byteIndex, UINT16 color1, UINT16 color2)
{

	UINT16 colorDest = getTaintColorReg(dest).at(byteIndex).color;
	if (colorDest != color1)
	{
		//Case not supported yet
		LOG_ERR("Tried to mix taint in a non-binary operation!");
		return;
	}

	const UINT32 posStart = this->tReg.getPos(dest) + byteIndex;
	if (color1 == EMPTY_COLOR)
	{
		if (color2 == EMPTY_COLOR)
		{
			//Both are empty_color, then no taint to perform
			return;
		}
		else
		{
			//dest is empty_color, just taint it with color2
			Tag tag(color2);
			this->regTaintField[posStart] = tag;
			LOG_DEBUG("Tainted reg with new color mixTaintRegByte(" << dest << ", " << byteIndex<< ", " << color1 << ", " << color2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
		}
	}
	else if (color2 == EMPTY_COLOR)
	{
		//dest is non-empty_color but color2 is, taint dest with empty_color
		this->regTaintField[posStart] = Tag(color2);
		LOG_DEBUG("Tainted reg with empty color mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with empty tag");
	}
	else
	{
		//Neither dest=color1 or color2 are empty_color. Time to mix
		Tag tag(color1, color2);
		this->regTaintField[posStart+byteIndex] = tag;
		this->tagLog.logTag(tag);
		LOG_DEBUG("Mixed taint reg mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
	}
}

//DEPRECATED
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
		UINT16 src2color = src2RegColorVector.at(ii).color;
		if (it == this->memTaintField.end())
		{
			//mem dest is not tainted, just taint with src2 reg color
			if (src2color != EMPTY_COLOR)
			{
				//Byte not in map yet
				Tag tag(src2color);
				this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest+ii, tag));
				LOG_DEBUG("(in loop) New memory taint mixTaintMemRegAllBytes(" << dest << ", " << length << ", " << src1 << ", " << src2 << ") --> mem.ins(" << dest + ii << ", T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
			}
			continue;
		}

		//mem dest is already tainted with some color
		if (src2color == EMPTY_COLOR)
		{
			//reg src2 has empty_color, just taint dest mem with empty_color
			Tag tag(src2color);
			it->second = tag;
			LOG_DEBUG("(in loop) Memory taint with empty color mixTaintMemRegAllBytes(" << dest << ", " << length << ", " << src1 << ", " << src2 << ") --> modified mem at " << dest + ii << " with T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
		}
		else
		{
			//mem dest and reg src2 have non-empty_color both, mix
			//LOG_DEBUG("MIX R2M--> MEMCOL:" << it->second.color << " REGCOL:" << src2color);
			Tag tag(it->second.color, src2color);
			it->second = tag;
			//LOG_DEBUG("NEW MEMCOL:" << it->second.color);
			this->tagLog.logTag(tag);
			LOG_DEBUG("(in loop) Mixed taint reg mixTaintMemRegAllBytes(" << dest << ", " << length << ", " << src1 << ", " << src2 << ") --> modified mem tag at " << dest + ii << " with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
		}
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

void TagMap::dumpTaintLog()
{
	this->tagLog.dumpTagLog();
}

void TagMap::dumpTaintLogPrettified(UINT16 startColor)
{
	this->tagLog.dumpTagLogPrettified(startColor);
}