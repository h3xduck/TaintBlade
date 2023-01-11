#include "TagMap.h"

TagMap::TagMap()
{
	this->tReg = TReg();
	for (int ii = 0; ii < REG_TAINT_FIELD_LEN; ii++)
	{
		this->regTaintField[ii] = Tag();
	}
	
	//this->memTaintField.insert({ 0, memInfo });
	//this->regTaintField = { 0 };
	//LOG("LOGGING THIS");
}

size_t TagMap::tagMapCount()
{
	size_t count = this->memTaintField.size();
	return count;
}

void TagMap::taintMem(ADDRINT addr, UINT16 color) 
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		//Byte not in map yet
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, Tag(color)));

	}
	else
	{
		it->second.color = color;
	}
}

void TagMap::untaintMem(ADDRINT addr)
{
	this->memTaintField.erase(addr);
}

Tag TagMap::getTaintColorMem(ADDRINT addr)
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		return Tag(0);
	}
	else
	{
		return it->second;
	}
}

void TagMap::mixTaintMem(ADDRINT dest, ADDRINT src1, ADDRINT src2)
{
	Tag src1MemTag = getTaintColorMem(src1);
	Tag src2MemTag = getTaintColorMem(src2);

	//TODO IMPORTANT: add search in mixed colors collection, now it's generating a new color for each mix
	auto it = this->memTaintField.find(dest);
	if (it == this->memTaintField.end())
	{
		//Byte not in map yet
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest, Tag(src1MemTag.color, src2MemTag.color)));
	}
	else
	{
		it->second = Tag(src1MemTag.color, src2MemTag.color);
	}
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
	for (INT ii = posStart; ii < taintLength; ii++)
	{
		colorVector.push_back(Tag(this->regTaintField[ii]));
	}

	return colorVector;
}

//TODO revise this works
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
		this->regTaintField[ii] = Tag(src1RegColorVector.at(ii).color, src2RegColorVector.at(ii).color);
	}

}


void TagMap::printTaintComplete()
{
	std::cerr << "MEM_TAINT_FIELD PRINT START" << std::endl;
	for (auto const& pair : this->memTaintField) {
		std::cerr << "{" << pair.first << ": " << pair.second.color << "}\n";
	}
	std::cerr << std::endl << "MEM_TAINT_FIELD PRINT END" << std::endl;
}