#include "TagMap.h"
#include "Tag.h"

TagMap::TagMap()
{
	Tag memInfo = { 0 };
	this->tReg = TReg();
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


void TagMap::taintReg(LEVEL_BASE::REG reg, UINT16 color)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 pos_start = this->tReg.getPos(reg);
	const UINT32 taint_length = this->tReg.getTaintLength(reg);
	for (INT ii = pos_start; ii < taint_length; ii++)
	{
		this->regTaintField[ii] = color;
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