#include "TagMap.h"

TagMap::TagMap()
{
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

void TagMap::untaintReg(LEVEL_BASE::REG reg)
{
	const UINT32 pos_start = this->tReg.getPos(reg);
	const UINT32 taint_length = this->tReg.getTaintLength(reg);
	for (INT ii = pos_start; ii < taint_length; ii++)
	{
		//0 is considered the 'untainted' color
		this->regTaintField[ii] = 0;
	}
}

void TagMap::mixTaintReg(LEVEL_BASE::REG reg1, LEVEL_BASE::REG reg2)
{

}


void TagMap::printTaintComplete()
{
	std::cerr << "MEM_TAINT_FIELD PRINT START" << std::endl;
	for (auto const& pair : this->memTaintField) {
		std::cerr << "{" << pair.first << ": " << pair.second.color << "}\n";
	}
	std::cerr << std::endl << "MEM_TAINT_FIELD PRINT END" << std::endl;
}