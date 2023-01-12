#include "TRegister.h"


TReg::TReg()
{
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RAX, 0));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RBX, 8));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RCX, 16 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RDX, 24 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RSI, 32 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RDI, 40 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R8, 48 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R9, 56 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R10, 64 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R11, 72 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R12, 80 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R13, 88 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R14, 96 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R15, 104 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RSP, 112 ));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_RBP, 120 ));
};

UINT32 TReg::getPos(INT reg)
{
	auto it = this->regIndexMapping.find(reg);
	if (it != this->regIndexMapping.end()) 
	{ 
		return it->second;
	}
	else 
	{ 
		//Shouldn't happen at any point
		LOG_ERR("Tried to get taint position of non supported register");
		return 256;
	}
}

UINT32 TReg::getTaintLength(LEVEL_BASE::REG reg)
{
	if (!REG_valid(reg))
	{
		LOG_DEBUG("Invalid register found");
		return 0;
	}
	if (REG_is_gr64(reg))
	{
		return 8;
	}
	else if(REG_is_gr32(reg))
	{
		return 4;
	}
	else if (REG_is_gr16(reg))
	{
		return 2;
	}
	else if (REG_is_gr8(reg))
	{
		return 1;
	}
	else
	{
		LOG_ERR("Tried to get taint length of non supported register: "<<reg);
		return 0;
	}
}