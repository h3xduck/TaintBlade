#include "TRegister.h"


TReg::TReg()
{
	//64 bit
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
	//32 bit
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_EAX, 4));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_EBX, 12));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_ECX, 20));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_EDX, 28));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_ESI, 36));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_EDI, 44));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R8D, 52));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R9D, 60));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R10D, 68));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R11D, 76));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R12D, 84));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R13D, 92));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R14D, 100));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R15D, 108));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_ESP, 116));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_EBP, 124));
	//16 bit
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_AX, 6));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_BX, 14));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_CX, 22));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_DX, 30));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_SI, 38));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_DI, 46));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R8W, 54));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R9W, 62));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R10W, 70));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R11W, 78));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R12W, 86));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R13W, 94));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R14W, 102));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R15W, 110));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_SP, 118));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_BP, 126));
	//8 bit - high
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_AH, 6));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_BH, 14));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_CH, 22));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_DH, 30));
	//8 bit - low
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_AL, 7));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_BL, 15));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_CL, 23));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_DL, 31));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_SIL, 39));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_DIL, 47));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R8B, 55));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R9B, 63));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R10B, 71));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R11B, 79));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R12B, 87));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R13B, 95));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R14B, 103));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_R15B, 111));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_SPL, 119));
	this->regIndexMapping.insert(std::make_pair<INT, UINT32>(REG_BPL, 127));
};

UINT32 TReg::getPos(INT reg)
{
	auto it = this->regIndexMapping.find(reg);
	if (it != this->regIndexMapping.end()) 
	{ 
		//LOG_DEBUG("Found reg " << reg << " at position " << it->second);
		return it->second;
	}
	else 
	{ 
		//Shouldn't happen, but RIP and RSP are not tainted yet (e.g.: lea)
		//LOG_INFO("Tried to get taint position of non supported register");
		return INVALID_REGISTER_POSITION;
	}
}

UINT32 TReg::getTaintLength(LEVEL_BASE::REG reg)
{
	if (!REG_valid(reg))
	{
		//LOG_DEBUG("Invalid register found");
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
#if(REPORT_UNSUPPORTED_REG)
		//LOG_INFO("Tried to get taint length of non supported register: "<<reg);
#endif
		return 0;
	}
}

BOOL TReg::isSupported(REG reg)
{
	return this->getPos(reg) != INVALID_REGISTER_POSITION;
}