#include "PseudoAssemblyParser.h"

void executeAssemblyLine(ADDRINT *reg, ADDRINT value)
{
	*reg = value;
	LOG_DEBUG("Modified value of register in user-provided assembly line to be: " << (ADDRINT)*reg<<" | original: "<<(ADDRINT)value);
}

void UTILS::EXEC::PseudoAssemblyParser::instrumentAssemblyLine(INS ins, std::string codeLine)
{
	//The format of the code line must be
	//REG=value
	
	std::istringstream isdata(codeLine);
	std::string regStr;
	std::getline(isdata, regStr, '=');
	std::string valueStr;
	std::getline(isdata, valueStr, '=');

	//Now we put the value into the register
	xed_reg_enum_t xedReg = str2xed_reg_enum_t(regStr.c_str());
	REG reg;
	switch (xedReg)
	{
#ifdef TARGET_IA32E
	case XED_REG_RAX: reg = REG_RAX; break;
	case XED_REG_RBX: reg = REG_RBX; break;
	case XED_REG_RCX: reg = REG_RCX; break;
	case XED_REG_RDX: reg = REG_RDX; break;
	case XED_REG_RDI: reg = REG_RDI; break;
	case XED_REG_RSI: reg = REG_RSI; break;
	case XED_REG_R8: reg = REG_R8; break;
	case XED_REG_R9: reg = REG_R9; break;
	case XED_REG_R10: reg = REG_R10; break;
	case XED_REG_R11: reg = REG_R11; break;
	case XED_REG_R12: reg = REG_R12; break;
	case XED_REG_R13: reg = REG_R13; break;
#endif
	case XED_REG_EAX: reg = REG_EAX; break;
	case XED_REG_EBX: reg = REG_EBX; break;
	case XED_REG_ECX: reg = REG_ECX; break;
	case XED_REG_EDX: reg = REG_EDX; break;
	case XED_REG_EDI: reg = REG_EDI; break;
	case XED_REG_ESI: reg = REG_ESI; break;
	default:
		LOG_ALERT("Tried to execute an invalid user-provided assembly line");
		return;
	}
	ADDRINT value = std::stoull(valueStr);
	INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(executeAssemblyLine), IARG_REG_REFERENCE, reg, IARG_ADDRINT, value, IARG_END);
}