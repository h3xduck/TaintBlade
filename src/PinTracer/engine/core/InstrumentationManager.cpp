#include "InstrumentationManager.h"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include "../../common/Context.h"

extern Context ctx;

//Info regarding categories from INS_Category and opcodes:
//https://software.intel.com/sites/landingpage/pintool/docs/98484/Pin/html/group__INS__INSPECTION.html#ga3d71d53c5043092d5dbc7c96a2c30b5b
//Categories --> https://intelxed.github.io/ref-manual/xed-category-enum_8h.html
//Opcodes --> idata.txt ex: https://github.com/insuyun/zebra/blob/2c2419ffffbbe289acc9b4314d5f28b76b87fdcf/lib/pin/extras/xed2-ia32/misc/idata.txt

void InstrumentationManager::instrumentInstruction(const INS& ins)
{
	if (!INS_Valid(ins))
	{
		LOG_ERR("Tried to instrument invalid instruction");
		return;
	}
	PerformanceOperator::incrementInstructionCounter();

	xed_iclass_enum_t opc = (xed_iclass_enum_t) INS_Opcode(ins);
	if (opc <= XED_ICLASS_INVALID || opc >= XED_ICLASS_LAST) {
		std::string logLine = "Tried to instrument unknown opcode ";
		logLine += decstr(opc);
		LOG_ERR(logLine);
		return;
	}

	//Log instruction
	//instMap.insert(std::make_pair<ADDRINT, std::string>(INS_Address(ins), INS_Disassemble(ins)));
	//instMap[INS_Address(ins)] = INS_Disassemble(ins);
	//LOG_DEBUG("Logged ip:" << INS_Address(ins));

	switch (opc)
	{
		//Logical binary instructions
		//TODO: in progress
	case XED_ICLASS_ADD:
	case XED_ICLASS_AND:
	case XED_ICLASS_OR:
		OPC_INST::instrumentBinaryOpc(ins);
		ctx.updateCurrentInstruction(INS_Address(ins));
		break;
	case XED_ICLASS_SUB:
	case XED_ICLASS_XOR:
		OPC_INST::instrumentBinaryIfEqualRegClearOpc(ins);
		ctx.updateCurrentInstruction(INS_Address(ins));
		break;
	case XED_ICLASS_LEA:
		OPC_INST::instrumentLeaOpc(ins);
		ctx.updateCurrentInstruction(INS_Address(ins));
		break;
	case XED_ICLASS_MOV:
	case XED_ICLASS_MOVSX:
	case XED_ICLASS_MOVZX:
		OPC_INST::instrumentOverwriteOpc(ins);
		ctx.updateCurrentInstruction(INS_Address(ins));
		break;
	default:
		//Unsupported or ignored, no tainting for those
	#if(REPORT_UNSUPPORTED_INS==1)
			LOG_DEBUG("Unsupported instruction: " << INS_Disassemble(ins));
	#endif
		break;
	}
}