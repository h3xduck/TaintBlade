#include "InstrumentationManager.h"
#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>

#include "../xed_iclass_instrumentation/LogicalOpc.h"

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

	xed_iclass_enum_t opc = (xed_iclass_enum_t) INS_Opcode(ins);
	if (opc <= XED_ICLASS_INVALID || opc >= XED_ICLASS_LAST) {
		std::string logLine = "Tried to instrument unknown opcode ";
		logLine += decstr(opc);
		LOG_ERR(logLine);
		return;
	}

	switch (opc)
	{
		//Logical binary instructions
		//TODO
	case XED_ICLASS_AND:
		instrumentLogicalOpc(ins);
	default:
		break;

	}
}