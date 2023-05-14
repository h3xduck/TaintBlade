#ifndef _INSTRUMENTATION_MANAGER_H_
#define _INSTRUMENTATION_MANAGER_H_

#include "../../utils/io/log.h"
#include "pin.H"
#include <xed-category-enum.h>
#include "../xed_iclass_instrumentation/BinaryOpc.h"
#include "../xed_iclass_instrumentation/OverwriteOpc.h"
#include "../xed_iclass_instrumentation/SpecialOpc.h"
#include "../../utils/inst/PerformanceOperator.h"
#include "../xed_iclass_instrumentation/ControlFlowOpc.h"
#include "../xed_iclass_instrumentation/CompareOpc.h"
#include "../xed_iclass_instrumentation/StringOpc.h"


class InstrumentationManager
{
public:
	void instrumentInstruction(const INS& ins);
};



#endif