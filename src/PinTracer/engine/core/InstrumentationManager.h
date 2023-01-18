#ifndef _INSTRUMENTATION_MANAGER_H_
#define _INSTRUMENTATION_MANAGER_H_

#include "../../utils/io/log.h"
#include "pin.H"
#include <xed-category-enum.h>
#include "../xed_iclass_instrumentation/LogicalOpc.h"
#include "../xed_iclass_instrumentation/MovOpc.h"

class InstrumentationManager
{
public:
	void instrumentInstruction(const INS& ins);
};



#endif