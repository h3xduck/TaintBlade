#ifndef _INSTRUMENTATION_MANAGER_
#define _INSTRUMENTATION_MANAGER_

#include "pin.H"
#include <xed-category-enum.h>
#include "../../utils/io/log.h"

class InstrumentationManager
{
public:
	void instrumentInstruction(const INS& ins);
};



#endif