#ifndef _INSTRUMENTATION_MANAGER_H_
#define _INSTRUMENTATION_MANAGER_H_

#include "../../utils/io/log.h"
#include "pin.H"
#include <xed-category-enum.h>

class InstrumentationManager
{
public:
	void instrumentInstruction(const INS& ins);
};



#endif