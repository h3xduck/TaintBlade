#ifndef _INSTRUMENTATION_MANAGER_H_
#define _INSTRUMENTATION_MANAGER_H_

#include "pin.H"
#include <xed-category-enum.h>
#include "../../utils/io/log.h"

class InstrumentationManager
{
public:
	void instrumentInstruction(const INS& ins);
};



#endif