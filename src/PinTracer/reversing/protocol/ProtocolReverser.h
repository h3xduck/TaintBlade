#ifndef _PROTOCOLREVERSER_H
#define _PROTOCOL_REVERSER_H

#include "../core/RevContext.h"
#include "../../common/Context.h"
#include "../../taint/core/TaintManager.h"

extern TaintManager taintManager;

namespace REVERSING
{
	namespace PROTOCOL
	{
		/**
		Takes the heuristics found in the context and tries to find protocol matchings
		*/
		void reverseProtocol();
	}
}



#endif

