#ifndef _DLL_IMAGE_LOAD_H_
#define _DLL_IMAGE_LOAD_H_

#include "pin.H"
#include "../inst/InstructionWorker.h"

namespace UTILS
{
	namespace EXEC
	{
		class DllImageLoad
		{
		private:
			std::string dllName;

			ADDRINT baseLoadAddress = 0;
			ADDRINT dynamicLoadAddress = 0;
		public:
			DllImageLoad(std::string dllName, ADDRINT dynamicLoadAdddress);

			//Setters and getters
			std::string getName();
			ADDRINT getBaseLoadAddress();
			ADDRINT getDynamicLoadAddress();
		};

	}
}


#endif