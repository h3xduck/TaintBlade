#ifndef _NOP_SECTION_H_
#define _NOP_SECTION_H_

#include "pin.H"

namespace UTILS
{
	namespace EXEC
	{
		class NopSection
		{
		public:
			ADDRINT baseStartAddress = 0;
			ADDRINT baseEndAddress = 0;
			ADDRINT dynamicStartAddress = 0;
			ADDRINT dynamicEndAddress = 0;
			std::string dllName;

			NopSection(std::string dllName, ADDRINT start, ADDRINT end)
			{
				this->dllName = dllName;
				this->baseStartAddress = start;
				this->baseEndAddress = end;
			}


		};
	}
}

#endif
