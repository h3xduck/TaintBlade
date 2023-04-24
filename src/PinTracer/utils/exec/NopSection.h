#ifndef _NOP_SECTION_H_
#define _NOP_SECTION_H_

#include "pin.H"

namespace UTILS
{
	namespace EXEC
	{
		class NopSection
		{
		private:
			ADDRINT baseStartAddress = 0;
			ADDRINT baseEndAddress = 0;
			ADDRINT dynamicStartAddress = 0;
			ADDRINT dynamicEndAddress = 0;
			std::string dllName;

			/**
			Lines of code passed by the user that will modify the program after NOP-ing all bytes
			*/
			std::vector<std::string> userAssemblyLines;
		public:
			NopSection(std::string dllName, ADDRINT start, ADDRINT end);

			//Setters and getters
			void setBaseStartAddress(ADDRINT addr);
			ADDRINT getBaseStartAddress();
			void setBaseEndAddress(ADDRINT addr);
			ADDRINT getBaseEndAddress();
			void setDynamicStartAddress(ADDRINT addr);
			ADDRINT getDynamicStartAddress();
			void setDynamicEndAddress(ADDRINT addr);
			ADDRINT getDynamicEndAddress();
			void setDllName(std::string name);
			std::string getDllName();
			void setUserAssemblyLines(std::vector<std::string> lines);
			std::vector<std::string> getUserAssemblyLines();
		};
	}
}

#endif
