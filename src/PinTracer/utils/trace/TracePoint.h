#ifndef _TRACE_POINT_H_
#define _TRACE_POINT_H_

#include "pin.H"
#include <iostream>

namespace UTILS
{
	namespace TRACE
	{
		class TracePoint
		{
		private:
			std::string dllName;
			std::string funcName;
			int numArgs;

			//Arguments before calling the function
			std::vector<std::string> argsPre;
			//Arguments before calling the function, but as pointers to program memory, so that the values can be read on exit
			std::vector<void*> argsPrePtr;
			//Arguments after calling the function
			std::vector<std::string> argsPost;

		public:
			TracePoint(std::string dllName, std::string funcName, int numArgs);

			//Getters and setters
			std::string getDllName();
			std::string getFuncName();
			int getNumArgs();
			std::vector<std::string>& getArgsPre();
			void setArgsPre(std::vector<std::string> vec);
			std::vector<void*> getArgsPrePtr();
			void setArgsPrePtr(std::vector<void*> vec);
			std::vector<std::string>& getArgsPost();
			void setArgsPost(std::vector<std::string> vec);
		};

	}
}




#endif

