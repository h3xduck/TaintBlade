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

		public:
			TracePoint(std::string dllName, std::string funcName, int numArgs);

			//Getters
			std::string& getDllName();
			std::string& getFuncName();
			int getNumArgs();
		};

	}
}




#endif

