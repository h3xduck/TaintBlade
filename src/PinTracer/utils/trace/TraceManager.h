#ifndef _TRACE_MANAGER_H_
#define _TRACE_MANAGER_H

#include "pin.H"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "TracePoint.h"

namespace UTILS
{
	namespace TRACE
	{
		class TraceManager
		{
		private:
			/**
			Vector with all dll+function combinations to be traced
			*/
			std::vector<TracePoint> traceVector;

			/**
			Trace a traceooint corresponding to a function, including extraction of its parameters, return value, and whether any colors were changed during its execution
			*/
			void traceTracePoint(TracePoint& tp);

		public:
			TraceManager();

			/**
			Adds a function to be traced
			*/
			void addTracePoint(const std::string &dllName, const std::string &funcName, const int numArgs);
		
			/**
			Checks if a function is to be traced and, if it is, it starts the corresponding tracing function
			*/
			void traceFunction(const std::string& dllName, const std::string& funcName);
		};
	}
}



#endif
