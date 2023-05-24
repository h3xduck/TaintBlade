#ifndef _TRACE_MANAGER_H_
#define _TRACE_MANAGER_H_

#include "pin.H"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"
#include "TracePoint.h"
#include "../io/log.h"
#include "../inst/InstructionWorker.h"

namespace UTILS
{
	namespace TRACE
	{

#define FUNCTION_TRACE_ENTER_0(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 0, IARG_END);
#define FUNCTION_TRACE_ENTER_1(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
#define FUNCTION_TRACE_ENTER_2(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
#define FUNCTION_TRACE_ENTER_3(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
#define FUNCTION_TRACE_ENTER_4(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
#define FUNCTION_TRACE_ENTER_5(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
#define FUNCTION_TRACE_ENTER_6(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_UINT32, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_END);
#define FUNCTION_TRACE_EXIT(rtn, dllName, funcName, exit_handler)	\
	RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(exit_handler), IARG_FUNCRET_EXITPOINT_VALUE, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_END);

#define FUNCTION_TRACE(rtn, dllName, funcName, numArgs, enter_handler, exit_handler)	\
	switch(numArgs)	\
	{	\
	case 0:	FUNCTION_TRACE_ENTER_0(rtn, dllName, funcName, enter_handler); break;	\
	case 1:	FUNCTION_TRACE_ENTER_1(rtn, dllName, funcName, enter_handler); break;	\
	case 2:	FUNCTION_TRACE_ENTER_2(rtn, dllName, funcName, enter_handler); break;	\
	case 3:	FUNCTION_TRACE_ENTER_3(rtn, dllName, funcName, enter_handler); break;	\
	case 4:	FUNCTION_TRACE_ENTER_4(rtn, dllName, funcName, enter_handler); break;	\
	case 5:	FUNCTION_TRACE_ENTER_5(rtn, dllName, funcName, enter_handler); break;	\
	case 6:	FUNCTION_TRACE_ENTER_6(rtn, dllName, funcName, enter_handler); break;	\
	default: LOG_ALERT("Failed to trace a routine, too many arguments ("<<numArgs<<")");	\
	}	\
	FUNCTION_TRACE_EXIT(rtn, dllName, funcName, exit_handler)

	/**
	Temporary storage to save the values of arguments before and after the execution of a function.
	Elements inserted when the function is entered and removed when the function exits.
	*/
	static std::vector<TracePoint> interFunctionCallsVector;

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
			void traceTracePoint(RTN &rtn, TracePoint &tp);

		public:
			TraceManager();

			/**
			Adds a routine to be traced
			*/
			void addTracePoint(const std::string &dllName, const std::string &funcName, const int numArgs);
		
			/**
			Checks if a function is to be traced and, if it is, it starts the corresponding tracing function
			*/
			void traceFunction(RTN rtn, const std::string& dllName, const std::string& funcName);
		};
	}
}



#endif
