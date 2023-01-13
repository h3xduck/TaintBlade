#ifndef _TAINT_MANAGER_H_
#define _TAINT_MANAGER_H_

//The order of these two includes is critical, since PINCRT must come first
#include "TaintController.h"
#include "TaintSource.h"

#include <iostream>
#include <cstdio>

#define INS_CALL_RTN_TAINT_ENTER_0(rtn, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_1(rtn, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_2(rtn, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_3(rtn, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_4(rtn, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
#define INS_CALL_RTN_TAINT_EXIT(rtn, exit_handler)	\
	RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(exit_handler), IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);


#define INS_CALL_RTN_TAINT(rtn, numArgs, enter_handler, exit_handler)	\
	switch(numArgs)	\
	{	\
	case 0:	INS_CALL_RTN_TAINT_ENTER_0(rtn, enter_handler); break;	\
	case 1:	INS_CALL_RTN_TAINT_ENTER_1(rtn, enter_handler); break;	\
	case 2:	INS_CALL_RTN_TAINT_ENTER_2(rtn, enter_handler); break;	\
	case 3:	INS_CALL_RTN_TAINT_ENTER_3(rtn, enter_handler); break;	\
	case 4:	INS_CALL_RTN_TAINT_ENTER_4(rtn, enter_handler); break;	\
	}	\
	INS_CALL_RTN_TAINT_EXIT(rtn, exit_handler)
	
extern TaintController taintController;

class TaintManager
{
private:
	std::tr1::unordered_map <std::string, std::vector<TaintSource>> taintFunctionMap;

public:
	TaintManager();

	TaintController& getController();

	void routineLoadedEvent(RTN rtn, const std::string& dllName, const std::string& funcName);

	void registerTaintSource(const std::string& dllName, const std::string& funcName, int numArgs);
	void unregisterTaintSource(const std::string& dllName, const std::string& funcName);

};

#endif