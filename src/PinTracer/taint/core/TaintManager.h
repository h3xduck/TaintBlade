#ifndef _TAINT_MANAGER_H_
#define _TAINT_MANAGER_H_

//The order of these two includes is critical, since PINCRT must come first
#include "TaintController.h"
#include "TaintSource.h"
#include "TaintSink.h"
#include "../../config/Names.h"
#include "../../utils/io/DataDumper.h"

#include <iostream>
#include <cstdio>
#include <algorithm>

#define INS_CALL_RTN_TAINT_ENTER_0(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_1(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_2(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_3(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_4(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_5(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_6(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_7(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_8(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_9(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_FUNCARG_ENTRYPOINT_VALUE, 8, IARG_END);
#define INS_CALL_RTN_TAINT_ENTER_10(rtn, dllName, funcName, enter_handler)	\
	RTN_InsertCall(rtn, IPOINT_BEFORE, AFUNPTR(enter_handler), IARG_RETURN_IP, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3, IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6, IARG_FUNCARG_ENTRYPOINT_VALUE, 7, IARG_FUNCARG_ENTRYPOINT_VALUE, 8, IARG_FUNCARG_ENTRYPOINT_VALUE, 9, IARG_END);

#define INS_CALL_RTN_TAINT_EXIT(rtn, dllName, funcName, exit_handler)	\
	RTN_InsertCall(rtn, IPOINT_AFTER, AFUNPTR(exit_handler), IARG_FUNCRET_EXITPOINT_VALUE, IARG_PTR, new std::string(dllName), IARG_PTR, new std::string(funcName), IARG_END);


#define INS_CALL_RTN_TAINT(rtn, dllName, funcName, numArgs, enter_handler, exit_handler)	\
	switch(numArgs)	\
	{	\
	case 0:	INS_CALL_RTN_TAINT_ENTER_0(rtn, dllName, funcName, enter_handler); break;	\
	case 1:	INS_CALL_RTN_TAINT_ENTER_1(rtn, dllName, funcName, enter_handler); break;	\
	case 2:	INS_CALL_RTN_TAINT_ENTER_2(rtn, dllName, funcName, enter_handler); break;	\
	case 3:	INS_CALL_RTN_TAINT_ENTER_3(rtn, dllName, funcName, enter_handler); break;	\
	case 4:	INS_CALL_RTN_TAINT_ENTER_4(rtn, dllName, funcName, enter_handler); break;	\
	case 5:	INS_CALL_RTN_TAINT_ENTER_5(rtn, dllName, funcName, enter_handler); break;	\
	case 6:	INS_CALL_RTN_TAINT_ENTER_6(rtn, dllName, funcName, enter_handler); break;	\
	case 7:	INS_CALL_RTN_TAINT_ENTER_7(rtn, dllName, funcName, enter_handler); break;	\
	case 8:	INS_CALL_RTN_TAINT_ENTER_8(rtn, dllName, funcName, enter_handler); break;	\
	case 9:	INS_CALL_RTN_TAINT_ENTER_9(rtn, dllName, funcName, enter_handler); break;	\
	case 10: INS_CALL_RTN_TAINT_ENTER_10(rtn, dllName, funcName, enter_handler); break;	\
	}	\
if(exit_handler !=NULL) INS_CALL_RTN_TAINT_EXIT(rtn, dllName, funcName, exit_handler)
	
extern TaintController taintController;

class TaintManager
{
private:
	std::tr1::unordered_map <std::string, std::vector<TaintSource>> taintFunctionMap;

public:
	TaintManager();

	TaintController& getController();

	void routineLoadedEvent(RTN rtn, std::string dllName, std::string funcName);

	/**
	Registers a new DLL + FUNC combination in the system as taint sources.
	The combination must be previously prepared by the system, it does not accept arbitrary generic
	function instrumentation (yet).
	*/
	void registerTaintSource(const std::string& dllName, const std::string& funcName, int numArgs);

	void unregisterTaintSource(const std::string& dllName, const std::string& funcName);

};

#endif