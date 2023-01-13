#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../../utils/io/log.h"
#include "TaintController.h"

#define ANY_FUNC_IN_DLL "ANY_FUNC_DLL_SOURCE"

#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um

namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
}

extern TaintController taintController;

class TaintSource
{
private:
	
public:
	//Handlers
	static VOID wsockRecvEnter()
	{
		LOG_ERR("Not implemented");
	};
	static VOID wsockRecvExit()
	{
		LOG_ERR("Not implemented");
	}

	static VOID mainEnter()
	{
		LOG_DEBUG("Called mainEnter()");
		
		//Test: taint RAX
		taintController.printTaint();
		taintController.taintRegNewColor(REG_RAX);
		taintController.taintRegNewColor(REG_RBX);
	};
	static VOID mainExit()
	{
		LOG_DEBUG("Called mainExit()");
		taintController.printTaint();
	}


	struct func_args_t
	{
		union {
			struct wsock_recv_t
			{
				//Args
				WINDOWS::SOCKET s;
				char* buf;
				int len;
				int flags;

				// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
			} wsock_recv;
		} ua;
	} func_args;

	//typedef void (*callback_function)(void); // type for conciseness

	std::string dllName;
	std::string funcName;
	int numArgs = 0;

	//placeholders
	VOID(*enterHandler)() = NULL;
	VOID(*exitHandler)() = NULL;

	TaintSource(const std::string& dllName, const std::string& funcName, int numArgs, VOID(*enter)(), VOID(*exit)());

	void taintSourceLogAll();

};

#endif