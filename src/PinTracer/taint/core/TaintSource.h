#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../../utils/io/log.h"


#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um

namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
}



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
	int numArgs = 4;

	//placeholders
	VOID(*enterHandler)() = NULL;
	VOID(*exitHandler)() = NULL;

	TaintSource(const std::string& dllName, const std::string& funcName, VOID(*enter)(), VOID(*exit)())
	{
		this->dllName = dllName;
		this->funcName = funcName;
		this->enterHandler = enter;
		this->exitHandler = exit;
		LOG_DEBUG("TaintSource initiated");
	};

	void taintSourceLogAll();

};

#endif