#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../utils/WinAPI.h"
#include "../io/log.h"






class TaintSource
{
private:
	static VOID wsockRecvEnter()
	{
		LOG_ERR("Not implemented");
	}
	static VOID wsockRecvExit()
	{
		LOG_ERR("Not implemented");
	}

public:
	typedef void (*callback_function)(void); // type for conciseness
	TaintSource(std::string& dllName, std::string& funcName, VOID (*enter)(void), VOID(*exit)(), struct func_args_t args);

	std::string dllName = "wsock32.dll";
	std::string funcName = "recv";
	int numArgs = 4;
	VOID(*enterHandler)() = wsockRecvEnter;
	VOID(*exitHandler)() = wsockRecvExit;
	
	struct func_args_t
	{
		union {
			struct wsock_recv_t
			{
				//WINDOWS::SOCKET s;
				char* buf;
				int len;
				int flags;
				// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
			} wsock_recv;
		} ua;
	} func_args;

};

#endif