#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../utils/WinAPI.h"

namespace TaintSource
{

	struct wsock_recv_t
	{
		std::string dllName = "wsock32.dll";
		std::string funcName = "recv";
		int numArgs = 4;
		AFUNPTR enterHandler = (AFUNPTR)wsock_recv_enter;
		AFUNPTR exitHandler = (AFUNPTR)wsock_recv_exit;

		WIN::SOCKET s;
		char* buf;
		int len;
		int flags;
		// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
	} wsock_recv;

}


#endif