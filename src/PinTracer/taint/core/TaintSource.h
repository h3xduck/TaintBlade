#ifndef _TAINT_SOURCE_H_
#define _TAINT_SOURCE_H_

#include "../../utils/io/log.h"
#include <stdarg.h>
#include "TaintController.h"
#include "../../utils/inst/InstructionWorker.h"

#define ANY_FUNC_IN_DLL "ANY_FUNC_DLL_SOURCE"

#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um

namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
}

extern TaintController taintController;

//Function arguments
struct wsock_recv_t
{
	//Args
	WINDOWS::SOCKET s;
	char* buf;
	int len;
	int flags;

	// https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-recv
};
static wsock_recv_t wsockRecv;

class TaintSource
{
private:

public:
	//Handlers
	static VOID wsockRecvEnter(int retIp, std::string dllName, std::string funcName, ...)
	{
		int NUM_ARGS = 4;
		va_list vaList;
		va_start(vaList, funcName);

		wsockRecv.s = va_arg(vaList, WINDOWS::SOCKET);
		wsockRecv.buf = va_arg(vaList, char*);
		wsockRecv.len = va_arg(vaList, int);
		wsockRecv.flags = va_arg(vaList, int);

		va_end(vaList);

		LOG_INFO("Called wsockRecvEnter()\n\tretIp: "<<retIp<<"\n\tbuf: " << wsockRecv.buf << "\n\tlen: "<< wsockRecv.len);
	};
	static VOID wsockRecvExit(int retVal, std::string dllName, std::string funcName, ...)
	{
		//Firstly, we must check that we received something. Return value is # of bytes read
		if(retVal<=0)
		{
			//No tainting needed
			return;
		}
		//Otherwise, we taint as many bytes in buf as indicated by retVal
		LOG_INFO("Called wsockRecvExit()\n\tretVal:" << retVal << "\n\tbuf: " << wsockRecv.buf << "\n\tlen: " << wsockRecv.len);

		std::vector<UINT16> colorVector = taintController.taintMemoryNewColor((ADDRINT)wsockRecv.buf, retVal);
		//LOG_DEBUG("Logging original color:: DLL:" << dllName << " FUNC:" << funcName);
		for (auto color : colorVector)
		{
			taintController.registerOriginalColor(color, dllName, funcName);
		}
		
	}

	static VOID mainEnter(int retIp, std::string dllName, std::string funcName, ...)
	{
		LOG_DEBUG("Called mainEnter()");
		
		//Test: taint RAX
		//taintController.printTaint();
		taintController.taintRegNewColor(REG_RAX);
		taintController.taintRegNewColor(REG_RBX);
	};
	static VOID mainExit(int retVal, std::string dllName, std::string funcName, ...)
	{
		LOG_DEBUG("Called mainExit()");
		//taintController.printTaint();
	}

	static VOID emptyHandler() {};

	//typedef void (*callback_function)(void); // type for conciseness

	std::string dllName;
	std::string funcName;
	int numArgs = 0;

	//placeholders
	VOID(*enterHandler)(int, std::string, std::string, ...) = NULL;
	VOID(*exitHandler)(int, std::string, std::string, ...) = NULL;

	TaintSource() {};
	TaintSource(const std::string dllName, const std::string funcName, int numArgs, VOID(*enter)(int, std::string, std::string, ...), VOID(*exit)(int, std::string, std::string, ...));

	void taintSourceLogAll();

};

#endif