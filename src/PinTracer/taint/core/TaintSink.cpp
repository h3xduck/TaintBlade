#include "TaintSink.h"

extern TaintController taintController;

void TAINT::CORE::TAINT_SINK::createProcessAEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10)
{
	LOG_DEBUG("Called createProcessA!");
	//Check the first two arguments
	WINDOWS::LPCSTR lpApplicationName = (WINDOWS::LPCSTR)arg1;
	WINDOWS::LPSTR lpCommandLine = (WINDOWS::LPSTR)arg2;
		
	//It may happen that any of the first arguments is NULL. PIN gets a bit angry checking nullness directly, so let's do it this way
	char testChar;
	PIN_SafeCopy(&testChar, (const char*)lpApplicationName, 1);

	const char* appNameArr = (const char*)lpApplicationName;
	if (testChar != '\0')
	{
		LOG_DEBUG("Detected application name: " << std::string(appNameArr));
		//Check whether any of the chars is tainted. If it is, then report it
		char c = 10;
		int ii = 0;
		while (c != '\0')
		{
			c = *(appNameArr + ii);
			LOG_DEBUG("Char: " << c);
			bool memTainted = taintController.memIsTainted((ADDRINT)appNameArr + ii);

			LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)appNameArr+ii) << " is tainted: " << memTainted);
			
			ii++;
		}
	}


	PIN_SafeCopy(&testChar, (char*)lpCommandLine, 1);
	char* commandLineArr = (char*)lpCommandLine;
	if (testChar != '\0')
	{
		LOG_DEBUG("Detected application name: " << std::string(commandLineArr));
		char c = 10;
		int ii = 0;
		while (c != '\0')
		{
			c = *(commandLineArr + ii);
			LOG_DEBUG("Char: " << c);
			bool memTainted = taintController.memIsTainted((ADDRINT)commandLineArr + ii);

			LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)commandLineArr+ii) << " is tainted: " << memTainted);

			ii++;
		}
	}
	
}