#include "TaintSink.h"

extern TaintController taintController;

void TAINT::CORE::TAINT_SINK::createProcessAEnter(ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10)
{
	LOG_DEBUG("Called createProcessA!");
	const std::string* dllNameStr = static_cast<std::string*>(dllName);
	const std::string* funcNameStr = static_cast<std::string*>(funcName);

	//Check the first two arguments
	WINDOWS::LPCSTR lpApplicationName = (WINDOWS::LPCSTR)arg1;
	WINDOWS::LPSTR lpCommandLine = (WINDOWS::LPSTR)arg2;
		
	//It may happen that any of the first arguments is NULL. PIN gets a bit angry checking nullness directly, so let's do it this way
	const char* appNameArr = (const char*)lpApplicationName;
	if (arg1 != NULL)
	{
		LOG_DEBUG("Detected application name: " << std::string(appNameArr));
		//Check whether any of the chars is tainted. If it is, then report it
		char c = 10;
		int ii = 0;
		while (c != '\0')
		{
			c = *(appNameArr + ii);
			bool memTainted = taintController.memIsTainted((ADDRINT)appNameArr + ii);

			if (memTainted)
			{
				UINT16 color = taintController.memGetColor((ADDRINT)appNameArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)appNameArr + ii) << " with color "<<color<<" is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color))
				{
					TagLog::color_taint_reason_t reason;
					reason.reasonClass = TagLog::TAINT_REASON_SINK;
					reason.sinkData = {
						*dllNameStr,
						*funcNameStr,
						0,
						(ADDRINT)ii
					};

					taintController.registerColorReason(colorParent, reason);
				}
			}

			ii++;
		}
	}

	char* commandLineArr = (char*)lpCommandLine;
	if (arg2 != NULL)
	{
		LOG_DEBUG("Detected application name: " << std::string(commandLineArr));
		char c = 10;
		int ii = 0;
		while (c != '\0')
		{
			c = *(commandLineArr + ii);
			bool memTainted = taintController.memIsTainted((ADDRINT)commandLineArr + ii);

			if (memTainted)
			{
				UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)commandLineArr + ii) << " with color " << color << " is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color)) {
					UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
					TagLog::color_taint_reason_t reason;
					reason.reasonClass = TagLog::TAINT_REASON_SINK;
					reason.sinkData = {
						*dllNameStr,
						*funcNameStr,
						1,
						(ADDRINT)ii
					};

					taintController.registerColorReason(colorParent, reason);
				}
			}

			ii++;
		}
	}
	
}