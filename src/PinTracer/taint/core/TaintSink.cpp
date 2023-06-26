#include "TaintSink.h"
#include "../../common/Context.h"

extern TaintController taintController;
extern Context ctx;

typedef struct func_dll_and_args_t
{
	std::string dllName;
	std::string funcName;
	ADDRINT ip;
	void* arg1;
	void* arg2;
	void* arg3;
	void* arg4;
	void* arg5;
	void* arg6;
	void* arg7;
	void* arg8;
	void* arg9;
	void* arg10;
};

static std::tr1::unordered_map<size_t, struct func_dll_and_args_t> sinkCallsData;

void TAINT::CORE::TAINT_SINK::createProcessAEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10)
{
	LOG_DEBUG("Called createProcessA!");
	bool taintSinkActivated = false; //whether any tainted data did end up into the sink function
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
				taintSinkActivated = true;
				UINT16 color = taintController.memGetColor((ADDRINT)appNameArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)appNameArr + ii) << " with color " << color << " is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color))
				{
					TagLog::color_taint_lead_t lead;
					lead.leadClass = TagLog::TAINT_LEAD_SINK;
					lead.sinkData = {
						*dllNameStr,
						*funcNameStr,
						0,
						(ADDRINT)ii
					};

					taintController.registerColorLead(colorParent, lead);
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
				taintSinkActivated = true;
				UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)commandLineArr + ii) << " with color " << color << " is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color)) {
					UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
					TagLog::color_taint_lead_t lead;
					lead.leadClass = TagLog::TAINT_LEAD_SINK;
					lead.sinkData = {
						*dllNameStr,
						*funcNameStr,
						1,
						(ADDRINT)ii
					};

					taintController.registerColorLead(colorParent, lead);
				}
			}

			ii++;
		}
	}

	if (taintSinkActivated)
	{
		//Register that this routine had some taint event
		UTILS::IO::DataDumpLine::taint_routine_dump_line_t data;
		PIN_LockClient();
		data.instAddrEntry = currIp;
		RTN rtn = RTN_FindByAddress(currIp);
		if (rtn == RTN_Invalid())
		{
			return;
		}
		RTN_Open(rtn);
		data.instAddrLast = INS_Address(RTN_InsTail(rtn));
		data.dll = *dllNameStr;
		data.func = *funcNameStr;
		data.containedEventsType = UTILS::IO::DataDumpLine::TAINT_SINK;
		ctx.getDataDumper().writeTaintRoutineDumpLine(data);
		RTN_Close(rtn);
		PIN_UnlockClient();
	}
}
	

void TAINT::CORE::TAINT_SINK::createProcessWEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6, void* arg7, void* arg8, void* arg9, void* arg10)
{
	LOG_DEBUG("Called createProcessW!");
	bool taintSinkActivated = false; //whether any tainted data did end up into the sink function
	const std::string* dllNameStr = static_cast<std::string*>(dllName);
	const std::string* funcNameStr = static_cast<std::string*>(funcName);

	//Check the first two arguments
	WINDOWS::LPCWSTR lpApplicationNameW = (WINDOWS::LPCWSTR)arg1;
	WINDOWS::LPWSTR lpCommandLineW = (WINDOWS::LPWSTR)arg2;

	//It may happen that any of the first arguments is NULL. PIN gets a bit angry checking nullness directly, so let's do it this way
	const wchar_t* appNameArr = (const wchar_t*)lpApplicationNameW;
	if (arg1 != NULL)
	{
		LOG_DEBUG("Detected application name: " << wcharstrToCharstr(std::wstring(appNameArr)));
		//Check whether any of the chars is tainted. If it is, then report it
		wchar_t c = 10;
		int ii = 0;
		while (c != L'\0')
		{
			LOG_DEBUG("Examining memory at " << to_hex_dbg((ADDRINT)appNameArr + ii));
			c = *(appNameArr + ii);
			bool memTainted = taintController.memIsTainted((ADDRINT)appNameArr + ii);

			if (memTainted)
			{
				taintSinkActivated = true;
				UINT16 color = taintController.memGetColor((ADDRINT)appNameArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)appNameArr + ii) << " with color " << color << " is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color))
				{
					TagLog::color_taint_lead_t lead;
					lead.leadClass = TagLog::TAINT_LEAD_SINK;
					lead.sinkData = {
						*dllNameStr,
						*funcNameStr,
						0,
						(ADDRINT)ii
					};

					taintController.registerColorLead(colorParent, lead);
				}
			}

			ii++;
		}
	}

	wchar_t* commandLineArr = (wchar_t*)lpCommandLineW;
	if (arg2 != NULL)
	{
		LOG_DEBUG("Detected application name: " << wcharstrToCharstr(std::wstring(commandLineArr)));
		wchar_t c = 10;
		int ii = 0;
		while (c != '\0')
		{
			c = *(commandLineArr + ii);
			bool memTainted = taintController.memIsTainted((ADDRINT)commandLineArr + ii);

			LOG_DEBUG("Examining memory at " << to_hex_dbg((ADDRINT)commandLineArr + ii));
			if (memTainted)
			{
				taintSinkActivated = true;
				UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
				LOG_DEBUG("Memory at " << to_hex_dbg((ADDRINT)commandLineArr + ii) << " with color " << color << " is tainted: " << memTainted);

				//We will mark any color that was a parent of this one to be part of a command (since their data will be here)
				for (UINT16& colorParent : taintController.getColorParents(color)) {
					UINT16 color = taintController.memGetColor((ADDRINT)commandLineArr + ii);
					TagLog::color_taint_lead_t lead;
					lead.leadClass = TagLog::TAINT_LEAD_SINK;
					lead.sinkData = {
						*dllNameStr,
						*funcNameStr,
						1,
						(ADDRINT)ii
					};

					taintController.registerColorLead(colorParent, lead);
				}
			}

			ii++;
		}
	}

	if (taintSinkActivated)
	{
		//Register that this routine had some taint event
		UTILS::IO::DataDumpLine::taint_routine_dump_line_t data;
		PIN_LockClient();
		data.instAddrEntry = currIp;
		RTN rtn = RTN_FindByAddress(currIp);
		if (rtn == RTN_Invalid())
		{
			return;
		}
		RTN_Open(rtn);
		data.instAddrLast = INS_Address(RTN_InsTail(rtn));
		data.dll = *dllNameStr;
		data.func = *funcNameStr;
		data.containedEventsType = UTILS::IO::DataDumpLine::TAINT_SINK;
		ctx.getDataDumper().writeTaintRoutineDumpLine(data);
		RTN_Close(rtn);
		PIN_UnlockClient();
	}
}

void TAINT::CORE::TAINT_SINK::MultiByteToWideCharEnter(ADDRINT currIp, ADDRINT retIp, VOID* dllName, VOID* funcName, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
{
	LOG_DEBUG("Called MultiByteToWideChar at enter!");
	const std::string* dllNameStr = static_cast<std::string*>(dllName);
	const std::string* funcNameStr = static_cast<std::string*>(funcName);

	//The key for the map is the has of the function
	std::hash<std::string> hasher;
	const size_t hash = hasher(*funcNameStr);

	sinkCallsData.erase(hash);
	struct func_dll_and_args_t data;
	data.dllName = *dllNameStr;
	data.funcName = *funcNameStr;
	data.ip = currIp;
	data.arg1 = arg1;
	data.arg2 = arg2;
	data.arg3 = arg3;
	/*WINDOWS::LPCCH str3W = (WINDOWS::LPCCH)arg3;
	char* str3 = (char*)str3W;
	int int1 = (int)arg1;
	int int2 = (int)arg2;
	int int4 = (int)arg4;
	PIN_LockClient();
	LOG_DEBUG("["<<to_hex_dbg(InstructionWorker::getBaseAddress(retIp))<<"]AT "<< *dllNameStr <<" | "<< *funcNameStr<< " ENTERRECEIVED: " << str3<< "INT1:" << int1 << " INT2:"<<int2<<" INT4:"<<int4);
	*/
	data.arg4 = arg4;
	data.arg5 = arg5;
	data.arg6 = arg6;
	sinkCallsData.insert(std::make_pair<size_t, struct func_dll_and_args_t>(hash, data));
}

void TAINT::CORE::TAINT_SINK::MultiByteToWideCharExit(ADDRINT retVal, VOID* dllName, VOID* funcName)
{
	LOG_DEBUG("Called MultiByteToWideChar at exit!");
	bool taintSinkActivated = false; //whether any tainted data did end up into the sink function
	const std::string* dllNameStr = static_cast<std::string*>(dllName);
	const std::string* funcNameStr = static_cast<std::string*>(funcName);

	std::hash<std::string> hasher;
	const size_t hash = hasher(*funcNameStr);

	auto it = sinkCallsData.find(hash);
	if (it == sinkCallsData.end())
	{
		//LOG_ALERT("Tried to instrument sink function at exit, but entry not found: " << to_hex_dbg(ip) << " | " << to_hex_dbg(branchTargetAddress));
	}
	else
	{
		//At this point, we dump the function and the arguments
		struct func_dll_and_args_t funcDllData;
		funcDllData = it->second;

		//Instrument the function MultiByteToWideCharExit according to:
		//https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar

		//If args are 0, either fails or returns data we don't care about
		if (retVal == 0 || funcDllData.arg6 == 0 || funcDllData.arg4 == 0)
		{
			sinkCallsData.erase(hash);
			return;
		}

		//The number of bytes indicated in arg3 are the ones transformed
		int transLen = retVal;
		//If the bytes from the src sring were tainted, the ones from the wide one will be too
		WINDOWS::LPCCH srcStrW = (WINDOWS::LPCCH)funcDllData.arg3;
		char* srcStr = (char*)srcStrW;
		WINDOWS::LPWSTR destStrW = (WINDOWS::LPWSTR)funcDllData.arg5;
		wchar_t* destStr = (wchar_t*)destStrW;

		if(srcStr!=NULL) LOG_DEBUG("SrcString: " << std::string(srcStr));
		if (destStr != NULL) LOG_DEBUG("DestString: " << wcharstrToCharstr(std::wstring(destStr)));

		//Update the instruction values so that we are right at the end of the routine right now, 
		//where we taint the data (or not)
		PIN_LockClient();
		RTN rtn = RTN_FindByAddress(funcDllData.ip);
		if (rtn == RTN_Invalid())
		{
			PIN_UnlockClient();
			return;
		}
		RTN_Open(rtn);
		const ADDRINT routineEndInstAddress = INS_Address(RTN_InsTail(rtn));
		RTN_Close(rtn);
		ctx.updateCurrentInstructionFullAddress(routineEndInstAddress);
		ctx.updateCurrentBaseInstruction(InstructionWorker::getBaseAddress(routineEndInstAddress));
		PIN_UnlockClient();

		for (int ii = 0; ii < transLen; ii++)
		{
			//If the byte was tainted, the one from the dest is too
			bool memTainted = taintController.memIsTainted((ADDRINT)srcStr + ii);
			if (memTainted)
			{
				taintSinkActivated = true;
				UINT16 color = taintController.memGetColor((ADDRINT)srcStr + ii);
				taintController.taintMemByteWithColor((ADDRINT)destStr + ii, color, true);
				LOG_DEBUG("MultiByteToWideChar: Tainted mem[" << to_hex_dbg((ADDRINT)destStr + ii) << "] with color " << color << " from mem[" << to_hex_dbg((ADDRINT)srcStr + ii) << "]");
			}

		}
			
		sinkCallsData.erase(hash);

		if (taintSinkActivated)
		{
			//Register that this routine had some taint event
			UTILS::IO::DataDumpLine::taint_routine_dump_line_t data;
			PIN_LockClient();
			data.instAddrEntry = funcDllData.ip;
			data.instAddrLast = routineEndInstAddress;
			data.dll = *dllNameStr;
			data.func = *funcNameStr;
			data.containedEventsType = UTILS::IO::DataDumpLine::TAINT_SINK;
			ctx.getDataDumper().writeTaintRoutineDumpLine(data);
			PIN_UnlockClient();
		}
		
	}
	LOG_DEBUG("Exited MultiByteToWideChar at exit!");

	
}