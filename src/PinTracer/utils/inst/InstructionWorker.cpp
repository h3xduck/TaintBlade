#include "InstructionWorker.h"

std::string getStringFromArg(void* arg)
{
	std::wstring res = InstructionWorker::printFunctionArgument((void*)arg);
	std::string resW(res.begin(), res.end());
	return resW;
}


ADDRINT InstructionWorker::getBaseAddress(ADDRINT addr)
{
	if (addr == 0)
	{
		return 0;
	}

	IMG module = IMG_FindByAddress(addr);
	ADDRINT base = IMG_LoadOffset(module);
	if (base == 0)
	{
		base = IMG_LowAddress(module);
		if (base == 0)
		{
			base = GetPageOfAddr(addr);
		}
	}

	ADDRINT baseAddr = addr - base;

	return baseAddr;
}

std::string InstructionWorker::getDllFromAddress(ADDRINT addr)
{
	IMG module = IMG_FindByAddress(addr);
	if (!IMG_Valid(module))
	{
		return NULL;
	}
	std::string dllName = IMG_Name(module);

	return dllName;
}

std::string InstructionWorker::getFunctionNameFromAddress(ADDRINT addr)
{
	IMG module = IMG_FindByAddress(addr);
	if (!IMG_Valid(module))
	{
		return NULL;
	}

	RTN routine = RTN_FindByAddress(addr);


	std::string routineName = RTN_FindNameByAddress(addr);

	return routineName;
}


std::wstring InstructionWorker::printFunctionArgument(void* arg)
{
	std::wstringstream result;
	if (arg == NULL)
	{
		return L"0";
	}

	if (!PIN_CheckReadAccess(arg))
	{
		//Unreadable, probably just a numerical argument
		result << std::hex << arg;
	}
	else
	{
		//Value accessible, try to read it
		//Possible string types:
		// Unicode string: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/shared/ntdef/unicode_string.htm
		// char*
		// wchar_t*

		result << "[" << std::hex <<  arg << "] --> ";

		//Try for unicode string
		typedef struct UNICODE_STRING
		{
			UINT16 len;
			UINT16 maxLen;
			wchar_t buf;
		} UNICODE_STRING;

		//Check unicode string
		UNICODE_STRING ustr = *(UNICODE_STRING*)arg;
		if (PIN_CheckReadAccess((void*)ustr.buf))
		{
			size_t stringLenUTF8 = getBufferStringLengthUTF8((void*)ustr.buf);
			size_t stringLenUTF16 = getBufferStringLengthUTF16((void*)ustr.buf);
			if (stringLenUTF8 == 1 && stringLenUTF8 < stringLenUTF16)
			{
				result << "Len: 0x" << stringLenUTF16;
				result << " | Value: " << (wchar_t*)arg;
			}
		}
			
		//Char* or wchar_t*
		UINT64 stringLenUTF8 = getBufferStringLengthUTF8(arg);
		UINT64 stringLenUTF16 = getBufferStringLengthUTF16(arg);
		if (stringLenUTF8 == 1 && stringLenUTF8 < stringLenUTF16)
		{
			result << "Len: 0x" << stringLenUTF16;
			result << " | Value: " << (wchar_t*)arg;
		}
		else if (stringLenUTF8 > 0)
		{
			result << "Len: 0x" << stringLenUTF8;
			result << " | Value: " << (char*)arg;
		}
		else
		{
			result << "<not string>";
		}
	}
	return result.str();
}


UINT64 getBufferStringLengthUTF8(void* buf)
{
	const UINT64 BUFFER_LIMIT_LEN = 100;
	UINT64 ii = 0;

	//std::cerr << "" << std::endl;

	while (ii < BUFFER_LIMIT_LEN)
	{
		BOOL accessible = PIN_CheckReadAccess((char*)buf + ii);
		if (!accessible)
		{
			//Chars might have been found, but not an ending '\0'
			return 0;
		}
		char c = *((char*)buf + ii);
		if (c == 0)
		{
			break;
		}
		if (c != 0x0A && c != 0x0D && (c < 0x20 || c>=0x7f))
		{
			//std::cerr << "Rejected " << std::dec << c << "=0x" << std::hex << c << std::endl;
			//return ii;
		}
		ii++;
	}

	return ii;
}

UINT64 getBufferStringLengthUTF16(void* buf)
{
	const UINT64 BUFFER_LIMIT_LEN = 100;
	UINT64 ii = 0;

	while (ii < BUFFER_LIMIT_LEN)
	{
		BOOL accessible = PIN_CheckReadAccess((wchar_t*)buf + ii);
		if (!accessible)
		{
			//Chars might have been found, but not an ending '\0'
			return 0;
		}
		wchar_t c = *((wchar_t*)buf + ii);
		if (c == 0)
		{
			break;
		}
		if (c != 0x0A && c != 0x0D && (c < 0x20 || c >= 0x7f))
		{
			//std::cerr << "Rejected " << std::dec << c << "=0x" << std::hex << c << std::endl;
			//return ii;
		}
		ii++;
	}

	return ii;
}


std::string InstructionWorker::getMemoryValueHexString(ADDRINT memAddr, int len)
{
	char data[8] = {0};
	PIN_SafeCopy(data, (VOID*)(memAddr), len);
	std::stringstream ss;
	ss << std::hex << std::setfill('0');
	for (int ii = 0; ii < len; ii++) 
	{
		ss << std::setw(2) << static_cast<unsigned>((UINT8)(data[ii]));
	}
	
	return ss.str();
}

std::vector<char> InstructionWorker::getMemoryValue(ADDRINT memAddr, int len)
{
	char data[8] = { 0 };
	PIN_SafeCopy(data, (VOID*)(memAddr), len);
	std::vector<char> vec;
	for (int ii = 0; ii < len; ii++)
	{
		vec.push_back(data[ii]);
	}

	return vec;
}

ADDRINT InstructionWorker::getRegisterValue(LEVEL_VM::CONTEXT *lctx, LEVEL_BASE::REG reg, UINT8 *valBuffer)
{
	PIN_GetContextRegval(lctx, reg, valBuffer);
	
	//Now we reverse the order, since we want the MSB to be at the "left" of the vector, that is, at index 0
	const UINT32 regSize = REG_Size(reg);
	for (int ii = 0; ii < regSize/2; ii++)
	{
		UINT8 aux = valBuffer[ii];
		valBuffer[ii] = valBuffer[regSize - ii - 1];
		valBuffer[regSize - ii - 1] = aux;
	}
	
	//for (int ii = 0; ii < 8; ii++) LOG_DEBUG("OUT ValBuffer[" << ii << "]: " << valBuffer[ii]);
	return 0;
}

