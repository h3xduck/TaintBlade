#ifndef _FORMAT_H_
#define _FORMAT_H_

#include "../../config/GlobalConfig.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <unistd.h>

extern std::string pintracerSuffix;

#if(DEBUG_IN_HEX==1)
	#define to_hex_dbg(mem) std::hex << mem << std::dec
#else 
	#define to_hex_dbg(mem) mem
#endif

#define to_hex(mem) std::hex << mem << std::dec
#define char_to_hex(c) std::hex << (int)c << std::dec

std::string wcharstrToCharstr(std::wstring wstr);
	


#define fixed_precision(file)

/**
Returns the filename with the PID appended and the corresponding subpath
*/
std::string getFilenameFullName(std::string filename);
	

#endif
