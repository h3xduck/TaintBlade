#ifndef _TAINT_IO_H_
#define _TAINT_IO_H_

#include <iostream>
#include <cstdio>
#include "../../config/GlobalConfig.h"


#define LOG_INT(msg, ...) \
    { \
    char buffer[256] = { 0 };\
    sprintf_s(buffer, sizeof(buffer), "%s \n\t\tAT %s(%d)", msg, __FILE__, __LINE__);\
    std::cerr << buffer <<std::endl;\
    };


#define LOG_ERR(msg, ...) {std::string _l = "[ERROR] "; _l += msg; LOG_INT(_l.c_str())}

#define LOG_INFO(msg, ...) {std::string _l = "[INFO] "; _l += msg; LOG_INT(_l.c_str())}

#if(DEBUG_LEVEL==1)
	#define LOG_DEBUG(msg) {std::string _l = "[DEBUG] "; _l += msg; LOG_INT(_l.c_str())}
#else
	#define LOG_DEBUG(msg, ...) 
#endif



#endif