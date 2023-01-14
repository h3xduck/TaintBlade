#ifndef _TAINT_IO_H_
#define _TAINT_IO_H_

#include <iostream>
#include <cstdio>
#include "../../config/GlobalConfig.h"


#define LOG_INT(msg, ...) \
    std::cerr << msg << "\n\t\tAT " << __FILE__ << "(:" << __LINE__ << ")" << std::endl;

#define LOG_INT_SHORT(msg) \
    std::cerr << msg << std::endl;

#define LOG_ERR(msg, ...) LOG_INT("[ERROR] " << msg)
#define LOG_ALERT(msg, ...) LOG_INT("[ALERT] " << msg)


#if(DEBUG_LEVEL==1)
	#define LOG_DEBUG(msg) \
    LOG_INT_SHORT("[DEBUG] " << msg)

    #define LOG_INFO(msg, ...) LOG_INT_SHORT("[INFO] " << msg)
#elif(DEBUG_LEVEL==2)
#define LOG_DEBUG(msg) \
    LOG_INT("[DEBUG] " << msg) 

#define LOG_INFO(msg, ...) LOG_INT("[INFO] " << msg)

#else
#define LOG_DEBUG(msg, ...)
#define LOG_INFO(msg, ...) LOG_INT_SHORT("[INFO] " << msg)
#endif



#endif