#ifndef _FORMAT_H_
#define _FORMAT_H_

#include "../../config/GlobalConfig.h"

#if(DEBUG_IN_HEX==1)
	#define to_hex(mem) std::hex << mem << std::dec
#else 
	#define to_hex(mem) mem
#endif



#define fixed_precision(file)	
	

#endif
