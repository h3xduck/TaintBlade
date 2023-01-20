#ifndef _T_REGISTERS_H_
#define _T_REGISTERS_H_

#include "../../utils/io/log.h"
#include "pin.H"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"


#define INVALID_REGISTER_POSITION 999

class TReg {
public:
	//Stores relation between LEVEL_BASE::REG's enum and the indexes in our register tainting structure
	//Yes, cannot initialize it here
	std::tr1::unordered_map<INT, UINT32> regIndexMapping;

	//Stores
	
	TReg();
	UINT32 getPos(INT reg);
	UINT32 getTaintLength(LEVEL_BASE::REG reg);
	BOOL isSupported(REG reg);
};







#endif