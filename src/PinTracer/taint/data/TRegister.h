#ifndef _T_REGISTERS_H_
#define _T_REGISTERS_H_

#include "pin.H"
#include "../../utils/io/log.h"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"

class TReg {
public:
	//Stores relation between LEVEL_BASE::REG's enum and the indexes in our register tainting structure
	//Yes, cannot initialize it here
	std::tr1::unordered_map<INT, UINT32> regIndexMapping;

	//Stores
	
	TReg();
	UINT32 getPos(INT reg);
	UINT32 getTaintLength(INT reg);
};







#endif