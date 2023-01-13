#ifndef _TAINT_CONTROLLER_H_
#define _TAINT_CONTROLLER_H_

#include "../data/TagMap.h"
#include <iostream>
#include <cstdio>

class TaintController
{
private:
	TagMap tagMap;
public:
	TaintController();

	void taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes);
	void taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes);
	void taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg);

	void taintRegNewColor(const LEVEL_BASE::REG reg);
	void taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg);
	void taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes);

	void printTaint();
};


#endif
