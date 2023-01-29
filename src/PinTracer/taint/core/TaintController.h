#ifndef _TAINT_CONTROLLER_H_
#define _TAINT_CONTROLLER_H_

#include "../data/TagMap.h"
#include <iostream>
#include <cstdio>
#include <algorithm>
#include <cctype>
#include <string>
#include "../../utils/io/format.h"

class TaintController
{
private:
	TagMap tagMap;
public:
	TaintController();

	std::vector<UINT16> taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes);
	void taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes);
	void taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg);
	void untaintMem(const ADDRINT destMem, const UINT32 destBytes);

	void taintRegNewColor(const LEVEL_BASE::REG reg);
	void taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg, BOOL srcExtension = false);
	void taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes);
	void untaintReg(const LEVEL_BASE::REG reg);

	void registerOriginalColor(UINT16 color, std::string dllName, std::string funcName);

	void printTaint();
	void dumpTaintLog();
	void dumpTaintLogPrettified(UINT16 color);
	void dumpTagLogOriginalColors();
	std::vector<std::pair<ADDRINT, UINT16>> getTaintedMemoryVector();
	std::vector<UINT16> getOriginalColorsVector();
};


#endif
