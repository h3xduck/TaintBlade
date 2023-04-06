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

	//To be used only by the taintSource, this marks the taint event as TAINTGEN (not a natural taint at the program)
	std::vector<UINT16> taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes);
	void taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes);
	void taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg, BOOL colorOverwrite = false);
	void untaintMem(const ADDRINT destMem, const UINT32 destBytes);

	void taintRegNewColor(const LEVEL_BASE::REG reg);
	void taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg, BOOL srcExtension = false);
	void taintRegWithMem(const LEVEL_BASE::REG destReg, const LEVEL_BASE::REG src1Reg, const ADDRINT src2Mem, const UINT32 src2Bytes);
	void untaintReg(const LEVEL_BASE::REG reg);

	void registerOriginalColor(UINT16 color, std::string dllName, std::string funcName);
	
	/**
	Returns a vector will all parents of a color (recursively, not limited to 1 generation)
	*/
	std::vector<UINT16> getColorParents(UINT16 color);

	void printTaint();
	void dumpTaintLog();
	void dumpTaintLogPrettified(UINT16 color);
	void dumpTagLogOriginalColors();
	std::vector<std::pair<ADDRINT, UINT16>> getTaintedMemoryVector();
	std::vector<std::pair<UINT16, std::pair<std::string, std::string>>> getOriginalColorsVector();
	std::vector<Tag> getColorTransVector();

	bool regIsTainted(REG reg);
	bool memIsTainted(ADDRINT mem);
	bool memRangeIsTainted(ADDRINT mem, int bytes);

	std::vector<UINT16> regGetColor(REG reg);
	UINT16 memGetColor(ADDRINT mem);
	std::vector<UINT16> memRangeGetColor(ADDRINT mem, int bytes);
};


#endif
