#ifndef _TAINT_MANAGER_H_
#define _TAINT_MANAGER_H_

#include "../data/TagMap.h"
#include "TaintSource.h"
#include <iostream>
#include <cstdio>

class TaintManager
{
private:
	TagMap tagMap;
	std::tr1::unordered_map <std::string, std::vector<TaintSource>> taintFunctionMap;


public:

	void registerTaintSource(const std::string& dllName, const std::string& funcName);
	void unregisterTaintSource(const std::string& dllName, const std::string& funcName);

	void taintMemoryNewColor(const ADDRINT memAddr, const UINT32 bytes);
	void taintMemWithMem(const ADDRINT destMem, const UINT32 destBytes, const ADDRINT srcMem, const UINT32 srcBytes);
	void taintMemWithReg(const ADDRINT destMem, const UINT32 destBytes, const LEVEL_BASE::REG srcReg);

	void taintRegNewColor(const LEVEL_BASE::REG reg);
	void taintRegWithReg(const LEVEL_BASE::REG destReg, LEVEL_BASE::REG srcReg);
};


#endif