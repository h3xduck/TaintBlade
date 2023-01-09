#ifndef _TAINT_MANAGER_H_
#define _TAINT_MANAGER_H_

#include "TagMap.h"
#include "Tag.h"
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

};


#endif