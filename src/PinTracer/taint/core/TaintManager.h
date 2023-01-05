#ifndef _TAINT_MANAGER_H_
#define _TAINT_MANAGER_H_

#include "TagMap.h"
#include "Tag.h"
#include "TaintSource.h"

class TaintManager
{
private:
	TagMap tagMap;
	std::tr1::unordered_map <std::string, std::vector<TaintSource>> taintFunctionMap;


public:

	void registerTaintSource(const std::string& dll_name, const std::string& func_name);
	void unregisterTaintSource(const std::string& dll_name, const std::string& func_name);

};


#endif