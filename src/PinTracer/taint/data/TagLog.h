#ifndef _TAGLOG_H_
#define _TAGLOG_H_

#include "Tag.h"
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"


class TagLog
{
private:
	std::tr1::unordered_map<ADDRINT, Tag> tagLogVector;
public:
	void logTag(Tag tag);
	void dumpTagLog();
};


#endif