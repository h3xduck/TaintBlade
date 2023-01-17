#ifndef _TAGLOG_H_
#define _TAGLOG_H_

#include "Tag.h"
#include <fstream>
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"


class TagLog
{
private:
	//Color, colors mixed to make it
	std::tr1::unordered_map<UINT16, Tag> tagLogMap;
	//Color used to mix, vector of colors with which it was combined (first) and the result (second element in vector)
	std::tr1::unordered_map<UINT16, std::vector<std::pair<UINT16, UINT16>>> reverseTagLogMap;
	void printBT(const std::string& prefix, const UINT16 color, bool isLeft);
	void printBT(const UINT16 color);
public:
	void logTag(Tag tag);
	void dumpTagLog();
	void dumpTagLogPrettified(UINT16 startColor);

	/**
	Checks if colors have already been mixed. If so, returns resulting color. Otherwise, empty color.
	*/
	UINT16 getMixColor(UINT16 d1, UINT16 d2);
};


#endif