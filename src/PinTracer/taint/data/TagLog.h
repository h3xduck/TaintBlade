#ifndef _TAGLOG_H_
#define _TAGLOG_H_

#include "Tag.h"
#include <fstream>
#include "../../../external/pin-3.25-98650-g8f6168173-msvc-windows/pin-3.25-98650-g8f6168173-msvc-windows/extras/stlport/include/unordered_map"


class TagLog
{
public:
	typedef struct original_color_data_t
	{
		std::string dllName; //DLL specifying the TaintSource at which the color was generated
		std::string funcName; //function name specifying the TaintSource at which the color was generated
		ADDRINT memAddress; //Memory address at which the color was generated
		UINT8 byteValue; //Original value of the byte at which the color was generated
	};

	enum taint_reason_class
	{
		NONE,
		TAINT_REASON_SINK //Was sent to CreateProccess or similar
	};
	typedef struct color_taint_reason_t
	{
		taint_reason_class reasonClass;
		struct taint_reason_sink_data_t {
			std::string dllName;
			std::string funcName;
			int argNumber; //Argument in which the tainted data is found
			ADDRINT offsetFromArgStart; //Offset (from start of argument) where tainted color is found
		} sinkData;
	};
private:
	//Color, colors mixed to make it
	std::tr1::unordered_map<UINT16, Tag> tagLogMap;
	//Color used to mix, vector of colors with which it was combined (first) and the result (second element in vector)
	std::tr1::unordered_map<UINT16, std::vector<std::pair<UINT16, UINT16>>> reverseTagLogMap;
	//Stores original colors, not created by mixing two others
	std::tr1::unordered_map<UINT16, original_color_data_t> originalColorsMap;
	/*
	Stores colors, and a list of 'reasons' why they are not just a normal taint(e.g.: they were sent into a taint sink)
	If a color does not appear here, it did not take part in any special operation
	*/
	std::tr1::unordered_map<UINT16, color_taint_reason_t> colorReasonMap;

	void printBT(const std::string& prefix, const UINT16 color, bool isLeft);
	void printBT(const UINT16 color);
public:
	void logTag(Tag tag);
	void dumpTagLog();
	void dumpTagLogPrettified(UINT16 startColor);

	/**
	Stores in the list of original colors a color along with other data
	*/
	void logTagOriginal(UINT16 color, std::string dllName, std::string funcName, ADDRINT memAddress, UINT8 byteValue);

	/**
	Stores in the map of taint color reasons a value
	*/
	void logColorTaintReason(UINT16 color, TagLog::color_taint_reason_t reason);

	void dumpTagLogOriginalColors();

	std::tr1::unordered_map<UINT16, Tag> getTagLogMap()
	{
		return this->tagLogMap;
	}

	std::tr1::unordered_map<UINT16, std::vector<std::pair<UINT16, UINT16>>> getReverseTagLogMap()
	{
		return this->reverseTagLogMap;
	}

	/**
	Checks if colors have already been mixed. If so, returns resulting color. Otherwise, empty color.
	*/
	UINT16 getMixColor(UINT16 d1, UINT16 d2);

	/**
	Get vector of original colors
	*/
	std::vector<std::pair<UINT16, original_color_data_t>> getOriginalColorsVector();

	/**
	Get vector of color taint reasons
	*/
	std::vector<std::pair<UINT16, color_taint_reason_t>> getColorsReasonsVector();

	/**
	Get the reason why a color was tainted, returns NONE reason if none
	*/
	color_taint_reason_t getColorTaintReason(UINT16 color);

	/**
	Get vector of color transformations
	*/
	std::vector<Tag> getColorTransVector();

	/**
	Get list of colors from which a color has been derived. Recursive, returns full list.
	*/
	std::vector<UINT16> getColorParentsRecursive(UINT16 color);
};


#endif