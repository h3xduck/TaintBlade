#include "TagLog.h"

void TagLog::logTag(Tag tag)
{
	auto it = this->tagLogMap.find(tag.color);
	if (it == this->tagLogMap.end())
	{
		//Color not in taglog yet, insert
		this->tagLogMap.insert(std::make_pair<UINT16, Tag>(tag.color, tag));

		//For inserting color mixes in the reversetaglog, we always put the smaller one as the key
		UINT16 keyColor = tag.derivate1<=tag.derivate2 ? tag.derivate1 : tag.derivate2;
		UINT16 pairColor = tag.derivate1 <= tag.derivate2 ? tag.derivate2 : tag.derivate1;
		//Check if this color is already part of a mix
		auto it2 = this->reverseTagLogMap.find(keyColor);
		if (it2 == this->reverseTagLogMap.end())
		{
			//Not part of any mix. Insert a new vector.
			std::vector<std::pair<UINT16, UINT16>> vec;
			vec.push_back(std::make_pair<UINT16, UINT16>(pairColor, tag.color));
			this->reverseTagLogMap.insert(std::make_pair<UINT16, std::vector<std::pair<UINT16, UINT16>>>(keyColor, vec));
		}
		else
		{
			//Already used in some mix. Insert new element in vector
			it2->second.push_back(std::make_pair<UINT16, UINT16>(pairColor, tag.color));
		}

		
	}
	else
	{
		//Color already in taglog, so a mix exists already
		LOG_ERR("Registered a Tag with repeated color in the taglog")
	}
}

void TagLog::dumpTagLog()
{
	LOG_INFO("NORMAL ORDERED TAG LOG: COLOR, DERIVATE1, DERIVATE2")
	for (auto& it : this->tagLogMap) {
		LOG_INFO("COL:"<< it.first << " D1:" << it.second.derivate1<<" D2:"<<it.second.derivate2);
	}
	LOG_INFO("INVERSE ORDERED TAG LOG: DERIVATE1, DERIVATE2, COLOR");
	for (auto& it : this->reverseTagLogMap) {
		LOG_INFO("D1:" << it.first<<":");
		for (auto& element : it.second)
		{
			LOG_INFO("\tD2:" << element.first << " COL:" << element.second);
		}
	}
}

void TagLog::dumpTagLogPrettified(UINT16 startColor)
{
	this->printBT(startColor);
}

void TagLog::printBT(const std::string& prefix, const UINT16 color, bool isLeft)
{
	if (color != EMPTY_COLOR)
	{
		std::cout << prefix;
		
		std::cout << "|__";

		// print the value of the node
		std::cout << color << std::endl;

		auto it = this->tagLogMap.find(color);
		UINT16 leftColor = 0;
		UINT16 rightColor = 0;
		if (it != this->tagLogMap.end())
		{
			leftColor = it->second.derivate1;
			rightColor = it->second.derivate2;
		}

		// enter the next tree level - left and right branch
		printBT(prefix + (isLeft ? "|   " : "    "), leftColor, true);
		printBT(prefix + (isLeft ? "|   " : "    "), rightColor, false);
	}
}

void TagLog::printBT(const UINT16 color)
{
	printBT("", color, false);
}

UINT16 TagLog::getMixColor(UINT16 d1, UINT16 d2)
{
	//We first need to get the smallest, since that is the one used as key
	UINT16 keyColor = d1 <= d2 ? d1 : d2;
	UINT16 pairColor = d1 <= d2 ? d2 : d1;

	//Look for the keyColor
	auto it = this->reverseTagLogMap.find(keyColor);
	if (it == this->reverseTagLogMap.end())
	{
		//Not found, no mix using this color
		return EMPTY_COLOR;
	}	
	else
	{
		//Color already used in some mix, but we need to get the one with pairColor
		for (auto& element : it->second) {
			if (element.first == pairColor)
			{
				//Found the mix, return resulting color
				return element.second;
			}
		}
		//Mix with that color was not found
		return EMPTY_COLOR;
	}
}

void TagLog::logTagOriginal(UINT16 color, std::string dllName, std::string funcName, ADDRINT memAddress, UINT8 byteValue)
{
	LOG_DEBUG("Logged original color [" << color << "] for DLL " << dllName << " and FUNC " << funcName << ", MEM:" << memAddress << ", BYTEVALUE:" << byteValue);
	original_color_data_t data = { dllName, funcName, memAddress, byteValue };
	this->originalColorsMap.insert(std::make_pair<UINT16, original_color_data_t>(color, data));
}

void TagLog::logColorTaintReason(UINT16 color, TagLog::color_taint_reason_t reason)
{
	LOG_DEBUG("Logged color taint reason for color [" << color << "], of reason class: " << reason.reasonClass);
	this->colorReasonMap.insert(std::make_pair<UINT16, color_taint_reason_t>(color, reason));
}

void TagLog::dumpTagLogOriginalColors()
{
	std::stringstream logLine;
	logLine << "ORIGINAL COLORS TAG LOG: COLOR, DLL, FUNCTION" << std::endl;
	for (auto& it : this->originalColorsMap) {
		logLine<<"|-> COLOR:" << it.first << ":: DLL:" << it.second.dllName << " FUNC:" << it.second.funcName << " MEM: " << it.second.memAddress << " BYTEVALUE: " << it.second.byteValue << std::endl;
	}
	LOG_INFO(logLine.str());
}

std::vector<std::pair<UINT16, TagLog::original_color_data_t>> TagLog::getOriginalColorsVector()
{
	std::vector<std::pair<UINT16, TagLog::original_color_data_t>> colorVec;
	for (auto& it : this->originalColorsMap) {
		colorVec.push_back(it);
	}
	return colorVec;
}

std::vector<std::pair<UINT16, TagLog::color_taint_reason_t>> TagLog::getColorsReasonsVector()
{
	std::vector<std::pair<UINT16, TagLog::color_taint_reason_t>> reasonVec;
	for (auto& it : this->colorReasonMap) {
		reasonVec.push_back(it);
	}
	return reasonVec;
}

TagLog::color_taint_reason_t TagLog::getColorTaintReason(UINT16 color)
{
	auto it = this->colorReasonMap.find(color);
	if (it == this->colorReasonMap.end())
	{
		//The color does not have a taint reason attached
		color_taint_reason_t taintReason;
		taintReason.reasonClass = TagLog::taint_reason_class::NONE;
		return taintReason;
	}
	//Found some reason for that color
	return it->second;
}

std::vector<Tag> TagLog::getColorTransVector()
{
	std::vector<Tag> vec;
	for (auto& it : this->tagLogMap)
	{
		Tag tag(it.first, it.second.derivate1, it.second.derivate2);
		vec.push_back(tag);
	}

	return vec;
}


std::vector<UINT16>* _getColorParents(TagLog *tagLog, UINT16 color, std::vector<UINT16> *vec)
{
	auto it = tagLog->getTagLogMap().find(color);
	if (it == tagLog->getTagLogMap().end())
	{
		vec->push_back(color);
	}
	else
	{
		vec->push_back(color);
		_getColorParents(tagLog, it->second.derivate1, vec);
		_getColorParents(tagLog, it->second.derivate2, vec);
		
		//Ensure colors are not repeated
		std::sort(vec->begin(), vec->end());
		vec->erase(std::unique(vec->begin(), vec->end()), vec->end());
	}

	return vec;
}

std::vector<UINT16> TagLog::getColorParentsRecursive(UINT16 color)
{
	std::vector<UINT16> vec;
	_getColorParents(this, color, &vec);
	

	return vec;
}