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