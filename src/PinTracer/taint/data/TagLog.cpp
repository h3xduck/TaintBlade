#include "TagLog.h"

void TagLog::logTag(Tag tag)
{
	auto it = this->tagLogVector.find(tag.color);
	if (it == this->tagLogVector.end())
	{
		//Color not in taglog yet, insert
		this->tagLogVector.insert(std::make_pair<ADDRINT, Tag>(tag.color, tag));
	}
	else
	{
		//Color already in taglog
		LOG_ERR("Registered a Tag with repeated color in the taglog")
	}
}

void TagLog::dumpTagLog()
{
	for (auto& it : this->tagLogVector) {
		LOG_INFO("COL:"<< it.first << " D1:" << it.second.derivate1<<" D2:"<<it.second.derivate2);
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

		auto it = this->tagLogVector.find(color);
		UINT16 leftColor = 0;
		UINT16 rightColor = 0;
		if (it != this->tagLogVector.end())
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