#include "TagLog.h"

void TagLog::logTag(Tag tag)
{
	this->tagLogVector.insert(std::make_pair<ADDRINT, Tag>(tag.color, tag));
}

void TagLog::dumpTagLog()
{
	for (auto& it : this->tagLogVector) {
		LOG_ALERT("COL:"<< it.first << " D1:" << it.second.derivate1<<" D2:"<<it.second.derivate2);
	}
}