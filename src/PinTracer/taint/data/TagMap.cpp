#include "TagMap.h"
#include "../../common/Context.h"

extern Context ctx;

void reportUnsupportedRegister(REG reg)
{
#if(REPORT_UNSUPPORTED_REG==1)
	LOG_DEBUG("Ignored instruction: invalid register position of reg " << reg);
#endif
}


TagMap::TagMap()
{
	this->tReg = TReg();
	this->tagLog = TagLog();
	for (int ii = 0; ii < REG_TAINT_FIELD_LEN; ii++)
	{
		this->regTaintField[ii] = Tag(0);
	}
	
	//this->memTaintField.insert({ 0, memInfo });
	//this->regTaintField = { 0 };
	LOG_INFO("TagMap initialized");
}

size_t TagMap::tagMapCount()
{
	size_t count = this->memTaintField.size();
	return count;
}

UINT16 TagMap::taintMemNew(ADDRINT addr)
{
	auto it = this->memTaintField.find(addr);
	Tag tag = Tag();
	if (it == this->memTaintField.end())
	{
		//Byte not in map yet
		this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, tag));
		LOG_MESSAGE_TAINT_MEM("New mem taint", "ins", addr, tag.color);
		
		//Register event for dump files
		struct DataDumper::memory_color_event_line_t event;
		event.color = tag.color;
		event.memAddr = addr;
		event.eventType = DataDumper::TAINT;
		dataDumper.writeMemoryColorEventDump(event);
	}
	else
	{
		it->second.color = tag.color;
		it->second.derivate1 = EMPTY_COLOR;
		it->second.derivate2 = EMPTY_COLOR;
		LOG_MESSAGE_TAINT_MEM("New color for existing memory taint", "modified", addr, it->second.color);
		
		//Register event for dump files
		struct DataDumper::memory_color_event_line_t event;
		event.color = tag.color;
		event.memAddr = addr;
		event.eventType = DataDumper::CHANGE;
		dataDumper.writeMemoryColorEventDump(event);
	}

	return tag.color;
}

void TagMap::taintMem(ADDRINT addr, UINT16 color, BOOL manualTaint) 
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		if (color != EMPTY_COLOR)
		{
			//LOG_DEBUG("New memory taint--> ADDR:" << addr << " COL:" << color);
			//Byte not in map yet
			Tag tag(color);
			this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(addr, tag));
			//this->printMemTaintComplete();
			LOG_MESSAGE_TAINT_MEM("New mem taint", "ins", addr, tag.color);
			
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.memAddr = addr;
			event.eventType = manualTaint==true ? DataDumper::TAINTGEN : DataDumper::TAINT;
			dataDumper.writeMemoryColorEventDump(event);
		}
		//No empty color tainting
	}
	else
	{
		//LOG_DEBUG("Memory taint--> ADDR:" << addr << " COL:" << color);
		it->second.color = color;
		LOG_MESSAGE_TAINT_MEM("New color for existing memory taint", "ins", addr, it->second.color);
		
		//Register event for dump files
		struct DataDumper::memory_color_event_line_t event;
		event.color = color;
		event.memAddr = addr;
		event.eventType = manualTaint == true ? DataDumper::CHANGEGEN : DataDumper::CHANGE;
		dataDumper.writeMemoryColorEventDump(event);

	}
}

void TagMap::untaintMem(ADDRINT addr)
{
	//Debug, print only if tainted
	auto it = this->memTaintField.find(addr);
	if (it != this->memTaintField.end())
	{
		LOG_MESSAGE_TAINT_MEM("Untainted mem", "erase", addr, 0);
		
		//Register event for dump files
		struct DataDumper::memory_color_event_line_t event;
		event.memAddr = addr;
		event.eventType = DataDumper::UNTAINT;
		dataDumper.writeMemoryColorEventDump(event);
	}
	this->memTaintField.erase(addr);
}

UINT16 TagMap::getTaintColorMem(ADDRINT addr)
{
	auto it = this->memTaintField.find(addr);
	if (it == this->memTaintField.end())
	{
		return EMPTY_COLOR;
	}
	else
	{
		return it->second.color;
	}
}

Tag TagMap::mixTaintMem(ADDRINT dest, ADDRINT src1, ADDRINT src2)
{
	Tag src1MemTag = getTaintColorMem(src1);
	Tag src2MemTag = getTaintColorMem(src2);

	auto it = this->memTaintField.find(dest);
	Tag tag;
	if (it == this->memTaintField.end())
	{
		//Byte of dest not in map yet, no mix since src1=empty_color
		if (src2MemTag.color != EMPTY_COLOR)
		{
			//Dest=src1 is tainted with color of src2
			tag = Tag(src2MemTag.color);
			this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest, tag));
			LOG_MESSAGE_MIX_MEM("New mem taint", "ins", dest, src2, tag.color,  0, src2MemTag.color);
			//LOG_DEBUG("New memory taint mixTaintMem(" << to_hex_dbg(dest) << ", " << to_hex_dbg(src1) << ", "<< to_hex_dbg(src2) <<") --> mem.ins(" << dest << ", T(" << tag.color << ", "<<tag.derivate1<<", "<<tag.derivate2<<"))");
		
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.memAddr = dest;
			event.eventType = DataDumper::TAINT;
			dataDumper.writeMemoryColorEventDump(event);
		}
		//else, nothing, since src2=empty_color and dest=src1 was not tainted
	}
	else
	{
		//Dest=src1 != empty_color
		if (src2MemTag.color != EMPTY_COLOR)
		{
			//Check if mix between these two colors already exists
			UINT16 mixColor = this->tagLog.getMixColor(src1MemTag.color, src2MemTag.color);
			if (mixColor == EMPTY_COLOR)
			{
				//We need to mix both colors, log the generated tag
				tag = Tag(src1MemTag.color, src2MemTag.color);
				it->second = tag;
				this->tagLog.logTag(tag);
				LOG_MESSAGE_MIX_MEM("Mixed mem taint", "modified", dest, src2, tag.color, src1MemTag.color, src2MemTag.color);
				//LOG_DEBUG("Mixed memory taint mixTaintMem(" << to_hex_dbg(dest) << ", " << to_hex_dbg(src1) << ", " << to_hex_dbg(src2) << ") --> modified T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << "))");
			
				//Register event for dump files
				struct DataDumper::memory_color_event_line_t event;
				event.color = tag.color;
				event.memAddr = dest;
				event.eventType = DataDumper::MIX;
				dataDumper.writeMemoryColorEventDump(event);
			}
			else
			{
				//Mix already generated before, use that color again
				tag = Tag(mixColor);
				it->second = tag;
				LOG_MESSAGE_MIX_MEM("Reused mix mem taint", "reused", dest, src2, tag.color, src1MemTag.color, src2MemTag.color);
				//LOG_DEBUG("Reused mix taint mixTaintMem(" << to_hex_dbg(dest) << ", " << to_hex_dbg(src1) << ", " << to_hex_dbg(src2) << ") --> reused T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << "))");
			
				//Register event for dump files
				struct DataDumper::memory_color_event_line_t event;
				event.color = tag.color;
				event.memAddr = dest;
				event.eventType = DataDumper::MIX;
				dataDumper.writeMemoryColorEventDump(event);
			}
			
		}
		else
		{
			//src2 is an empty_color, thus we directly taint dest=src1 with empty_color
			it->second.color = EMPTY_COLOR;
			LOG_MESSAGE_MIX_MEM("Mixed mem taint", "modified", dest, src2, EMPTY_COLOR, src1MemTag.color, src2MemTag.color);
			//LOG_DEBUG("New color for existing memory taint mixTaintMem(" << to_hex_dbg(dest) << ", " << to_hex_dbg(src1) << ", " << to_hex_dbg(src2) << ") --> modified T(" << tag.color << ", X, X))");
		
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.memAddr = dest;
			event.eventType = DataDumper::UNTAINT;
			dataDumper.writeMemoryColorEventDump(event);
		}
	}

	return tag;
}


void TagMap::taintRegNew(LEVEL_BASE::REG reg)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);

	if (!this->tReg.isSupported(reg))
	{
		reportUnsupportedRegister(reg);
		return;
	}

	Tag tag = Tag::tagNext();
	UINT16 firstColor = tag.color;

	if (posStart == INVALID_REGISTER_POSITION)
	{
		LOG_DEBUG("Ignored instruction: invalid register position of reg " << REG_StringShort(reg));
		return;
	}

	//LOG_DEBUG("Tainting new register:: POS:" << posStart << " LEN:" << taintLength << " COL:" << tag.color << " LCOL:" << tag.lastColor);

	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		this->regTaintField[ii] = tag;
	}

	LOG_MESSAGE_TAINT_REG_RANGE("New reg taint", "modified", reg, posStart, posStart + taintLength, firstColor, tag.color);
	//LOG_DEBUG("New reg taint taintRegNew(" << reg << ") --> modified Tags of reg("<< REG_StringShort(reg)<<" R:"<<reg<<" PI : " <<posStart<<" PF : "<<posStart+taintLength << ") with new color from PI : " << firstColor << " to PF : " << tag.color);
}

void TagMap::taintReg(LEVEL_BASE::REG reg, UINT16 color)
{
	//Whatever the color stored before is, we still overwrite it
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);

	if (!this->tReg.isSupported(reg))
	{
		reportUnsupportedRegister(reg);
		return;
	}

	for (INT ii = posStart; ii < posStart+taintLength; ii++)
	{
		this->regTaintField[ii] = Tag(color);
	}
	LOG_MESSAGE_TAINT_REG_UNIQUE("New reg taint", "modified", reg, posStart, posStart + taintLength, color);
	//LOG_DEBUG("New reg taint taintReg(" << reg << ", "<<color<<") --> modified Tags of reg("<< REG_StringShort(reg) <<" R:" << reg << " PI:" << posStart << " PF:" << posStart + taintLength << ") with new color "<<color);
}

void TagMap::untaintReg(LEVEL_BASE::REG reg, int byteIndex)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);

	if (!this->tReg.isSupported(reg))
	{
		reportUnsupportedRegister(reg);
		return;
	}

	if (byteIndex >= taintLength)
	{
		LOG_ERR("Tried to untaint an invalid position of register "<< REG_StringShort(reg) <<" --> R:"<<reg<<" ByteIndex:"<<byteIndex);
	}

	UINT16 taintColor = this->regTaintField[posStart + byteIndex].color;
	if (taintColor != EMPTY_COLOR)
	{
		LOG_MESSAGE_TAINT_REG_UNIQUE_WITHINDEX("Untainted reg", "modified", reg, posStart, byteIndex, EMPTY_COLOR);
		//LOG_DEBUG("Untainted reg untaintReg(" << reg << ") --> modified Tag of reg("<< REG_StringShort(reg) <<" R:" << reg << " PosStart:" << posStart << "ByteIndex:" << byteIndex << ") with empty color");
		//0 is considered the 'untainted' color
		this->regTaintField[posStart + byteIndex] = Tag(0);
	}
}

std::vector<Tag> TagMap::getTaintColorReg(LEVEL_BASE::REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	std::vector<Tag> colorVector = std::vector<Tag>();

	for (UINT32 ii = posStart; ii < posStart+taintLength; ii++)
	{
		colorVector.push_back(this->regTaintField[ii]);
		//LOG_DEBUG("Color " << ii << ": " << this->regTaintField[ii].color);
	}

	return colorVector;
}

void TagMap::mixTaintReg(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2)
{
	//Mandatory that the registers are of the same size
	std::vector<Tag> src1RegColorVector = getTaintColorReg(src1);
	std::vector<Tag> src2RegColorVector = getTaintColorReg(src2);
	const UINT32 posStart = this->tReg.getPos(dest);
	const UINT32 taintLength = this->tReg.getTaintLength(dest);

	if (!this->tReg.isSupported(dest))
	{
		reportUnsupportedRegister(dest);
		return;
	}
	else if (!this->tReg.isSupported(src2))
	{
		reportUnsupportedRegister(src2);
		return;
	}

	if (src1RegColorVector.size() != src2RegColorVector.size() ||
		src1RegColorVector.size() != taintLength)
	{
		//TODO manage different length registers. Do it similary as with memory
		LOG_ERR("Tried to mix taint between registers of different lengths");
		return;
	}
	
	for (int ii = 0; ii < src1RegColorVector.size(); ii++)
	{
		UINT16 colorSrc1 = src1RegColorVector.at(ii).color;
		UINT16 colorSrc2 = src2RegColorVector.at(ii).color;
		if (colorSrc1 != EMPTY_COLOR)
		{
			//src1=dest is not empty_color
			if (colorSrc2 == EMPTY_COLOR)
			{
				//src2=empty_color, thus just keep the color of that taint byte
				LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Maintained taint reg", "maintain", dest, src2, posStart, ii, colorSrc1, colorSrc1, colorSrc2);
				//LOG_DEBUG("(in loop) Maintained taint of reg at mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ")--> maintained Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P : " << posStart + ii << ") because src has empty color");
				
				//Tag tag(0);
				//this->regTaintField[posStart + ii] = tag;
				//LOG_DEBUG("(in loop) Untainted reg mixTaintReg(" << dest << ", "<<src1<<", "<< src2<<") --> modified Tag of reg(R:" << dest << " P:"<< posStart + ii << ") with full empty color");
			}
			else
			{
				//src2 is not empty_color, then we need to mix the colors
				UINT16 mixColor = this->tagLog.getMixColor(colorSrc1, colorSrc2);
				if (mixColor == EMPTY_COLOR)
				{
					//No previous mixes
					Tag tag(colorSrc1, colorSrc2);
					this->regTaintField[posStart + ii] = tag;
					//LOG_DEBUG("NEW DEST/SRC1COL:" << tag.color);
					this->tagLog.logTag(tag);
					LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Mixed reg taint, new color gen,", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorSrc2);
					//LOG_DEBUG("(in loop) Mixed reg taint, new color generated, mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ")--> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P : " << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
				
					//Register event for dump files
					struct DataDumper::memory_color_event_line_t event;
					event.color = tag.color;
					event.eventType = DataDumper::MIX;
					dataDumper.writeMemoryColorEventDump(event);
				}
				else
				{
					//Mix already generated before, use that color again
					Tag tag = Tag(mixColor);
					this->regTaintField[posStart + ii] = tag;
					LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Reused reg mix taint,", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorSrc2);
					//LOG_DEBUG("(in loop) Reused mix taint in reg mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ")--> reused Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P : " << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
					
					//Register event for dump files
					struct DataDumper::memory_color_event_line_t event;
					event.color = tag.color;
					event.eventType = DataDumper::MIX;
					dataDumper.writeMemoryColorEventDump(event);
				}
			}
		}
		else
		{
			//dest=src1 was untainted, taint it now with whatever color is at src2
			//LOG_DEBUG("MIX R2R--> Dest was untainted, tainting with SRC2COL:"<<colorSrc2);
			if (colorSrc2 != EMPTY_COLOR)
			{
				Tag tag(colorSrc2);
				this->regTaintField[posStart + ii] = tag;
				LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Tainted reg for the first time", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorSrc2);
				//LOG_DEBUG("(in loop) Tainted reg for the first time mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
			}
			//else nothing, no changes in color
			
		}
		
	}

}

void TagMap::mixTaintRegWithExtension(LEVEL_BASE::REG dest, LEVEL_BASE::REG src1, LEVEL_BASE::REG src2)
{
	std::vector<Tag> src1RegColorVector = getTaintColorReg(src1);
	std::vector<Tag> src2RegColorVector = getTaintColorReg(src2);
	const UINT32 taintLength = this->tReg.getTaintLength(dest);

	if (!this->tReg.isSupported(dest))
	{
		reportUnsupportedRegister(dest);
		return;
	}
	else if (!this->tReg.isSupported(src2) || src2RegColorVector.empty())
	{
		reportUnsupportedRegister(src2);
		return;
	}

	if (! (src1RegColorVector.size() != src2RegColorVector.size() ||
		src1RegColorVector.size() != taintLength))
	{
		//Register src does not need to be sign extended
		this->mixTaintReg(dest, src1, src2);
		return;
	}

	//Sign extension must be performed
	const UINT32 posStart = this->tReg.getPos(dest);
	const UINT32 src2taintLength = this->tReg.getTaintLength(src2);
	const UINT16 colorExt = src2RegColorVector.at(src2taintLength - 1).color;

	for (int ii = 0; ii < src1RegColorVector.size(); ii++)
	{
		UINT16 colorSrc1 = src1RegColorVector.at(ii).color;
		if (colorSrc1 != EMPTY_COLOR)
		{
			//src1=dest is not empty_color
			if (colorExt == EMPTY_COLOR)
			{
				//src2=empty_color, thus just untaint that reg byte
				Tag tag(0);
				this->regTaintField[posStart + ii] = tag;
				LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Untainted full reg", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorExt);
				//LOG_DEBUG("(in loop) Untainted reg mixTaintRegWithExtension(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart + ii << ") with full empty color");
			}
			else
			{
				//src2 is not empty_color, then we need to mix the colors
				UINT16 mixColor = this->tagLog.getMixColor(colorSrc1, colorExt);
				if (mixColor == EMPTY_COLOR)
				{
					//No previous mixes
					Tag tag(colorSrc1, colorExt);
					this->regTaintField[posStart + ii] = tag;
					//LOG_DEBUG("NEW DEST/SRC1COL:" << tag.color);
					this->tagLog.logTag(tag);
					LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Mixed reg taint", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorExt);
					//LOG_DEBUG("(in loop) Mixed reg taint mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
				
					//Register event for dump files
					struct DataDumper::memory_color_event_line_t event;
					event.color = tag.color;
					event.eventType = DataDumper::MIX;
					dataDumper.writeMemoryColorEventDump(event);
				}
				else
				{
					//Mix already generated before, use that color again
					Tag tag = Tag(mixColor);
					this->regTaintField[posStart + ii] = tag;
					LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Reused mix in reg taint", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorExt);
					//LOG_DEBUG("(in loop) Reused mix in reg taint mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ") --> reused Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
				
					//Register event for dump files
					struct DataDumper::memory_color_event_line_t event;
					event.color = tag.color;
					event.eventType = DataDumper::MIX;
					dataDumper.writeMemoryColorEventDump(event);
				}
			}
		}
		else
		{
			//dest=src1 was untainted, taint it now with whatever color is at src2
			//LOG_DEBUG("MIX R2R--> Dest was untainted, tainting with SRC2COL:"<<colorSrc2);
			if (colorExt != EMPTY_COLOR)
			{
				Tag tag(colorExt);
				this->regTaintField[posStart + ii] = tag;
				LOG_MESSAGE_TAINT_REG_MULTI("(in loop) Tainted reg with new color", "modified", dest, src2, posStart, ii, tag.color, colorSrc1, colorExt);
				//LOG_DEBUG("(in loop) Tainted reg with new color mixTaintReg(" << REG_StringShort(dest) << ", " << REG_StringShort(src1) << ", " << REG_StringShort(src2) << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart + ii << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
			}
			//else nothing, no changes in color

		}

	}
}

void TagMap::mixTaintRegByte(LEVEL_BASE::REG dest, UINT32 byteIndex, UINT16 color1, UINT16 color2)
{

	UINT16 colorDest = getTaintColorReg(dest).at(byteIndex).color;
	if (colorDest != color1)
	{
		//Case not supported yet
		LOG_ERR("Tried to mix taint in a non-binary operation!");
		return;
	}

	UINT32 posStart = this->tReg.getPos(dest);

	if (!this->tReg.isSupported(dest))
	{
		reportUnsupportedRegister(dest);
		return;
	}

	posStart+=byteIndex;
	if (color1 == EMPTY_COLOR)
	{
		if (color2 == EMPTY_COLOR)
		{
			//Both are empty_color, then no taint to perform
			//LOG_DEBUG("IGNORED mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> modified Tag of reg(R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with colors "<<color1<<" and "<<color2);
			return;
		}
		else
		{
			//dest is empty_color, just taint it with color2
			Tag tag(color2);
			this->regTaintField[posStart] = tag;
			LOG_MESSAGE_TAINT_REG_MULTI_UNKNOWNSRC("Tainted reg with new color", "modified", dest, posStart, byteIndex, tag.color, color1, color2);
			//LOG_DEBUG("Tainted reg "<< REG_StringShort(dest) <<" with new color mixTaintRegByte(" << dest << ", " << byteIndex<< ", " << color1 << ", " << color2 << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
		}
	}
	else if (color2 == EMPTY_COLOR)
	{
		//dest is non-empty_color but color2 is, taint dest with empty_color
		this->regTaintField[posStart] = Tag(color2);
		LOG_MESSAGE_TAINT_REG_MULTI_UNKNOWNSRC("Tainted reg with empty color", "modified", dest, posStart, byteIndex, EMPTY_COLOR, color1, color2);
		//LOG_DEBUG("Tainted reg "<< REG_StringShort(dest) <<" with empty color mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with empty tag");
	}
	else
	{
		//Neither dest=color1 or color2 are empty_color. Time to mix
		UINT16 mixColor = this->tagLog.getMixColor(color1, color2);
		if (mixColor == EMPTY_COLOR)
		{
			//No previous mixes
			Tag tag(color1, color2);
			this->regTaintField[posStart] = tag;
			this->tagLog.logTag(tag);
			LOG_MESSAGE_TAINT_REG_MULTI_UNKNOWNSRC("Mixed taint reg", "modified", dest, posStart, byteIndex, tag.color, color1, color2);
			//LOG_DEBUG("Mixed taint reg "<< REG_StringShort(dest) <<" mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> modified Tag of reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
		
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.eventType = DataDumper::MIX;
			dataDumper.writeMemoryColorEventDump(event);
		}
		else
		{
			//Mix already generated before, use that color again
			Tag tag = Tag(mixColor);
			this->regTaintField[posStart] = tag;
			LOG_MESSAGE_TAINT_REG_MULTI_UNKNOWNSRC("Reused mix taint reg", "modified", dest, posStart, byteIndex, tag.color, color1, color2);
			//LOG_DEBUG("Reused mix taint reg "<< REG_StringShort(dest) <<" mixTaintRegByte(" << dest << ", " << byteIndex << ", " << color1 << ", " << color2 << ") --> reused Tag for reg("<< REG_StringShort(dest) <<" R:" << dest << " P:" << posStart << " B:" << byteIndex << ") with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
		
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.eventType = DataDumper::MIX;
			dataDumper.writeMemoryColorEventDump(event);
		}
	}
}

//WARNING: DEPRECATED
//TODO REMOVE
void TagMap::mixTaintRegColors(LEVEL_BASE::REG dest, UINT32 length, std::vector<UINT16> colorV1, std::vector<UINT16> colorV2)
{
	const UINT32 posStart = this->tReg.getPos(dest);
	const UINT32 taintLength = this->tReg.getTaintLength(dest);

	if (!this->tReg.isSupported(dest))
	{
		reportUnsupportedRegister(dest);
		return;
	}

	for (int ii = 0; ii < length; ii++)
	{
		UINT16 color1 = colorV1.at(ii);
		if (color1 == EMPTY_COLOR)
		{
			this->regTaintField[ii] = Tag(colorV2.at(ii));
		}
		else
		{
			this->regTaintField[ii] = Tag(color1, colorV2.at(ii));
		}
	}
}

void TagMap::mixTaintMemRegAllBytes(ADDRINT dest, UINT32 length, ADDRINT src1, LEVEL_BASE::REG src2)
{
	//Supported only if dest and src1 are the same memory address
	if (dest != src1)
	{
		LOG_ERR("Dest and src1 were not the same");
		return;
	}

	const ADDRINT memIt = dest;
	std::vector<Tag> src2RegColorVector = getTaintColorReg(src2);
	
	for (int ii = 0; ii < length; ii++)
	{
		auto it = this->memTaintField.find(dest+ii);
		UINT16 src2color = src2RegColorVector.at(ii).color;
		if (it == this->memTaintField.end())
		{
			//mem dest is not tainted, just taint with src2 reg color
			if (src2color != EMPTY_COLOR)
			{
				//Byte not in map yet
				Tag tag(src2color);
				this->memTaintField.insert(std::make_pair<ADDRINT, Tag>(dest+ii, tag));
				LOG_MESSAGE_MIX_MEM_WITH_REG("(in loop) New mem taint using reg", "modified", dest+ii, src2, tag.color, EMPTY_COLOR, src2color);
				//LOG_DEBUG("(in loop) New memory taint using reg "<< REG_StringShort(src2) <<" mixTaintMemRegAllBytes(" << to_hex_dbg(dest) << ", " << length << ", " << to_hex_dbg(src1) << ", " << src2 << ") --> mem.ins(" << to_hex_dbg(dest + ii) << ", T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
			
				//Register event for dump files
				struct DataDumper::memory_color_event_line_t event;
				event.color = tag.color;
				event.memAddr = dest+ii;
				event.eventType = DataDumper::TAINT;
				dataDumper.writeMemoryColorEventDump(event);
			}
			continue;
		}
		UINT16 memColor = it->second.color;
		//mem dest is already tainted with some color
		if (src2color == EMPTY_COLOR)
		{
			//reg src2 has empty_color, just taint dest mem with empty_color
			Tag tag(src2color);
			it->second = tag;
			LOG_MESSAGE_MIX_MEM_WITH_REG("(in loop) Mem taint with empty color using reg", "modified", dest + ii, src2, tag.color, memColor, src2color);
			//LOG_DEBUG("(in loop) Memory taint with empty color using reg "<< REG_StringShort(src2) <<" mixTaintMemRegAllBytes(" << to_hex_dbg(dest) << ", " << length << ", " << to_hex_dbg(src1) << ", " << src2 << ") --> modified mem at " << dest + ii << " with T(" << tag.color << "," << tag.derivate1 << "," << tag.derivate2 << "))");
		
			//Register event for dump files
			struct DataDumper::memory_color_event_line_t event;
			event.color = tag.color;
			event.memAddr = dest;
			event.eventType = DataDumper::UNTAINT;
			dataDumper.writeMemoryColorEventDump(event);
		}
		else
		{
			//mem dest and reg src2 have non-empty_color both, mix
			UINT16 mixColor = this->tagLog.getMixColor(it->second.color, src2color);
			if (mixColor == EMPTY_COLOR)
			{
				//No previous mixes
				Tag tag(it->second.color, src2color);
				it->second = tag;
				this->tagLog.logTag(tag);
				LOG_MESSAGE_MIX_MEM_WITH_REG("(in loop) Mixed mem taint using reg", "modified", dest + ii, src2, tag.color, memColor, src2color);
				//LOG_DEBUG("(in loop) Mixed taint reg using "<< REG_StringShort(src2) <<" mixTaintMemRegAllBytes(" << to_hex_dbg(dest) << ", " << length << ", " << to_hex_dbg(src1) << ", " << src2 << ") --> modified mem tag at " << dest + ii << " with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
			
				//Register event for dump files
				struct DataDumper::memory_color_event_line_t event;
				event.color = tag.color;
				event.memAddr = dest;
				event.eventType = DataDumper::MIX;
				dataDumper.writeMemoryColorEventDump(event);
			}
			else
			{
				//Mix already generated before, use that color again
				Tag tag = Tag(mixColor);
				it->second = tag;
				LOG_MESSAGE_MIX_MEM_WITH_REG("(in loop) Reused mem mix taint using reg", "modified", dest + ii, src2, tag.color, memColor, src2color);
				//LOG_DEBUG("(in loop) Reused mix taint reg of "<< REG_StringShort(src2) <<" mixTaintMemRegAllBytes(" << to_hex_dbg(dest) << ", " << length << ", " << to_hex_dbg(src1) << ", " << src2 << ") --> reused mem tag for " << to_hex_dbg(dest + ii) << " with T(" << tag.color << ", " << tag.derivate1 << ", " << tag.derivate2 << ")");
			
				//Register event for dump files
				struct DataDumper::memory_color_event_line_t event;
				event.color = tag.color;
				event.memAddr = dest;
				event.eventType = DataDumper::MIX;
				dataDumper.writeMemoryColorEventDump(event);
			}
		}
	}
}

std::vector<std::pair<ADDRINT, UINT16>> TagMap::getTaintedMemoryVector()
{
	std::vector<std::pair<ADDRINT, UINT16>> vec;
	for (auto const& pair : this->memTaintField) {
		vec.push_back(std::make_pair<ADDRINT, UINT16>(pair.first, pair.second.color));
	}
	return vec;
}

std::vector<std::pair<UINT16, TagLog::original_color_data_t>> TagMap::getOriginalColorsVector()
{
	return this->tagLog.getOriginalColorsVector();
}

std::vector<std::pair<UINT16, TagLog::color_taint_reason_t>> TagMap::getColorReasonsVector()
{
	return this->tagLog.getColorsReasonsVector();
}

TagLog::color_taint_reason_t TagMap::getColorTaintReason(UINT16 color)
{
	return this->tagLog.getColorTaintReason(color);
}

std::vector<Tag> TagMap::getColorTransVector()
{
	return this->tagLog.getColorTransVector();
}


void TagMap::printMemTaintComplete()
{
	std::cerr << "MEM_TAINT_FIELD PRINT START" << std::endl;
	for (auto const& pair : this->memTaintField) {
		std::cerr << "{" << pair.first << ": " << pair.second.color << "}\n";
	}
	std::cerr << std::endl << "MEM_TAINT_FIELD PRINT END" << std::endl;
}

void TagMap::printRegTaintComplete()
{
	std::cerr << "REG_TAINT_FIELD PRINT START" << std::endl;
	const int NUM_COLUMNS = 8;
	for (int ii = 0; ii < 128; ii+=NUM_COLUMNS)
	{
		for (int jj = 0; jj < NUM_COLUMNS; jj++)
		{
			std::cerr << "{" << ii+jj << ": " << this->regTaintField[ii+jj].color << "} ";
		}
		std::cerr << std::endl;
	}
	std::cerr << std::endl << "REG_TAINT_FIELD PRINT END" << std::endl;
}

UINT16 TagMap::getNextTagColor()
{
	Tag tag = Tag::tagNext();
	return tag.color;
}

void TagMap::dumpTaintLog()
{
	this->tagLog.dumpTagLog();
}

void TagMap::dumpTaintLogPrettified(UINT16 startColor)
{
	this->tagLog.dumpTagLogPrettified(startColor);
}

void TagMap::dumpTagLogOriginalColors()
{
	this->tagLog.dumpTagLogOriginalColors();
}

bool TagMap::regIsTainted(REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);

	for (UINT32 ii = posStart; ii < posStart + taintLength; ii++)
	{
		if (this->regTaintField[ii].color != EMPTY_COLOR)
		{
			return true;
		}
	}

	return false;
}

bool TagMap::memIsTainted(ADDRINT mem)
{
	auto it = this->memTaintField.find(mem);
	if (it == this->memTaintField.end())
	{
		return false;
	}

	return true;
}

bool TagMap::memRangeIsTainted(ADDRINT mem, int bytes)
{
	for (int ii = 0; ii < bytes; ii++)
	{
		auto it = this->memTaintField.find(mem);
		if (it != this->memTaintField.end())
		{
			return true;
		}
	}

	return false;
}

std::vector<UINT16> TagMap::regGetColor(REG reg)
{
	const UINT32 posStart = this->tReg.getPos(reg);
	const UINT32 taintLength = this->tReg.getTaintLength(reg);
	std::vector<UINT16> colorVec;

	for (UINT32 ii = posStart; ii < posStart + taintLength; ii++)
	{
		colorVec.push_back(this->regTaintField[ii].color);
	}

	return colorVec;
}

UINT16 TagMap::memGetColor(ADDRINT mem)
{
	auto it = this->memTaintField.find(mem);
	if (it == this->memTaintField.end())
	{
		return EMPTY_COLOR;
	}

	return it->second.color;
}

std::vector<UINT16> TagMap::memRangeGetColor(ADDRINT mem, int bytes)
{
	std::vector<UINT16> colorVec;
	for (int ii = 0; ii < bytes; ii++)
	{
		auto it = this->memTaintField.find(mem);
		if (it != this->memTaintField.end())
		{
			colorVec.push_back(it->second.color);
		}
		else
		{
			colorVec.push_back(EMPTY_COLOR);
		}
	}

	return colorVec;
}
