#include "DataDumper.h"

DataDumper dataDumper;
extern Context ctx;
extern std::string pintracerSuffix;

DataDumper::DataDumper()
{
	this->memDumpFile.open(getFilenameFullName(CURRENT_TAINTED_MEMORY_DUMP_FILE).c_str());
	this->orgColorsDumpFile.open(getFilenameFullName(ORG_COLORS_DUMP_FILE).c_str());
	this->colorTransDumpFile.open(getFilenameFullName(COLOR_TRANS_DUMP_FILE).c_str());
	this->funcDllNamesDumpFile.open(getFilenameFullName(FUNC_DLL_NAMES_DUMP_FILE).c_str());
	this->memColorEventDumpFile.open(getFilenameFullName(TAINT_EVENT_DUMP_FILE).c_str());
	this->heuristicsResultsDumpFile.open(getFilenameFullName(HEURISTIC_RESULTS_DUMP_FILE).c_str());
	this->protocolResultsDumpFile.open(getFilenameFullName(PROTOCOL_RESULTS_DUMP_FILE).c_str());
	this->traceResultsDumpFile.open(getFilenameFullName(TRACE_RESULTS_DUMP_FILE).c_str());
}

void DataDumper::writeOriginalColorDump(std::vector<std::pair<UINT16, TagLog::original_color_data_t>> &colorVec)
{
	//NOTE: in here we also have the memAddress available
	for (auto it : colorVec)
	{
		this->orgColorsDumpFile << it.first << DUMP_INTER_SEPARATOR <<
			it.second.dllName << DUMP_INTER_SEPARATOR <<
			it.second.funcName << DUMP_INTER_SEPARATOR <<
			this->lastRoutineDumpIndex << DUMP_OUTER_SEPARATOR;
	}
}

void DataDumper::writeMemoryColorEventDump(memory_color_event_line_t event)
{
	this->memColorEventDumpFile << event.eventType << DUMP_INTER_SEPARATOR <<
		this->lastRoutineDumpIndex << DUMP_INTER_SEPARATOR <<
		ctx.getCurrentBaseInstruction() << DUMP_INTER_SEPARATOR <<
		event.memAddr << DUMP_INTER_SEPARATOR <<
		event.color << DUMP_INTER_SEPARATOR <<
		ctx.getLastMemoryValue() << DUMP_INTER_SEPARATOR <<
		ctx.getLastMemoryLength() << DUMP_OUTER_SEPARATOR;
}

void DataDumper::writeRoutineDumpLine(struct func_dll_names_dump_line_t data)
{
	this->funcDllNamesDumpFile << this->lastRoutineDumpIndex << DUMP_INTER_SEPARATOR << 
		data.dllFrom.c_str() << DUMP_INTER_SEPARATOR << data.funcFrom.c_str() << 
		DUMP_INTER_SEPARATOR << data.memAddrFrom << DUMP_INTER_SEPARATOR << 
		data.dllTo.c_str() << DUMP_INTER_SEPARATOR << data.funcTo.c_str() <<
		DUMP_INTER_SEPARATOR << data.memAddrTo << DUMP_INTER_SEPARATOR <<
		data.arg0 << DUMP_INTER_SEPARATOR <<
		data.arg1 << DUMP_INTER_SEPARATOR <<
		data.arg2 << DUMP_INTER_SEPARATOR <<
		data.arg3 << DUMP_INTER_SEPARATOR <<
		data.arg4 << DUMP_INTER_SEPARATOR <<
		data.arg5 << DUMP_OUTER_SEPARATOR;
	this->lastRoutineDumpIndex++;
}

size_t hashCalculateMemoryVector(std::vector<std::pair<ADDRINT, UINT16>> vec)
{
	std::size_t seed = vec.size();
	for (auto& i : vec) {
		seed ^= i.first + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= i.second + 0x1f353261 + (seed << 6) + (seed >> 2);
	}
	return seed;
}

void DataDumper::writeCurrentTaintedMemoryDump(ADDRINT ip, std::vector<std::pair<ADDRINT, UINT16>> vec)
{
	//Calculate hash and compare with the last one
	size_t hash = hashCalculateMemoryVector(vec);
	if (vec.size() == lastMemDumpVecSize || hash == this->hashLastMemDump)
	{
		//Same hash, return
		return;
	}

	this->memDumpFile << ip << DUMP_INTER_SEPARATOR << this->lastRoutineDumpIndex;
	for (auto it : vec)
	{
		this->memDumpFile << DUMP_INTER_SEPARATOR << it.first << DUMP_INTER_SEPARATOR << it.second;
	}
	this->memDumpFile << DUMP_OUTER_SEPARATOR;

	this->hashLastMemDump = hash;
	this->lastMemDumpVecSize = vec.size();
}

void DataDumper::writeColorTransformationDump(std::vector<Tag> vec)
{
	for (auto& it : vec)
	{
		this->colorTransDumpFile << it.color << DUMP_INTER_SEPARATOR <<
			it.derivate1 << DUMP_INTER_SEPARATOR <<
			it.derivate2 << DUMP_OUTER_SEPARATOR;
	}
}

void DataDumper::writeRevHeuristicDumpLine(HLComparison log)
{
	std::vector<RevAtom> atomVec = log.getFullAtomVector();
	std::vector<std::string> instVec = log.getInstructionVector();
	this->heuristicsResultsDumpFile << "COMPARISON HEURISTIC MET: " <<std::endl;
	for (int ii=0; ii<atomVec.size(); ii++)
	{
		this->heuristicsResultsDumpFile << "\t" << to_hex(atomVec.at(ii).getBaseAddress()) << ": " << instVec.at(ii) << std::endl;
	}
}

void DataDumper::writeRevHeuristicDumpLine(HLPointerField log)
{
	std::vector<RevAtom> atomVec = log.getFullAtomVector();
	std::vector<std::string> instVec = log.getInstructionVector();
	this->heuristicsResultsDumpFile << "POINTER FIELD HEURISTIC MET: " << std::endl;
	for (int ii = 0; ii < atomVec.size(); ii++)
	{
		this->heuristicsResultsDumpFile << "\t" << to_hex(atomVec.at(ii).getBaseAddress()) << ": " << instVec.at(ii) << std::endl;
	}
}

void DataDumper::writeProtocolDump(REVERSING::PROTOCOL::Protocol protocol)
{
	std::vector<REVERSING::PROTOCOL::ProtocolNetworkBuffer>& protNetbufferVec = protocol.getNetworkBufferVector();
	
	//We will iterate over each protocol netbuffer and print the data of their data
	for (int ii = 0; ii < protNetbufferVec.size(); ii++)
	{
		//Data from protocol netbuffer
		this->protocolResultsDumpFile << "The tracer detected " << protNetbufferVec.size() << " buffers:" << std::endl;
		this->protocolResultsDumpFile << "PROTOCOL NETWORK BUFFER " << ii << ":" << std::endl;
		REVERSING::PROTOCOL::ProtocolNetworkBuffer& protNetBuf = protNetbufferVec.at(ii);
		std::vector<UINT16> &colors = protNetBuf.getColorsVector();
		std::vector<UINT8> &values = protNetBuf.getValuesVector();
		std::vector<TagLog::color_taint_reason_t>& taintReasons = protNetBuf.gecolorTaintReasonsVector();
		ADDRINT start = protNetBuf.getStartMemAddress();
		ADDRINT end = protNetBuf.getEndMemAddress();
		this->protocolResultsDumpFile << "\tMemory start: " << start << " | Memory end: " << end << std::endl;

		this->protocolResultsDumpFile << "\tValues:" << std::endl;
		for (int jj = 0; jj < colors.size(); jj++)
		{
			UINT16& color = colors.at(jj);
			UINT8& value = values.at(jj);
			TagLog::color_taint_reason_t& reason = taintReasons.at(jj);
			this->protocolResultsDumpFile << "\t\t Color: " << color << " | Byte value: " << InstructionWorker::byteToHexValueString(value) << " (as char: " << value <<")";
			//Print whether the byte has any special reason to be tainted
			switch (reason.reasonClass)
			{
			case TagLog::TAINT_REASON_SINK:
				this->protocolResultsDumpFile << " | used as arg " << reason.sinkData.argNumber << " in " << reason.sinkData.dllName << " ::> " << reason.sinkData.funcName << " at offset " << reason.sinkData.offsetFromArgStart;
				break;
			}
			this->protocolResultsDumpFile << std::endl;
		}

		//Data from each of the protocol words contained in each protocol netbuffer
		std::vector<REVERSING::PROTOCOL::ProtocolWord> &protWordVec = protNetBuf.getWordVector();
		this->protocolResultsDumpFile << "\tThe buffer contains " << protWordVec.size() << " words:" << std::endl;
		for (REVERSING::PROTOCOL::ProtocolWord &protWord : protWordVec)
		{
			//Print the word, pad it with some tabs for pretty printing
			std::string wordStr = protWord.toString();
			std::string old("\n");
			std::string rep("\n\t\t");
			for (std::size_t pos = 0;
				(pos = wordStr.find(old, pos)) != std::string::npos;
				pos += rep.length())
			{
				wordStr.replace(pos, old.length(), rep);
			}
			this->protocolResultsDumpFile << "\t\t" << wordStr << std::endl;
		}

		//Also inform about found pointer fields
		std::vector<REVERSING::PROTOCOL::ProtocolPointer>& protPointerVec = protNetBuf.pointerVector();
		this->protocolResultsDumpFile << "\tThe buffer contains " << protPointerVec.size() << " pointer fields:" << std::endl;
		for (REVERSING::PROTOCOL::ProtocolPointer& protPointer : protPointerVec)
		{
			//Print the pointer, pad it with some tabs for pretty printing
			std::string ptrStr = protPointer.toString();
			std::string old("\n");
			std::string rep("\n\t\t");
			for (std::size_t pos = 0;
				(pos = ptrStr.find(old, pos)) != std::string::npos;
				pos += rep.length())
			{
				ptrStr.replace(pos, old.length(), rep);
			}
			this->protocolResultsDumpFile << "\t\t" << ptrStr << std::endl;
		}
		this->protocolResultsDumpFile << std::endl;
	}
}

void DataDumper::writeTraceDumpLine(UTILS::TRACE::TracePoint& tp)
{
	std::vector<std::string> argsPre = tp.getArgsPre();
	std::vector<std::string> argsPost = tp.getArgsPost();
	this->traceResultsDumpFile << "DLL: " << tp.getDllName() << " | FUNC: " << tp.getFuncName() << std::endl;
	this->traceResultsDumpFile << "Called with arguments:" << std::endl;
	for (int ii = 0; ii < tp.getNumArgs(); ii++)
	{
		this->traceResultsDumpFile << "\targ" << ii << ": " << argsPre.at(ii) << std::endl;
	}
	this->traceResultsDumpFile << "Exited with arguments:" << std::endl;
	for (int ii = 0; ii < tp.getNumArgs(); ii++)
	{
		this->traceResultsDumpFile << "\targ" << ii << ": " << argsPost.at(ii) << std::endl;
	}
	this->traceResultsDumpFile << std::endl;
}


void DataDumper::resetDumpFiles()
{
	if (remove(CURRENT_TAINTED_MEMORY_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting data dump file");
	}
	else
	{
		LOG_DEBUG("Data dump file successfully deleted");
	}

	if (remove(ORG_COLORS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting original colors dump file");
	}
	else
	{
		LOG_DEBUG("Original colors dump file successfully deleted");
	}

	if (remove(COLOR_TRANS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting colors transformation dump file");
	}
	else
	{
		LOG_DEBUG("Colors transformation dump file successfully deleted");
	}

	if (remove(TAINT_EVENT_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting taint events dump file");
	}
	else
	{
		LOG_DEBUG("Taint events dump file successfully deleted");
	}

	if (remove(FUNC_DLL_NAMES_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting function calls dump file");
	}
	else
	{
		LOG_DEBUG("Function calls dump file successfully deleted");
	}

	if (remove(HEURISTIC_RESULTS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting heuristic results dump file");
	}
	else
	{
		LOG_DEBUG("Heuristic results dump file successfully deleted");
	}

	if (remove(PROTOCOL_RESULTS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting protocol results dump file");
	}
	else
	{
		LOG_DEBUG("Protocol results dump file successfully deleted");
	}

	if (remove(TRACE_RESULTS_DUMP_FILE) != 0)
	{
		LOG_ERR("Error deleting trace results dump file");
	}
	else
	{
		LOG_DEBUG("Trace results dump file successfully deleted");
	}
}