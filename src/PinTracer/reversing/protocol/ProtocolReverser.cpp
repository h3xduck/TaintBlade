#include "ProtocolReverser.h"

extern Context ctx;

void REVERSING::PROTOCOL::reverseProtocol()
{
	//First we get the heuristics. They must be there already at this point
	RevLog<HLComparison> heuristicsVec = ctx.getRevContext()->getHeuristicsVector();
	std::vector<HLComparison> logHeuristicVec = heuristicsVec.getLogVector();

	//Get list of original colors (tainted by rules) with the memory addresses they 
	//were initially related to
	std::vector<std::pair<UINT16, TagLog::original_color_data_t>> orgVec = taintManager.getController().getOriginalColorsVector();

	if (orgVec.size() <= 0)
	{
		LOG_ERR("It is not possible to reverse the protocol since no data was rule tainted");
		return;
	}
	if(logHeuristicVec.size() <= 0)
	{
		LOG_ERR("It is not possible to reverse the protocol since no heuristics were found");
		return;
	}

	//Now we must build the original buffers from this data
	//Note that a program may do some things that we must bear in mind:
	// - Receive network data in the same buffer (same memory address)
	// - Receive some bytes in a buffer, but require multiple calls (and we rule-tainted each call separatedly)
	//Therefore, in here we will try to join any buffer with consecutive addresses in one.
	//And also, when we notice a jump in the buffer addresses, we create another object
	Protocol protocol;
	ProtocolNetworkBuffer protNetBuffer;
	int currentVectorIndex = 0;
	bool firstBufferByte = true;
	ADDRINT lastMemValue = 0;
	bool firstProtocolBuffer = true;
	//The first one should be the first byte, it was supposed to be put in order
	protNetBuffer.setStartMemAddress(orgVec.front().second.memAddress);
	LOG_DEBUG("Starting protocol reversing, found " << logHeuristicVec.size() << " heuristics and " << orgVec.size() << " entries at the original colors vector");
	while(currentVectorIndex < orgVec.size())
	{
		//We get both the heuristic (which has the original RevAtoms inside) and the color information
		std::pair<UINT16, TagLog::original_color_data_t> &data = orgVec.at(currentVectorIndex);
		
		//We put the original values of the buffer now, depending on whether it is the same buffer or not
		const ADDRINT memAddress = data.second.memAddress;
		if (memAddress != lastMemValue+1)
		{
			LOG_DEBUG("Found new buffer, starting at " << to_hex_dbg(memAddress));
			//The buffer is at the same address, or the program used another buffer 
			//Check if this is not the very first buffer. If not, we've already got one to store in the protocol
			if (!firstProtocolBuffer)
			{
				protocol.addBufferToNetworkBufferVector(protNetBuffer);
			}

			//Create new buffer and store new start
			protNetBuffer = ProtocolNetworkBuffer();
			protNetBuffer.setStartMemAddress(memAddress);
			protNetBuffer.setEndMemAddress(memAddress);
			protNetBuffer.addValueToValuesVector(memAddress);
		}
		else
		{
			LOG_DEBUG("Continuing buffer (start:" << to_hex_dbg(protNetBuffer.getStartMemAddress()) << "), currently at " << to_hex_dbg(memAddress));
			//Next memory address follows the previous one, it is the same joint buffer
			protNetBuffer.addValueToValuesVector(memAddress);
			//The end address is just every time, until it is no longer modified
			protNetBuffer.setEndMemAddress(memAddress);
			
		}
		lastMemValue = memAddress;
		currentVectorIndex++;
		firstProtocolBuffer = false;
	}
	
	LOG_DEBUG("Protocol reverser detected the following buffers:");
	for (ProtocolNetworkBuffer &buf : protocol.getNetworkBufferVector())
	{
		LOG_DEBUG("Start: " << to_hex(buf.getStartMemAddress()) << " | End: " << to_hex(buf.getEndMemAddress()));
	}
	
}