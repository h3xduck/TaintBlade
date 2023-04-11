#include "ProtocolReverser.h"

extern Context ctx;

typedef struct comparison_data_t
{
	int comparisonResult; //reuslt
	UINT8 byteComparison; //byte value to which the buffer byte is compared
};

bool compare_comparison_data_t(const comparison_data_t& a, const comparison_data_t& b)
{
	return a.byteComparison < b.byteComparison;
}

void REVERSING::PROTOCOL::reverseProtocol()
{
	//First we get the heuristics. They must be there already at this point
	RevLog<HLComparison> heuristicsVec = ctx.getRevContext()->getHeuristicsVector();
	std::vector<HLComparison> logHeuristicVec = heuristicsVec.getLogVector();

	//Get list of original colors (tainted by rules) with the memory addresses they 
	//were initially related to
	std::vector<std::pair<UINT16, TagLog::original_color_data_t>> orgVec = taintManager.getController().getOriginalColorsVector();

	//Test
	/*TagLog::original_color_data_t data;
	data.byteValue = 0;
	data.memAddress = 1000000;
	std::pair<UINT16, TagLog::original_color_data_t > log = std::make_pair(1, data);
	orgVec.push_back(log);
	data.byteValue = 1;
	data.memAddress = 1000001;
	log = std::make_pair(2, data);
	orgVec.push_back(log);*/

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

	//TODO revise whether to do this with colors
	// 
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
	protNetBuffer.setStartColor(orgVec.front().first);
	LOG_DEBUG("Starting protocol reversing, found " << logHeuristicVec.size() << " heuristics and " << orgVec.size() << " entries at the original colors vector");
	while(currentVectorIndex < orgVec.size())
	{
		//We get both the heuristic (which has the original RevAtoms inside) and the color information
		std::pair<UINT16, TagLog::original_color_data_t> &data = orgVec.at(currentVectorIndex);
		
		//We put the original values of the buffer now, depending on whether it is the same buffer or not
		const ADDRINT memAddress = data.second.memAddress;
		const UINT8 byteValue = data.second.byteValue;
		const UINT16 color = data.first;
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
			protNetBuffer.setStartColor(color);
			protNetBuffer.setEndMemAddress(memAddress);
			protNetBuffer.setEndColor(color);
			protNetBuffer.addValueToValuesVector(byteValue);
			//Include the color information into buffer byte
			protNetBuffer.addColorToColorsVector(color);
		}
		else
		{
			LOG_DEBUG("Continuing buffer (start:" << to_hex_dbg(protNetBuffer.getStartMemAddress()) << "), currently at " << to_hex_dbg(memAddress));
			//Next memory address follows the previous one, it is the same joint buffer
			//The end address is just every time, until it is no longer modified
			protNetBuffer.setEndMemAddress(memAddress);
			protNetBuffer.setEndColor(color);
			//Include the color information into buffer byte
			protNetBuffer.addColorToColorsVector(color);
			//We get the actual value of the byte at that memory address and store it
			protNetBuffer.addValueToValuesVector(byteValue);
			
		}
		lastMemValue = memAddress;
		currentVectorIndex++;
		firstProtocolBuffer = false;
	}
	//Include the last buffer, if we found at least one
	if (!firstProtocolBuffer)
	{
		protocol.addBufferToNetworkBufferVector(protNetBuffer);
	}
	
	LOG_DEBUG("Protocol reverser detected the following buffers:");
	for (ProtocolNetworkBuffer &buf : protocol.getNetworkBufferVector())
	{
		LOG_DEBUG("Start: " << to_hex(buf.getStartMemAddress()) << " | End: " << to_hex(buf.getEndMemAddress() << "Colors:(" << buf.getStartColor() << "-" << buf.getEndColor() << ")"));
	}

	//Now, we have all network buffers used in the program. It is time to reverse the protocol using the heuristics
	//First, let's load the comparison heuristics we gathered during the program execution and try to cross-reference them
	//with the network buffers we've got using the color of their bytes. 
	//Any heuristic may contain multiple bytes in the comparison and therefore ordering them is difficult.
	//Therefore we will deconstruct the heuristics into a simpler form, one byte comparison each,
	//taking into account that if an heuristic with 2 bytes comparison is correct, then each byte
	//alone by itself must be a successful compare too.
	for (ProtocolNetworkBuffer& buf : protocol.getNetworkBufferVector())
	{
		//Each entry contains a vector, one for each color.
		//For each of the vectors at each colors, we find the comparisons made to them.
		std::vector<std::vector<comparison_data_t>> comparisonMatrix(buf.getColorsVector().size(), std::vector<comparison_data_t>());
		//comparisonMatrix.reserve(buf.getColorsVector().size());
		LOG_DEBUG("Starting with buffer of size " << buf.getColorsVector().size());
		
		//We take the values we want from the heuristics to fill up the matrix
		//TODO optimize: get this heuristic out already if all colors covered
		for (HLComparison& heuristic : logHeuristicVec)
		{
			std::vector<UINT16>* heuristicColors = heuristic.getComparisonColorsFirst();
			std::vector<UINT8>* heuristicValues = heuristic.getComparisonValuesSecond();
			LOG_DEBUG("Iterating in heuristic for " << heuristicColors->size() << " colors");
			for (int ii = 0; ii < heuristicColors->size(); ii++)
			{
				UINT16& color = heuristicColors->at(ii);
				//If the heuristic refers to a color contained in the buffer
				if (color >= buf.getStartColor() && color <= buf.getEndColor())
				{
					//Get position based on colors, which are sequential
					//Store the data about the comparison
					//We must write all different possible colors.
					LOG_DEBUG("Storing compvalues for color " << color << " in position " << ii << " of the heuristic");
					UINT8 byteValue = heuristicValues->at(ii);
					comparison_data_t comp = { heuristic.getComparisonResult(), byteValue};
					LOG_DEBUG("Introduced at position " << color - buf.getStartColor() << ": COMPVALUE:" << byteValue << " COMPRES: " << heuristic.getComparisonResult());
					comparisonMatrix.at(color - buf.getStartColor()).push_back(comp);
				}
				else
				{
					//TODO: What if the heuristic holds a derived color?
					LOG_DEBUG("Ignored heuristic color " << color << " since it's not in range");
				}
			}
		}


		//Test
		LOG_DEBUG("Starting buffer dump:");
		//Test, checkout results
		for (std::vector<comparison_data_t>& vec : comparisonMatrix)
		{
			LOG_DEBUG("COLOR: ");
			for (comparison_data_t& data : vec)
			{
				LOG_DEBUG("\tBYTE:"<<data.byteComparison<<" RES:"<<data.comparisonResult);
			}
		}


		//At this point, we already have the matrix fully built. It is time to fill up to build the delimitors
		//First, we sort the vectors for each of the bytes of the buffer, so that they are ordered
		//NOTE: Maybe it is better if we do not sort it, to avoid interfering in keyword detection, where
		// we might reorder some keyword comparison bytes. In the end, heuristics have come ordered already.
		/*for (std::vector<comparison_data_t>& vec : comparisonMatrix)
		
			std::sort(vec.begin(), vec.end(), compare_comparison_data_t);
		}*/

		//Once sorted, we try to find the delimitors and keywords. The idea is the following:
		//We get the first element from the first byte of the buffer. If it exists. Otherwise,
		//we start from the nth element, where n is the first vector with any element inside.
		//From that nth vector, we consider that:
		// - A "delimeter" is a value that the buffer is compared with multiple times, sequentially,
		//   with lots of false comparison results. We will check for bytes checked in sequential vectors.
		// - A "keyword" is a value not checked sequentially, but rather checked for a certain byte(s).
		//   it is commonly made of multiple bytes, so we will try to extend the keyword.


		

	}

	

}