#include "ProtocolReverser.h"

extern Context ctx;

typedef struct comparison_data_t
{
	int heuristicLevel;   //heuristic level (see reversing algorithm for explanation)
	int comparisonResult; //result of comparison
	UINT8 byteComparison; //byte value to which the buffer byte is compared
	UINT16 colorInvolved; //taint color which the byte that was compared holded
	int bufferIndex;	  //index at the netbuffer to which the comparison was made
};

bool compare_comparison_data_t(const comparison_data_t& a, const comparison_data_t& b)
{
	return a.byteComparison < b.byteComparison;
}

void REVERSING::PROTOCOL::reverseProtocol()
{
	//First we get the comparison heuristics. They must be there already at this point
	RevLog<HLComparison> &heuristicsVec = ctx.getRevContext()->getComparisonHeuristicsVector();
	std::vector<HLComparison> &logHeuristicVec = heuristicsVec.getLogVector();

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
	LOG_DEBUG("Starting protocol reversing, found " << logHeuristicVec.size() << " comparison heuristics and " << orgVec.size() << " entries at the original colors vector");
	while(currentVectorIndex < orgVec.size())
	{
		//We get both the heuristic (which has the original RevAtoms inside) and the color information
		std::pair<UINT16, TagLog::original_color_data_t> &data = orgVec.at(currentVectorIndex);
		
		//We put the original values of the buffer now, depending on whether it is the same buffer or not
		const ADDRINT memAddress = data.second.memAddress;
		const UINT8 byteValue = data.second.byteValue;
		const UINT16 color = data.first;
		TagLog::color_taint_reason_t taintReason = taintManager.getController().getColorTaintReason(color);
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
			protNetBuffer.addReasonTocolorTaintReasonsVector(taintReason);
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
			protNetBuffer.addReasonTocolorTaintReasonsVector(taintReason);
			
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
		LOG_DEBUG("Start: " << to_hex(buf.getStartMemAddress()) << " | End: " << to_hex(buf.getEndMemAddress() << " | Colors:(" << buf.getStartColor() << "-" << buf.getEndColor() << ")"));
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
		//A vector containing the full list of heuristic comparisons.
		//Inside the vector, we can find elements:
		// - Ordered by "heuristic level (HL)": a series of comparisons share an heuristic level if 
		//   they occured sequentially in time and in consecutive bytes. (e.g.: comparing byte 0 and
		//   then comparing byte 1).
		// - Inside each HL, the comparisons are ordered by the byte of the buffer they were compared to.
		// - Each element specifies the HL, the index of the byte inside the buffer, the result of the comparison,
		//   and the value of the byte in the comparison.
		//For each of the vectors at each colors, we find the comparisons made to them.
		std::vector<comparison_data_t> comparisonVector;
		
		LOG_DEBUG("Starting with buffer of size " << buf.getColorsVector().size());
		
		//We take the values we want from the heuristics to fill up the vector
		//TODO optimize: get this heuristic out already if all colors covered

		//Iterative value, unique globally for all heuristics, for distinguishing comparisons belonging to same heuristic
		//after they are separated.
		int heuristicLevel = 0;
		UINT16 lastComparedColor = 0;
		for (HLComparison& heuristic : logHeuristicVec)
		{
			std::vector<UINT16>& heuristicColors = heuristic.getComparisonColorsFirst();
			std::vector<UINT8>& heuristicValues = heuristic.getComparisonValuesSecond();
			LOG_DEBUG("Iterating in heuristic for " << heuristicColors.size() << " colors");

			//All comparisons in the heuristic share heuristic level, since they belong to the same comparison
			bool firstColorInHeuristic = true;
			for (int ii = 0; ii < heuristicColors.size(); ii++)
			{
				UINT16& color = heuristicColors.at(ii);
				//If the heuristic refers to a color contained in the buffer
				if (color >= buf.getStartColor() && color <= buf.getEndColor())
				{
					//Determine if we must maintain the heuristic level as with the previous heuristic
					//Note that comparisons of the same heuristic always share Heuristic Level.
					//TODO: improve this by using the instruction pointer at which the comparison occured
					//TODO IMPORTANT: improve this so that we do not check just the color, but the color of the parent that was rule-tainted
					if (color == lastComparedColor + 1)
					{
						//Means the comparison is sequential to the last one, so share heuristic colors
						LOG_DEBUG("C: " << color << ", kept HL: " << heuristicLevel);
						lastComparedColor = color;
					}
					else if (!firstColorInHeuristic)
					{
						//If we are still in the same heuristic, then even if the color is not consecutive, no big deal
						LOG_DEBUG("C: " << color << " | LC: " << lastComparedColor<<", but same heuristic so maintained HL: "<<heuristicLevel);
						lastComparedColor = color;
					}
					else
					{
						LOG_DEBUG("C: " << color << " | LC: " << lastComparedColor<<" | HL incremented: "<<heuristicLevel+1);
						//Increment the heuristic level, since it is clearly not related to the last instruction
						lastComparedColor = color;
						heuristicLevel++;
					}

					//Get position based on colors, which are sequential
					//Store the data about the comparison
					//We must write all different possible colors.
					LOG_DEBUG("Storing compvalues for color " << color << " which were at position " << ii << " of the heuristic");
					UINT8 byteValue = heuristicValues.at(ii);
					int bufferIndex = color-buf.getStartColor();
					comparison_data_t comp = { heuristicLevel, heuristic.getComparisonResult(), byteValue, color, bufferIndex};
					LOG_DEBUG("Introduced comparison:: HL:" << heuristicLevel << " COMPVALUE:" << byteValue << " COMPRES: " << heuristic.getComparisonResult());
					comparisonVector.push_back(comp);
					firstColorInHeuristic = false;
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
		for (comparison_data_t& comp: comparisonVector)
		{
			LOG_DEBUG("\tHL:" << comp.heuristicLevel << " BYTE:" << InstructionWorker::byteToHexValueString(comp.byteComparison) << " (as char: " << comp.byteComparison << ") RES:" << comp.comparisonResult);
		}


		//At this point, we already have the comparison vector fully built. It is time to fill up to build the delimitors
		//We try to find the delimitors and keywords. The idea is the following:
		//We get the first element win the vector, with the lowest HL. We take that as the start of a word, and then
		//try to interpret with a series of heuristics whether it is a delimeter or a keyword.
		//The following are some heuristics:
		// - A "delimeter" is a value that the buffer is compared with multiple times, sequentially,
		//   with lots of false comparison results, and one true. We will check for bytes checked in the same HL.
		// - A "keyword" is a value in the same HL, checked for a certain byte(s) but not with the same byte sequentially.
		//   It may be checked with things like strcmp(), which we will try to detect.

		LOG_DEBUG("Starting word extraction process");
		for (int ii = 0; ii < comparisonVector.size(); ii++)
		{
			LOG_DEBUG("Iteration start");
			ProtocolWord currentWord;

			//We take the first comparison we can find
			const comparison_data_t topComparison = comparisonVector.at(ii);

			//Put the data we want from the byte we checked
			currentWord.addByte(topComparison.byteComparison);
			currentWord.addColor(topComparison.colorInvolved);
			currentWord.addSuccessIndex(topComparison.comparisonResult);
			currentWord.setStartIndex(topComparison.bufferIndex);
			currentWord.setEndIndex(topComparison.bufferIndex);

			LOG_DEBUG("Starting from BYTE:" << InstructionWorker::byteToHexValueString(topComparison.byteComparison) << "(as char: " << topComparison.byteComparison << ") SUCCESS:" << topComparison.comparisonResult);

			//First of all, we join in the word all bytes that were related to the same compare instruction (they chave the same HL)
			for (int jj = ii + 1; jj <= comparisonVector.size(); jj++)
			{
				//In case we already parsed all elements in the vector, we introduce the current word if any and end the comparisons
				if (jj == comparisonVector.size())
				{
					if (currentWord.getWordType() != ProtocolWord::UNDEFINED)
					{
						LOG_DEBUG("Inserted bytes of a keyword or unfinished delimeter upon buffer end reached");
						buf.addWordToWordVector(currentWord);
						//We finished checking all 
					}
					else
					{
						//If we did not identify it yet as a keyword or delimeter, it must be a lone byte. Insert it as a bytekeyword
						LOG_DEBUG("Inserted a lone bytekeyword");
						currentWord.setWordType(ProtocolWord::BYTEKEYWORD);
						buf.addWordToWordVector(currentWord);
					}

					LOG_DEBUG("Finished checking HL " << topComparison.heuristicLevel);
					ii = jj;
					break;
				}

				comparison_data_t& itData = comparisonVector.at(jj);
				if (itData.heuristicLevel == topComparison.heuristicLevel)
				{
					//It came from the same heuristic level

					//Is it a delimeter? If it is, it must be the same byte as before
					//Also, check that we did not identify it as a keyword before already
					//NOTE: we could check whether it is a keyword+delimeter in the same HL here
					if (currentWord.getWordType() != ProtocolWord::KEYWORD && itData.byteComparison == topComparison.byteComparison)
					{
						//It is most likely a delimeter, or we detected it as such before
						currentWord.addByte(itData.byteComparison);
						currentWord.addColor(itData.colorInvolved);
						currentWord.addSuccessIndex(itData.comparisonResult);
						currentWord.setEndIndex(itData.bufferIndex);
						//Let's check if the delimeter already had its 'success' comparison:
						if (itData.comparisonResult == 1)
						{
							//Delimeter succeeded already. This must be the end of the delimeter, so we finish the word already
							currentWord.setWordType(ProtocolWord::DELIMETER);
							buf.addWordToWordVector(currentWord);
							LOG_DEBUG("Next byte is from a success comparison of the same delimeter, so joined it with the last byte(s)");
							//We insert the word and finish
							//We set the current comparison to the current one, which was the last one with the same HL.
							ii = jj;
							break;
						}
						else
						{
							//The delimeter did not reach the success comparison yet. We include the byte in the word, but we keep looking
							//for the success comparison
							currentWord.setWordType(ProtocolWord::FAILEDDELIMETER);
							LOG_DEBUG("Next byte is from a failed comparison of the same delimeter, so joined it with the last byte(s)");
						}
					}
					else
					{
						//It is not a delimeter, must be a keyword
						currentWord.addByte(itData.byteComparison);
						currentWord.addColor(itData.colorInvolved);
						currentWord.addSuccessIndex(itData.comparisonResult);
						currentWord.setEndIndex(itData.bufferIndex);
						currentWord.setWordType(ProtocolWord::KEYWORD);
						//We keep searching for the end of the keyword, which will be when we change HL
						LOG_DEBUG("Next byte is from the same keyword, so joined it with the last byte(s)");
					}

				}
				else
				{
					//The bytes did not come from the same heuristic level, so we stop searching already
					//If we have an unfinished keyword or delimeter in the currentword, we consider the last byte to be the end
					//of them. So we insert the word.
					if (currentWord.getWordType() != ProtocolWord::UNDEFINED)
					{
						LOG_DEBUG("Inserted bytes of a keyword or unfinished delimeter");
						buf.addWordToWordVector(currentWord);
					}
					else
					{
						//If we did not identify it yet as a keyword or delimeter, it must be a lone byte. Insert it as a bytekeyword
						LOG_DEBUG("Inserted a lone bytekeyword");
						currentWord.setWordType(ProtocolWord::BYTEKEYWORD);
						buf.addWordToWordVector(currentWord);
					}
					//We set the current comparison to the one before this one, which was the last one with the same HL.
					ii = jj - 1;
					break;
				}

			} // end checking current Heuristic Level

			LOG_DEBUG("Finished checking HL " << topComparison.heuristicLevel);

		} //end for all bytes in the protocol netbuffer


	} //finished parsing for all protocol netbuffers
	

	//Once we've got all comparison heuristics interpreted into the protocol netbuffers, we will do the same with
	//the pointer field heuristics
	RevLog<HLPointerField>& pointerFieldheuristicsVec = ctx.getRevContext()->getPointerFieldHeuristicsVector();
	std::vector<HLPointerField>& logPointerFieldHeuristicVec = pointerFieldheuristicsVec.getLogVector();
	for (ProtocolNetworkBuffer& buf : protocol.getNetworkBufferVector())
	{
		for (HLPointerField& pointerField : logPointerFieldHeuristicVec)
		{
			//Check if any of the pointer value goes correspond to this buffer
			std::vector<UINT16> colorPointerVec = pointerField.comparisonColorsPointed();
			UINT16 pointedColor = colorPointerVec.at(0);
			if (pointedColor >= buf.getStartColor() && pointedColor <= buf.getEndColor())
			{
				ProtocolPointer protPointer(pointerField.comparisonValuesPointer(), pointerField.comparisonColorsPointer(), pointedColor);
				buf.pointerVector().push_back(protPointer);
				continue;
			}
			//Or if the pointed color corresponds to it
			if (pointedColor >= buf.getStartColor() && pointedColor <= buf.getEndColor())
			{
				ProtocolPointer protPointer(pointerField.comparisonValuesPointer(), pointerField.comparisonColorsPointer(), pointedColor);
				buf.pointerVector().push_back(protPointer);
			}

		}
	}

	//Test
	for (ProtocolNetworkBuffer& buf : protocol.getNetworkBufferVector())
	{
		LOG_DEBUG("NETWORKBUFFER of len:"<< buf.getWordVector().size());
		LOG_DEBUG("PROTOCOL WORDS:")
		for (ProtocolWord& word : buf.getWordVector())
		{
			LOG_DEBUG(word.toString());
		}
		LOG_DEBUG("PROTOCOL POINTERS ("<<buf.pointerVector().size()<<"):");
		for (ProtocolPointer& pointer : buf.pointerVector())
		{
			LOG_DEBUG(pointer.toString());
		}
	}

	//Dump data about the protocol
	ctx.getDataDumper().writeProtocolDump(protocol);

}