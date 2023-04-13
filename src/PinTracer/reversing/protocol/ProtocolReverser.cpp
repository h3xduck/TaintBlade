#include "ProtocolReverser.h"

extern Context ctx;

typedef struct comparison_data_t
{
	int comparisonResult; //result
	UINT8 byteComparison; //byte value to which the buffer byte is compared
	int heuristicValue;   //data with same value means it came from the same heuristic comparison
};

bool compare_comparison_data_t(const comparison_data_t& a, const comparison_data_t& b)
{
	return a.byteComparison < b.byteComparison;
}

void REVERSING::PROTOCOL::reverseProtocol()
{
	//First we get the heuristics. They must be there already at this point
	RevLog<HLComparison> &heuristicsVec = ctx.getRevContext()->getHeuristicsVector();
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
		//Each entry contains a vector, one for each color.
		//For each of the vectors at each colors, we find the comparisons made to them.
		std::vector<std::vector<comparison_data_t>> comparisonMatrix(buf.getColorsVector().size(), std::vector<comparison_data_t>());
		//comparisonMatrix.reserve(buf.getColorsVector().size());
		LOG_DEBUG("Starting with buffer of size " << buf.getColorsVector().size());
		
		//We take the values we want from the heuristics to fill up the matrix
		//TODO optimize: get this heuristic out already if all colors covered

		//Iterative value, unique globally for all heuristics, for distinguishing comparisons belonging to same heuristic
		//after they are separated.
		int heuristicValue = 0;
		for (HLComparison& heuristic : logHeuristicVec)
		{
			std::vector<UINT16>& heuristicColors = heuristic.getComparisonColorsFirst();
			std::vector<UINT8>& heuristicValues = heuristic.getComparisonValuesSecond();
			LOG_DEBUG("Iterating in heuristic for " << heuristicColors.size() << " colors");
			for (int ii = 0; ii < heuristicColors.size(); ii++)
			{
				UINT16& color = heuristicColors.at(ii);
				//If the heuristic refers to a color contained in the buffer
				if (color >= buf.getStartColor() && color <= buf.getEndColor())
				{
					//Get position based on colors, which are sequential
					//Store the data about the comparison
					//We must write all different possible colors.
					LOG_DEBUG("Storing compvalues for color " << color << " which were at position " << ii << " of the heuristic");
					UINT8 byteValue = heuristicValues.at(ii);
					comparison_data_t comp = { heuristic.getComparisonResult(), byteValue, heuristicValue};
					LOG_DEBUG("Introduced at position " << color - buf.getStartColor() << ", where bufStartColor is "<< buf.getStartColor() <<": COMPVALUE:" << byteValue << " COMPRES: " << heuristic.getComparisonResult());
					comparisonMatrix.at(color - buf.getStartColor()).push_back(comp);
				}
				else
				{
					//TODO: What if the heuristic holds a derived color?
					LOG_DEBUG("Ignored heuristic color " << color << " since it's not in range");
				}
			}
			heuristicValue++;
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

		int currentFirstColumn = 0;
		int matrixLength = comparisonMatrix.size();

		LOG_DEBUG("Starting word extraction process");
		while (currentFirstColumn < matrixLength)
		{
			LOG_DEBUG("Iteration start");
			ProtocolWord currentWord;
			if (comparisonMatrix.at(currentFirstColumn).empty())
			{
				//Go to the next column in the matrix, the next byte in the buffer
				currentFirstColumn++;
				LOG_DEBUG("Empty column at netbuffer[" << currentFirstColumn << "], going to next one");
				continue;
			}
			
			//If we've got some comparison for this byte in the buffer, we take the first
			std::vector<comparison_data_t>& currentVector = comparisonMatrix.at(currentFirstColumn);
			const comparison_data_t topComparison = currentVector.front();

			//Put the data we want from the byte we checked, then pop it from the vector
			currentWord.addByte(topComparison.byteComparison);
			currentWord.addSuccessIndex(topComparison.comparisonResult);
			currentWord.setStartIndex(currentFirstColumn);
			currentWord.setEndIndex(currentFirstColumn);
			//Pop byte from the vector
			currentVector.erase(currentVector.begin());

			//First of all, we join in the word all bytes that were related to the same compare instruction (they came from the same heuristic)
			for (int jj = currentFirstColumn + 1; jj < matrixLength; jj++)
			{
				std::vector<comparison_data_t>& itVector = comparisonMatrix.at(jj);
				if (itVector.empty())
				{
					break;
				}
				comparison_data_t& data = itVector.front();
				if (data.heuristicValue == topComparison.heuristicValue)
				{
					//It came from the same heuristic
					currentWord.addByte(data.byteComparison);
					currentWord.addSuccessIndex(data.comparisonResult);
					currentWord.setEndIndex(jj);

					//We are considering delimiters to be 1-byte long. So if the comparison is >1 byte long already, it is a keyword
					currentWord.setWordType(ProtocolWord::KEYWORD);
					LOG_DEBUG("Next byte is from the same heuristic, so joined it with the last byte(s)");

					//Pop byte from the vector
					itVector.erase(itVector.begin());
				}
				else
				{
					//The bytes from the same heuristic must follow each other in the buffer. If this one did not meet that, we stop searching already
				}
			}

			//Now we start looking for either delimeter or keyword types
			LOG_DEBUG("Calculating word starting at netbuffer[" << currentFirstColumn << "], COMPVALUE:" << topComparison.byteComparison);

			//We check the result
			if (topComparison.comparisonResult == 0)
			{
				LOG_DEBUG("Failed comparison");
				//Failed comparison
				//Either missed delimeter or (failed) keyword check
				//Let's check subsequent bytes to see if it is a delimeter
				if (currentFirstColumn + 1 == matrixLength)
				{
					//Means this is the last byte of the buffer. It might be a delimiter checked for the last byte,
					//or maybe a keyword. We will be considering it a keyword however, since most delimeters will need to iterate over the buffer
					currentWord = ProtocolWord(topComparison.byteComparison, currentFirstColumn, currentWord.getEndIndex(), ProtocolWord::KEYWORD, topComparison.comparisonResult);
					buf.addWordToWordVector(currentWord);
					//Value poped already
					LOG_DEBUG("netbuffer[" << currentFirstColumn << "] is empty, and it was the very last byte, so SEPARATORLASTBYTE");

					//We have finished this comparison, but there might be more in the current column
					continue;
				}
				else
				{
					//It is not the last byte of the buffer, so let's check the next bytes at the buffer
					//If the next bytes of the buffer have the same bytes in the comparison, then this is
					//highly likely a delimeter, but we need to see if there is a success comparison at some point
					//(the byte at which the program finds the delimeter).
					//If the next bytes are do not have the same value in the comparisons, this might be a keyword
					//(which failed), and we might join the next bytes in the same keyword too.

					LOG_DEBUG("Starting to check next bytes in the buffer...");
					for (int jj = currentWord.getEndIndex() + 1; jj < matrixLength; jj++)
					{
						LOG_DEBUG("Now checking byte at index "<<jj);
						std::vector<comparison_data_t>& itVector = comparisonMatrix.at(jj);
						if (itVector.empty())
						{
							//Nothing in the next bytes... 
							
							if (currentWord.getWordType() != ProtocolWord::UNDEFINED)
							{
								//If we have identified this word before as a delimeter or something, just insert it and that's it
								//It ended at the previous byte
								currentWord = ProtocolWord(currentWord.getAllBytes(), currentFirstColumn, jj - 1, currentWord.getWordType(), currentWord.getSuccessIndexes());
								buf.addWordToWordVector(currentWord);
								LOG_DEBUG("Empty column at netbuffer[" << jj << "] is empty, storing the word of length "<< currentWord.getAllBytes().size()<<" until this point: "<<currentWord.toString());
								//No value, no pop
								
								break; //Quit loop, word defined, go to next comparison in buffer
							}
							else
							{
								//It was a 1-byte check, since we did not identify the type yet.
								//Let's just say it was a keyword check, of a single byte, we are not too sure, so save that info too
								currentWord = ProtocolWord(topComparison.byteComparison, currentFirstColumn, jj - 1, ProtocolWord::BYTEKEYWORD, topComparison.comparisonResult);
								buf.addWordToWordVector(currentWord);
								LOG_DEBUG("Empty column at netbuffer[" << jj << "] is empty, and nothing to store, saving BYTEKEYWORD: "<<currentWord.toString());
								//No value, no pops
								break; //Quit loop, word defined, go to next comparison in buffer
							}
						}
						else
						{
							//We've got some comparison for this byte
							//Get the value of the topmost comparison at the byte
							const comparison_data_t& itComparison = itVector.front();

							//If they are not from the same heuristic, let's try to join the values still:
							//NOTE: Multi-byte delimeters not considered
							if (itComparison.byteComparison == topComparison.byteComparison)
							{
								//This is highly likely a delimiter, since it's the same byte as before
								//Check if this time it was a success
								if (itComparison.comparisonResult == 0)
								{
									//It was a fail again
									//This looks like a delimeter, but we need to wait for a success condition to say so
									//For now, mark it as a delimeter without success clause
									currentWord.setWordType(ProtocolWord::FAILEDDELIMETER);
									currentWord.addByte(itComparison.byteComparison);
									currentWord.addSuccessIndex(itComparison.comparisonResult);
									LOG_DEBUG("Next byte is the same as the last one, and a failed comp. Storing:" << currentWord.toString());
									//Pop byte it from the vector
									itVector.erase(itVector.begin());

									//Continue iterating to next buffer byte to see the type of the word
								}
								else
								{
									//Now the comparison succeeded
									//It is almost surely a delimeter. Add the last byte and insert the word already
									currentWord.addByte(itComparison.byteComparison);
									currentWord.addSuccessIndex(itComparison.comparisonResult);
									currentWord = ProtocolWord(currentWord.getAllBytes(), currentFirstColumn, jj, ProtocolWord::DELIMETER, currentWord.getSuccessIndexes());
									buf.addWordToWordVector(currentWord);
									LOG_DEBUG("Next byte is the same as the last one, and a successful comp. Storing:" << currentWord.toString());
									//Pop byte it from the vector
									itVector.erase(itVector.begin());
									break; //Quit loop, word defined, go to next comparison in buffer
								}
							}
							else
							{
								//The byte is not the same as the one before. The previous byte might have been part of a keyword then
								//Save word as keyword and try so search for more bytes.
								currentWord.addByte(itComparison.byteComparison);
								currentWord.addSuccessIndex(itComparison.comparisonResult);
								LOG_DEBUG("Next byte is NOT the same as the last one. Saving last byte as  part of KEYWORD. Storing:" << currentWord.toString());
								currentWord.setWordType(ProtocolWord::KEYWORD);
								//Pop byte it from the vector
								itVector.erase(itVector.begin());

								//Continue iterating to next buffer byte to search for the rest of bytes of the word
							}
						}
					}
				}
			}
			else
			{
				LOG_DEBUG("Successful comparison");
				//The comparison was a success.
				//It might be a keyword (which succeeded) or a delimeter with succeded for the very first byte
				//However it does not make much sense to have a delimeter succeeding at the first byte of its checking, so let's consider it a keyword
				//and later try to join it with others.
				currentWord = ProtocolWord(topComparison.byteComparison, currentFirstColumn, currentFirstColumn, ProtocolWord::KEYWORD, topComparison.comparisonResult);
				buf.addWordToWordVector(currentWord);
				LOG_DEBUG("Storing: " << currentWord.toString());
				//Value poped already
			}

		} //end while all bytes of the protocol netbuffer

		//Finally, try to join the keywords
		/*std::vector<ProtocolWord>& wordVector = buf.getWordVector();
		for (int ii=0; ii<wordVector.size(); ii++)
		{
			ProtocolWord& word = wordVector.at(ii);
			if (word.getWordType() == ProtocolWord::BYTEKEYWORD)
			{
				//Try and check if the next keywords can be joined
				int nextKeywordIndex = ii + 1;
				while(nextKeywordIndex < wordVector.size()) //We are reducing the size of the wordVector in each iteration
				{
					ProtocolWord& wordIt = wordVector.at(nextKeywordIndex);
					if (word.getWordType() == ProtocolWord::BYTEKEYWORD)
					{
						//If the keywords are placed in sequential bytes in the netbuffer, and both had the same result
						if (word.getEndIndex() == wordIt.getStartIndex() &&
							word.getSuccessIndexes().at(0) == wordIt.getSuccessIndexes().at(0))
						{
							//We can join keywords
							word.addByte(wordIt.getAllBytes().at(0));
							word.addSuccessIndex(wordIt.getSuccessIndexes().at(0));
							wordVector.erase(wordVector.begin() + nextKeywordIndex);
						}
					}
					nextKeywordIndex++;
				}
			}
		}*/

	} //finished parsing for all protocol netbuffers

	//Test
	for (ProtocolNetworkBuffer& buf : protocol.getNetworkBufferVector())
	{
		LOG_DEBUG("NETWORKBUFFER of len:"<< buf.getWordVector().size());
		for (ProtocolWord& word : buf.getWordVector())
		{
			LOG_DEBUG(word.toString());
		}
	}

}