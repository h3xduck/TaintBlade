#include "HeuristicsValidator.h"

#define H_MARK \
	"[H:" << ii << "/" << HLComparison::getRevHeuristicNumber() << " | I:" << jj+1 << "/" << atomSize << "] "

#define H_MARK_i \
	"[H:" << ii << "/" << HLComparison::getRevHeuristicNumber() << " | I:" << jj+1 << "/" << atomSize << " | i:" << currentInstructionIndex+1 << "] "

#if(HEURISTIC_DEBUG==1)
#define LOG_REV_DEBUG_noh(log) \
	LOG_DEBUG(log)
#define LOG_REV_DEBUG(log) \
	LOG_DEBUG(H_MARK log)
#define LOG_REV_DEBUG_i(log) \
	LOG_DEBUG(H_MARK_i log)
#else
#define LOG_REV_DEBUG_noh(log)
#define LOG_REV_DEBUG(log)
#define LOG_REV_DEBUG_i(log)
#endif

HLComparison REVERSING::HEURISTICS::checkValidity(RevLog<RevAtom> *revLog)
{
	if (HLComparison::getInternalRevHeuristic().empty())
	{
		HLComparison::initializeRevHeuristic();
		LOG_DEBUG("Heuristics for HLComparison initialized");
	}

	std::vector<RevAtom> atomVec = REVERSING::HEURISTICS::checkHeuristicAlgNRS(revLog);
	if (atomVec.empty())
	{
		return HLComparison();
	}
	else
	{
		HLComparison hl(atomVec);
		//Calculate the comparison values (and its result) based on the loaded atoms
		hl.calculateHLOperationFromLoadedAtoms();
		hl.setHeuristicMet(1);
		return hl;
	}
}

int REVERSING::HEURISTICS::quickAtomicCompare(RevAtom atom1, RevHeuristicAtom hAtom2)
{
	RevHeuristicAtom* internalhAtom1 = atom1.getRevHeuristicAtom();

	if (atom1.getInstType() != hAtom2.instType)
	{
		//LOG_DEBUG("Quick compare, not same instruction: "<<atom1.getInstType()<<" : "<<hAtom2.instType);
		return 0;
	}

	if (atom1.getOperandsType() == RevHeuristicAtom::INVALID)
	{
		//LOG_DEBUG("Quick compare, invalid operands for instruction");
		return 0;
	}

	if (!internalhAtom1->containtedIn(hAtom2))
	{
		//LOG_DEBUG("Quick compare, heuristic not contained in the other ");
		return 0;
	}

	return 1;
}

/**
Returns whether a given color is in a vector of colors
*/
int isColorInVector(UINT16 color, std::vector<UINT16>& vec)
{
	return std::find(vec.begin(), vec.end(), color) != vec.end();
}

/**
Returns whether any color in a vector is contained in the other
*/
int isAnyColorInVector(std::vector<UINT16>& colors, std::vector<UINT16>& vec)
{
	for (const UINT16& color : colors)
	{
		//LOG_DEBUG("Checking color" << color);
		//If any of the colors is contained in the vector, then the heuristic is valid
		if (isColorInVector(color, vec))
		{
			return 1;
		}
	}
	return 0;
}

std::vector<RevAtom> REVERSING::HEURISTICS::checkHeuristicAlgNRS(RevLog<RevAtom> *revLog)
{
	//Result vector
	std::vector<RevAtom> resAtomVec(0);

	//We must check whether the revLog corresponds to any of the hardcoded heuristics
	std::vector<RevAtom> revLogVector = revLog->getLogVector();
	const size_t atomSize = revLogVector.size();
	
	//LOG_REV_DEBUG_noh("Started heuristic validation, RevLog size: " << atomSize);

	for (int ii = HLComparison::getRevHeuristicNumber(); ii > 0; ii--)
	{
		LOG_REV_DEBUG_noh(">> Starting to check heuristic " << ii << "/"<<HLComparison::getRevHeuristicNumber());
		RevHeuristic heuristic = HLComparison::getInternalRevHeuristic().at(ii - 1);
		std::vector<RevHeuristicAtom> atomHeuristicVector = heuristic.getAtomVector();

		//Number of instructions in the heuristic to meet to consider it met (the full length of it)
		const int heuristicLength = atomHeuristicVector.size();
		int numberInstructionsMet = 0;
		
		//Check heuristic with every single (consequent) combination of instructions, going back in time
		
		//Since we received a vector of all tainted instructions, some sequence may meet the heuristic but have a
		//tainted instruction in the middle. If this is the case, we must be able to skip it. The counter is for that.
		//int skippedInstructions = 0;
		for (int jj = atomSize - 1; jj >= 0; jj--)
		{
			LOG_REV_DEBUG("Starting with instruction at "<<to_hex_dbg(revLogVector.at(jj).getBaseAddress()));

			RevAtom atom = revLogVector.at(jj);
			if (atomHeuristicVector.size() > revLogVector.size())
			{
				//The heuristic is longer than the vector, just quit and go for the next heuristic
				LOG_REV_DEBUG("The heuristic is longer than the vector");
				numberInstructionsMet = 0;
				break;
			}

			/* (Test)
				if (atom.getInstType() == XED_ICLASS_CMP)
			{
				RevDataAtom* dataAtom = atom.getRevDataAtom();
				std::vector<UINT8> flags = dataAtom->getFlagsValue();
				LOG_REV_DEBUG_noh("Flags:: CF:" << to_hex_dbg((int)flags.at(0)) << " PF:" << to_hex_dbg((int)flags.at(2)) << " AF:" << to_hex_dbg((int)flags.at(4)) << " ZF:" << to_hex_dbg((int)flags.at(6)) << " SF:" << to_hex_dbg((int)flags.at(7)));
			}*/

			RevHeuristicAtom hHeuristicAtom = atomHeuristicVector.back();
			//Quick check just to see if the last instructions are the same, if they are we go ahead and try to check the full heuristic and taint data
			if (REVERSING::HEURISTICS::quickAtomicCompare(atom, hHeuristicAtom))
			{
				LOG_REV_DEBUG("Quick compare step success");
				//Found possible start of heuristic in building block
				//We now go back checking for continuation of the full heuristic 

				//Auxiliary vector for the algorithm of checking the actual taint colors between heuristic atoms
				std::vector<UINT16> runningColorVector;

				//The heuristic seemed to be met, but we need to check the actual colors before drawing a conclusion
				RevColorAtom *colorAtom = atom.getRevColorAtom();
				RevHeuristicAtom *hAtom = atom.getRevHeuristicAtom();
				//We will check the selected elements of the RevHeuristicAtom. For those elements, we will check the colors
				//in the RevColorAtom. Those colors will be stored and subsequent RevAtoms will only be valid for the heuristic
				//if their taint colors are contained in said vector.
				if (hAtom->leaBaseTainted) runningColorVector.push_back(colorAtom->leaBaseColor);
				if (hAtom->leaIndexTainted) runningColorVector.push_back(colorAtom->leaIndexColor);
				if (hAtom->memDestTainted)
				{
					for (UINT16& color : colorAtom->memDestColor)
					{
						runningColorVector.push_back(color);
					}
				}
				if (hAtom->memSrcTainted)
				{
					for (UINT16& color : colorAtom->memSrcColor)
					{
						runningColorVector.push_back(color);
					}
				}
				if (hAtom->regDestTainted)
				{
					for (UINT16& color : colorAtom->regDestColor)
					{
						runningColorVector.push_back(color);
					}
				}
				if (hAtom->regSrcTainted)
				{
					for (UINT16& color : colorAtom->regSrcColor)
					{
						runningColorVector.push_back(color);
					}
				}

				if (!runningColorVector.empty())
				{
					LOG_REV_DEBUG_noh("Instruction has taint colors: ");
					for (UINT16& color : runningColorVector)
					{
						LOG_REV_DEBUG_noh(color);
					}
				}
				else
				{
					LOG_ERR("No color found for the instruction. This should not have happened");
				}

				//Delete duplicates
				std::sort(runningColorVector.begin(), runningColorVector.end());
				runningColorVector.erase(std::unique(runningColorVector.begin(), runningColorVector.end()), runningColorVector.end());

				//Now we get the full vector will all taint colors, including the parent colors from which
				//these colors were derived (and which are considered to be the same for the heuristic).
				int initialSize = runningColorVector.size();
				for (int it=0; it < initialSize; it++)
				{
					const UINT16& color = runningColorVector.at(it);
					LOG_REV_DEBUG("Getting parents of color: " << color);
					//For every color that is its parent, we store it in our vector
					std::vector<UINT16> resVec = taintManager.getController().getColorParents(color);
					for (UINT16& c : resVec)
					{
						LOG_REV_DEBUG("Storing color in runningColorVector: "<<c);
						runningColorVector.push_back(c);
					}
				}

				//Delete duplicates (shouldn't be any, but just in case)
				std::sort(runningColorVector.begin(), runningColorVector.end());
				runningColorVector.erase(std::unique(runningColorVector.begin(), runningColorVector.end()), runningColorVector.end());

				//Now we have a vector will all the colors that are related to the current atom. 
				//We will now check the heuristic, checking the previous instructions

				//Position inside the sequence of instructions atoms, starting at position jj going backwards
				int currentInstructionIndex = jj;
				//Position inside the sequence of heuristic atoms in the current heuristic ii
				int currentHeuristicPosition = heuristicLength - 1;
				while (currentInstructionIndex >= 0)
				{
					LOG_REV_DEBUG_i("Comparing heuristic with instruction at position: " << currentInstructionIndex+1 << " (1-" << atomSize <<")");

					//Check if the heuristic already found a hit at this point, if it did, halt
					if (revLog->getHeuristicLastHitIndex(ii - 1) >= currentInstructionIndex)
					{
						//Go to next heuristic
						LOG_REV_DEBUG_i("Heuristic check halted at instruction position " << currentInstructionIndex+1 << " because of a previous hit");
						resAtomVec.clear();
						goto endOfHeuristic;
					}

					//We start from the back, going backwards
					RevAtom itAtom = revLogVector.at(currentInstructionIndex);
					RevHeuristicAtom *itHAtom = itAtom.getRevHeuristicAtom();
					RevHeuristicAtom itHeuristicAtom = atomHeuristicVector.at(currentHeuristicPosition);
					if (!REVERSING::HEURISTICS::quickAtomicCompare(itAtom, itHeuristicAtom))
					{
						//Might be an instruction interleaved but the heuristic can still be met.
						//Skip the instruction and go for the next
						LOG_REV_DEBUG_i("Skipped due to quick compare");
						currentInstructionIndex--;
						continue;
					}

					LOG_REV_DEBUG_i("Started deep heuristic check");
					//It seemed to be met, now check the actual colors using the vector we extracted before
					//The colors must be contained in said vector.
					//We check the values that MUST be tainted in the heuristic
					RevColorAtom* itColorAtom = itAtom.getRevColorAtom();
					//Same for the rest
					if (itHeuristicAtom.leaBaseTainted)
					{
						if (isColorInVector(itColorAtom->leaBaseColor, runningColorVector))
						{
							//Could not find color in vector.
							LOG_REV_DEBUG_i("Skipped due to leaBase");
							currentInstructionIndex--;
							continue;
						}
						//Found the color in the previous instruction. Alright
					}
					if (itHeuristicAtom.leaIndexTainted)
					{
						if (isColorInVector(itColorAtom->leaIndexColor, runningColorVector))
						{
							LOG_REV_DEBUG_i("Skipped due to leaIndex");
							currentInstructionIndex--;
							continue;
						}
					}
					if (itHeuristicAtom.memDestTainted)
					{
						if (!isAnyColorInVector(itColorAtom->memDestColor, runningColorVector))
						{
							LOG_REV_DEBUG_i("Skipped due to memDest");
							currentInstructionIndex--;
							continue;
						}
					}
					if (itHeuristicAtom.memSrcTainted)
					{
						if (!isAnyColorInVector(itColorAtom->memSrcColor, runningColorVector)) 
						{
							LOG_REV_DEBUG_i("Skipped due to memSrc");
							currentInstructionIndex--;
							continue;
						}
					}
					if (itHeuristicAtom.regDestTainted)
					{
						if (!isAnyColorInVector(itColorAtom->regDestColor, runningColorVector)) 
						{
							LOG_REV_DEBUG_i("Skipped due regDest");
							currentInstructionIndex--;
							continue;
						}
					}
					if (itHeuristicAtom.regSrcTainted)
					{
						if (!isAnyColorInVector(itColorAtom->regSrcColor, runningColorVector)) 
						{
							LOG_REV_DEBUG_i("Skipped due to regSrc");
							currentInstructionIndex--;
							continue;
						}
					}

					//No need for any more imm checks

					//If we are here, the heuristic was met for this instruction atom
					//It must be met for all, so just continue to the next one
					LOG_REV_DEBUG_i("Atom met the heuristic");
					resAtomVec.push_back(itAtom);
					numberInstructionsMet++;

					if (numberInstructionsMet == heuristicLength)
					{
						//We already have the full heuristic, so halt all comparisons
						LOG_REV_DEBUG_i("Heuristic completed");
						//Mark the heuristic match
						revLog->setHeutisticLastHit(ii - 1, currentInstructionIndex);
						break; // == goto endOfSequence;
					}

					currentInstructionIndex--;
					currentHeuristicPosition--;

				} //end of sequence of instructions
				LOG_REV_DEBUG("Reached the end of the RevLog at heuristic "<<ii);

			}
			else
			{
				//Failed the quick check
				numberInstructionsMet = 0;
				resAtomVec.clear();
				LOG_REV_DEBUG("Failed quickCompare");
			}

		endOfSequence:
			//Next instruction in the sequence, going backwards

			LOG_REV_DEBUG("Currently met " << numberInstructionsMet << "/" << heuristicLength << " atoms of the heuristic");

			//Check if we finished
			if (numberInstructionsMet == heuristicLength)
			{
				//If we reached this point, the heuristic was met for all instructions. So we met the heuristic itself
				//with all the atoms that we have found
				LOG_REV_DEBUG("HEURISTIC " << ii << " FULLY MET!");
				return resAtomVec;
			}

			//Reset number of heuristic atoms met, since we will go check another sequence starting at another position
			numberInstructionsMet = 0;
			resAtomVec.clear();

			LOG_REV_DEBUG("Finished checking heuristic starting at index " << jj);

		} //end of checking one heuristic starting at one instruction

	endOfHeuristic:
		//Next heuristic
		{}

	} //end of all heuristics

	//Return empty vector
	return std::vector<RevAtom>();
}