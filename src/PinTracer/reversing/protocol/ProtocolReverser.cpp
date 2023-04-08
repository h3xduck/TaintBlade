#include "ProtocolReverser.h"

extern Context ctx;

void REVERSING::PROTOCOL::reverseProtocol()
{
	//First we get the heuristics. They must be there already at this point
	RevLog<HLComparison> heuristicsVec = ctx.getRevContext()->getHeuristicsVector();

	//Get list of original colors (tainted by rules) with the memory addresses they 
	//were initially related to
	std::vector<std::pair<UINT16, TagLog::original_color_data_t>> orgVec = taintManager.getController().getOriginalColorsVector();

	//Now we must build the original buffers from this data


}