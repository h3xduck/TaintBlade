#include "HLComparison.h"

static const RevHeuristic heuristic[] = {
	RevHeuristic(
		XED_ICLASS_CMP, 0, 0, 0, 0, 0, 0
	)
};


int HLComparison::checkValidity(std::vector<RevAtom> revLog)
{
	//TEST
	LOG_DEBUG(heuristic[0].instType);
	return 0;
}