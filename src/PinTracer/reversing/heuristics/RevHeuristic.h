#ifndef _REVHEURISTIC_H_
#define _REVHEURISTIC_H_

#include <vector>
#include "../data/RevHeuristicAtom.h"
#include "../data/RevAtom.h"
#include "HLOperation.h"

class RevHeuristic
{
private:
	std::vector<RevHeuristicAtom> atomVector;
	HLOperation::HL_operation_type_t heuristicType_;
public:
	RevHeuristic();
	RevHeuristic(std::vector<RevHeuristicAtom> atoms, HLOperation::HL_operation_type_t opType);
	std::vector<RevHeuristicAtom> getAtomVector();
	//setters and getters
	HLOperation::HL_operation_type_t& heuristicType() { return heuristicType_; }
};


#endif
