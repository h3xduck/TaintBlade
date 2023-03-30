#ifndef _REVHEURISTIC_H_
#define _REVHEURISTIC_H_

#include <vector>
#include "../data/RevHeuristicAtom.h"
#include "../data/RevAtom.h"

class RevHeuristic
{
private:
	std::vector<RevHeuristicAtom> atomVector;
public:
	RevHeuristic();
	RevHeuristic(std::vector<RevHeuristicAtom> atoms);
	std::vector<RevHeuristicAtom> getAtomVector();
};


#endif
