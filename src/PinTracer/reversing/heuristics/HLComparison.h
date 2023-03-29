#ifndef _HLCOMPARISON_H_
#define _HLCOMPARISON_H_

#include <vector>
#include <memory>
#include <iostream>
#include <xed-category-enum.h>
#include "../data/RevAtom.h"
#include "../data/RevLog.h"
#include "../data/RevHeuristic.h"
#include "../../utils/io/log.h"

class HLComparison
{
private:
	
public:
	/**
	Returns a HLComparison instance if the vector corresponds to one of the heuristics
	describing a high-level comparison instruction. Otherwise, null
	*/
	static int checkValidity(std::vector<RevAtom> revLog);
};


#endif
