#ifndef _OPCOMPARISON_H_
#define _OPCOMPARISON_H_

#include "../../data/RevHeuristicAtom.h"
#include "../HLOperation.h"
#include <vector>

namespace REVERSING
{
	namespace HEURISTICS
	{
		namespace OPERATORS
		{
			class OpComparison
			{
			private:
				/**
				This structure contains a vector of vectors, where each vector contains the list of heuristic
				atoms that, together, define a heuristic.
				e.g.:
					{
						{CMP X X, }

					}

				Initialized the first time when needed
				*/
				static std::vector<std::vector<RevHeuristicAtom>> vectorOfAtomVectors;

			public:
				OpComparison();
			};
		}
	}
}



#endif