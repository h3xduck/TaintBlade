#ifndef _HEURISTICVALIDATOR_H_
#define _HEURISTICVALIDATOR_H_

#include "HLComparison.h"
#include "../../taint/core/TaintManager.h"


extern TaintManager taintManager;

namespace REVERSING
{
	namespace HEURISTICS
	{
		/**
		Returns a HLComparison instance if the vector corresponds to one of the heuristics
		describing a high-level comparison instruction.
		*/
		HLComparison checkValidity(RevLog<RevAtom> *revLog);

		/**
		Compares a RevAtom with a certain RevHeuristicAtom.
		This is meant to be a quick check to avoid large computation times, it only checks whether there is
		taint or not, but it does not check the taint colors.
		Returns 1 if the RevAtom corresponds to the heuristic described by the RevHeuristicAtom
		Otherwise, returns 0.
		*/
		int quickAtomicCompare(RevAtom atom, RevHeuristicAtom hAtom);

		/**
		Algorithm for checking an heuristic
		- For all heuristics in the list of heuristics (N)
		- - For all instructions in the RevLog (R)
		- - - For all instructions previous to selected instruction R, 
			check if RevAtom of instruction = RevHeuristicAtom of instruction in heuristic (S)

		Returns vector of RevAtoms found to belong to the RevHeuristic (ignoring any
		RevAtom not included in the heuristic). If heuristic not met, returns empty vector.
		*/
		static std::vector<RevAtom> checkHeuristicAlgNRS(RevLog<RevAtom> *revLog);
	};
};

#endif
