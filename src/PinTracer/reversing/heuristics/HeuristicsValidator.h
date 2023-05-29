#ifndef _HEURISTICVALIDATOR_H_
#define _HEURISTICVALIDATOR_H_

#include "HLOperation.h"
#include "HLComparison.h"
#include "HLPointerField.h"
#include "../../taint/core/TaintManager.h"


extern TaintManager taintManager;

namespace REVERSING
{
	namespace HEURISTICS
	{
		/**
		Returns two values:
		- A pointer to a HLOperation if the vector corresponds to one of the heuristics
			describing a high-level comparison instruction. NULL if no heuristic was met.
		- An indicator of the type of heuristic operation found
		The object is an instance of a derived HLOperation type, and should be freed aftwerwards.
		*/
		std::pair<HLOperation*, HLOperation::HL_operation_type_t> checkValidity(RevLog<RevAtom> *revLog);

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
		For every element in the vector, it indicates the type of heuristic detected (comparison, pointer field...)
		*/
		static std::pair<std::vector<RevAtom>, HLOperation::HL_operation_type_t> checkHeuristicAlgNRS(RevLog<RevAtom> *revLog);
	};
};

#endif
