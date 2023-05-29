#ifndef _REV_CONTEXT_H_
#define _REV_CONTEXT_H_

#include "../data/RevLog.h"
#include "../data/RevAtom.h"
#include "../heuristics/HLComparison.h"
#include "../heuristics/HLPointerField.h"
#include "../../test/TestEngine.h"

class RevContext
{
private:
	/**
	Current list of instructions being analyzed, gets reseted often
	*/
	RevLog<RevAtom> revLogCurrent;

	/**
	List of instructions that were found to correspond to a high-level comparison operation.
	A vector of heuristics.
	*/
	RevLog<HLComparison> revLogComparisonHeuristics;

	/**
	List of instructions that were found to correspond to a high-level pointer field operation.
	A vector of heuristics.
	*/
	RevLog<HLPointerField> revLogPointerFieldHeuristics;

	/**
	An auxiliary RevAtom that is used during instrumentation, used to store
	information available at different steps of the program.
	It may be deleted if no element is tainted or inserted if there are any.
	*/
	RevAtom currentRevAtom;

	/**
	List of memory addresses range
	*/

public:
	RevContext();

	/**
	Inserts a new RevAtom in the current revLog
	*/
	void insertRevLog(RevAtom atom);

	/**
	Gets the current revLog and analyzes the inserted instructions.
	Tries to find whether the sequence corresponds to a high-level instruction.
	
	If it does not correspond to a HL instruction, it just continues.
	Otherwise, it will store the HL instruction into the revLogParsed and empty the
	current revLogCurrent.
	*/
	void operateRevLog();

	/**
	Prints all entries in the revLogCurrent
	*/
	void printRevLogCurrent();

	/**
	Deletes all entries in the revLogCurrent
	*/
	void cleanRevLogCurrent();

	/**
	Deletes first x elements in the revLogCurrent
	*/
	void cleanRangeRevLogCurrent(int x);

	/**
	Prints all heuristics found during the program execution
	*/
	void printRevLogHeuristics();

	/**
	Returns auxiliary RevAtom used during instrumentation
	*/
	RevAtom* getCurrentRevAtom();

	/**
	Cleans all values from the auxiliary RevAtom
	*/
	void cleanCurrentRevAtom();

	/**
	Returns length of the RevLog vector
	*/
	int getRevLogCurrentLength();

	/**
	Writes all the heuristics found during the execution of the program to a file
	*/
	void dumpFoundHeuristics();

	/**
	Returns the vector of all comparison heuristics found during the program execution
	*/
	RevLog<HLComparison>& getComparisonHeuristicsVector();

	/**
	Returns the vector of all comparison heuristics found during the program execution
	*/
	RevLog<HLPointerField>& getPointerFieldHeuristicsVector();

};

#endif