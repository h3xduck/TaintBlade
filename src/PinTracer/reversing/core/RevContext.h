#ifndef _REV_CONTEXT_H_
#define _REV_CONTEXT_H_

#include "../data/RevLog.h"
#include "../data/RevAtom.h"
#include "../heuristics/HLComparison.h"

class RevContext
{
private:
	/**
	Current list of instructions being analyzed, gets reseted often
	*/
	RevLog<RevAtom> revLogCurrent;

	/**
	List of instructions that were found to correspond to a high-level operation
	(such as a comparison).
	*/
	RevLog<HLComparison> revLogParsed;

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
	Prints all entries in the revLogParsed
	*/
	void printRevLogParsed();

};

#endif