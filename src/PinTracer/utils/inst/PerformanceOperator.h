#ifndef _H_PERFORMANCE_OPERATOR_
#define _H_PERFORMANCE_OPERATOR_

#include <time.h>
#include "pin.H"

namespace PerformanceOperator {
	static ADDRINT instructionCounter;
	const static int milestone = 5000;

	void incrementInstructionCounter();
	
	extern time_t beginChrono;
	extern time_t endChrono;

	void startChrono();
	void measureChrono();

	/**
	This function takes the current image and IP and writes into a file so that
	the state of the program is known
	*/
	void trackCurrentState(INS &ins);

	/**
	Get current time timestamp
	*/
	UINT64 getCurrentTimeTimestamp();
	

};







#endif
