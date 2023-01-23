#ifndef _H_PERFORMANCE_OPERATOR_
#define _H_PERFORMANCE_OPERATOR_

#include <time.h>

namespace PerformanceOperator {
	static long instructionCounter;
	const static int milestone = 5000;

	void incrementInstructionCounter();
	
	extern time_t beginChrono;
	extern time_t endChrono;

	void startChrono();
	void measureChrono();

};







#endif
