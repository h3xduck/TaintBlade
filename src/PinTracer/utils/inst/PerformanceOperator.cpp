#include "PerformanceOperator.h"
#include "../io/log.h"
#include "../io/format.h"

time_t PerformanceOperator::beginChrono;
time_t PerformanceOperator::endChrono;

void PerformanceOperator::startChrono()
{
	time(&PerformanceOperator::beginChrono);
}

void PerformanceOperator::measureChrono()
{
	time(&PerformanceOperator::endChrono);
	double dif = difftime(PerformanceOperator::endChrono, PerformanceOperator::beginChrono);
	LOG_DEBUG("Elapsed: " << dif << " seconds.");
}

void PerformanceOperator::incrementInstructionCounter()
{
	PerformanceOperator::instructionCounter++;
	if (instructionCounter % milestone == 0)
	{
		LOG_DEBUG("Milestone: " << PerformanceOperator::instructionCounter << " instructions executed");
		measureChrono();
	}
}