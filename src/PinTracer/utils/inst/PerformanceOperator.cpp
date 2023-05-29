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
	LOG_DEBUG("Milestone: " << PerformanceOperator::instructionCounter << " instructions executed" << std::endl << "\t|-> " << dif << " seconds.");
}

void PerformanceOperator::incrementInstructionCounter()
{
	PerformanceOperator::instructionCounter++;
	if (instructionCounter % milestone == 0)
	{
		measureChrono();
	}
}

std::ofstream stateTrackerFile;
void PerformanceOperator::trackCurrentState(INS &ins)
{
	if (!stateTrackerFile.is_open())
	{
		stateTrackerFile.open(getFilenameFullName(std::string(STATE_TRACKER_FILE)).c_str(), std::ios_base::out | std::ios_base::trunc);
	}

	ADDRINT addr = INS_Address(ins);
	IMG img = IMG_FindByAddress(addr);
	std::string name;
	if (img.is_valid())
	{
		name = IMG_Name(img);
	}
	else
	{
		name = "INVALID";
	}

	std::stringstream ss;
	ss << to_hex(addr) << ": " << name << std::endl;
	std::string line = ss.str();
	std::streampos pos = stateTrackerFile.tellp();

	stateTrackerFile.seekp(0, std::ios_base::beg);
	stateTrackerFile.write(line.c_str(), line.size());

	// Fill the remaining space with whitespace
	int remaining = line.size() - (pos- stateTrackerFile.tellp());
	if (remaining > 0) {
		for (int j = 0; j < remaining; ++j) {
			stateTrackerFile.put('\0');
		}
	}
}
