#ifndef _HEURISTICMILESTONE_H_
#define _HEURISTICMILESTONE_H_

#include "TestMilestone.h"
#include "../reversing/heuristics/HLComparison.h"

class HeuristicMilestone : public TestMilestone
{
private:
	/**
	Describes the instruction types of which the heuristic is made of
	*/
	std::vector<std::string> instVector;
public:
	HeuristicMilestone(std::string inst) : TestMilestone()
	{
		this->instVector = std::vector<std::string>();
		this->instVector.push_back(inst);
	};

	HeuristicMilestone(std::string inst, milestone_type_t type) : TestMilestone()
	{
		this->instVector = std::vector<std::string>();
		this->instVector.push_back(inst);
		this->milestoneType = type;
	};

	HeuristicMilestone(std::vector<std::string> instVector, milestone_type_t type) : TestMilestone()
	{
		this->instVector = instVector;
		this->milestoneType = type;
	};

	milestone_state_t evaluate(std::vector<std::string> hVector)
	{
		//If already completed
		if (this->milestoneState == COMPLETED)
		{
			return this->milestoneState;
		}

		//Compare heuristic vector with the milestone vector
		if (hVector.size() != this->instVector.size())
		{
			LOG_DEBUG(hVector.size() << ":"<<this->instVector.size());
			return UNCOMPLETED;
		}
		for (int ii = 0; ii < hVector.size(); ii++)
		{
			if (hVector.at(ii) != this->instVector.at(ii))
			{
				return UNCOMPLETED;
			}
		}
		this->complete();
		return COMPLETED;
	}

	std::vector<std::string> getInstVector()
	{
		return this->instVector;
	}

};


#endif

