#ifndef _TEST_H_
#define _TEST_H_

#include <iostream>
#include <vector>
#include "TestMilestone.h"
#include "../utils/io/log.h"
#include "HeuristicMilestone.h"

class Test
{
public:
	enum test_state_t
	{
		FAILED,
		SUCCESS
	};

private:
	std::vector<TestMilestone*> milestoneSet;
	std::string name;
	test_state_t state;

public:
	Test(std::string name) 
	{
		this->name = name;
	}

	Test(std::string name, std::vector<TestMilestone*> milestones)
	{
		this->milestoneSet = milestones;
		this->name = name;
	}

	void addMilestone(TestMilestone* milestone)
	{
		if (milestone->getType() == TestMilestone::HEURISTIC)
		{
			HeuristicMilestone* hMilestone = new HeuristicMilestone(*static_cast<HeuristicMilestone*>(milestone));
			this->milestoneSet.push_back(hMilestone);
		}
		else
		{
			LOG_DEBUG("Tried to add unknown type of milestone into test");
		}
	}

	test_state_t getTestResults()
	{
		for (TestMilestone *elem : this->milestoneSet)
		{
			if (elem->getState() == TestMilestone::UNCOMPLETED)
			{
				return this->FAILED;
			}
		}

		return this->SUCCESS;
	}

	int isCompleted()
	{
		for (auto& elem : this->milestoneSet)
		{
			if (elem->getState() == TestMilestone::UNCOMPLETED)
			{
				return 0;
			}
		}
		return 1;
	}

	/**
	Returns first uncompleted milestone of the test.
	Should include a call for istestcompleted() before
	*/
	TestMilestone* getFirstUncompletedMilestone()
	{
		for (auto *elem : this->milestoneSet)
		{
			if (elem->getState() == TestMilestone::UNCOMPLETED)
			{
				return elem;
			}
		}

		return NULL;
	}


	/**
	Evaluates whether a milestone is contained in this test.
	Milestones are evaluated orderly.
	For this test, we pass a HeuristicMilestone and check whether the milestone corresponds to that set of operations.
	
	If it does, it marks the test milestone of the test as completed and return 1. Otherwise, returns 0.
	*/
	int evaluateMilestone(HeuristicMilestone heuristic)
	{
		if (this->isCompleted())
		{
			//Test completed
			return 1;
		}
		
		TestMilestone *milestone = this->getFirstUncompletedMilestone();
		if (milestone->getType() == TestMilestone::HEURISTIC)
		{
			HeuristicMilestone *hMilestone = static_cast<HeuristicMilestone*>(milestone);
			TestMilestone::milestone_state_t res = hMilestone->evaluate(heuristic.getInstVector());
			if (res == TestMilestone::COMPLETED)
			{
				return 1;
			}
		}
		else
		{
			LOG_DEBUG("Tried to evaluate an unknown milestone type at a test");
		}

		return 0;
	}

	std::string getName()
	{
		return this->name;
	}

};


#endif