#ifndef _TESTMILESTONE_H_
#define _TESTMILESTONE_H_

#include <iostream>
#include <vector>

class TestMilestone
{
public:
	enum milestone_state_t
	{
		UNCOMPLETED,
		COMPLETED
	};
	enum milestone_type_t
	{
		HEURISTIC,
		UNDEFINED
	};
protected:
	std::string milestoneMsg = "";
	milestone_state_t milestoneState = UNCOMPLETED;
	milestone_type_t milestoneType = UNDEFINED;

public:
	TestMilestone() {};

	TestMilestone(std::string msg)
	{
		this->milestoneMsg = msg;
	}

	TestMilestone(std::string msg, milestone_state_t state)
	{
		this->milestoneMsg = msg;
		this->milestoneState = state;
	}

	TestMilestone(milestone_type_t type)
	{
		this->milestoneType = type;
	}

	std::string getMsg()
	{
		return this->milestoneMsg;
	}

	void setMsg(std::string msg)
	{
		this->milestoneMsg = msg;
	}

	milestone_state_t getState()
	{
		return this->milestoneState;
	}

	void complete()
	{
		this->milestoneState = COMPLETED;
	}

	milestone_type_t getType()
	{
		return this->milestoneType;
	}

	void setType(milestone_type_t type)
	{
		this->milestoneType = type;
	}

};


#endif