#include "TestEngine.h"

TestEngine globalTestEngine;

TestEngine::testlevel_t TestEngine::getTestLevel()
{
	return this->testLevel;
}

void TestEngine::setTestLevel(testlevel_t level)
{
	this->testLevel = level;
}

void TestEngine::addTest(Test test)
{
	this->testSet.push_back(test);
}

void TestEngine::cleanTestSet()
{
	this->testSet.clear();
}

void TestEngine::logMilestone(TestMilestone* milestone)
{
	if(milestone->getType() == TestMilestone::HEURISTIC)
	{
		HeuristicMilestone* heuristicMilestone = new HeuristicMilestone(*static_cast<HeuristicMilestone*>(milestone));
		this->milestoneLog.push_back(heuristicMilestone);
	}
	else
	{
		LOG_DEBUG("Tried to log unknown type of milestone into test engine");
	}
}

void TestEngine::cleanMilestoneLog()
{
	for (TestMilestone* milestone : this->milestoneLog)
	{
		delete milestone;
	}
	this->milestoneLog.clear();
}

void TestEngine::loadTestsFromFile(std::string testFile)
{
	LOG_DEBUG("Loading tests from " << testFile);
	std::ifstream infile(testFile);
	std::string line;
	int loadedTestCounter = 0;
	//Read TEST block
	while (std::getline(infile, line))
	{
		if (line == this->TEST_START_LINE)
		{
			//First line is the name of the test
			std::getline(infile, line);
			Test test(line);

			int loadedMilestoneCounter = 0;
			// Parse lines until finding ENDLINE
			while (std::getline(infile, line))
			{
				if (line == this->TEST_END_LINE)
				{
					LOG_DEBUG("Added test " << loadedTestCounter << ", loaded milestones: " << loadedMilestoneCounter);
					break;
				}
				else
				{
					//Parse milestone. e.g.: H CMP ADD
					const std::string milestoneType = line.substr(0, 1);
					if (milestoneType == "H")
					{
						//Heuristic milestone
						const std::string milestoneData = line.substr(2, line.length());
						std::istringstream isdata(milestoneData);
						std::string token;

						//List of instruction types for the heuristic
						while (std::getline(isdata, token, ' ')) {
							LOG_DEBUG("Extracting instruction types: "<<token);
							HeuristicMilestone milestone = HeuristicMilestone(token, TestMilestone::HEURISTIC);
							test.addMilestone(&milestone);
							loadedMilestoneCounter++;
						}
					}
					
				}
			}

			//Add test to set
			this->addTest(test);
			loadedTestCounter++;
		}
		else
		{
			LOG_ALERT("Failed to load tests");
			return;
		}	
	}

	LOG_DEBUG("Finished adding tests, loaded tests: " << loadedTestCounter);
	std::cerr << "Loaded tests : " << loadedTestCounter << std::endl;
}


void TestEngine::evaluateTests()
{
	LOG_DEBUG("Evaluating tests");

	int testCounter = 0;
	for (Test test : this->testSet)
	{
		LOG_DEBUG("Evaluating test " << testCounter);
		//For each test, evaluate the milestone log
		int milestoneCounter = 0;
		for (TestMilestone *milestone : this->milestoneLog)
		{
			if (milestone->getType() == TestMilestone::HEURISTIC)
			{
				LOG_DEBUG("Evaluating milestone " << milestoneCounter)
				HeuristicMilestone* hmilestone = static_cast<HeuristicMilestone*>(milestone);
				//LOG_DEBUG("Milestone inst len: " << hmilestone->getInstVector().size());
				int res = test.evaluateMilestone(*hmilestone);
				if (res)
				{
					LOG_DEBUG("Milestone fulfilled!");
				}
			}
			milestoneCounter++;
		}
		testCounter++;
	}

	//Now that we checked all milestones, we must get the final result of the tests
	for (int ii=0; ii<this->testSet.size(); ii++)
	{
		//10 - green, 12 - red, 15 - white
		WINDOWS::HANDLE hConsole = WINDOWS::GetStdHandle((WINDOWS::DWORD)-11);

		Test test = testSet.at(ii);
		if (test.getTestResults() == Test::SUCCESS)
		{
			WINDOWS::SetConsoleTextAttribute(hConsole, 10);
			std::cerr << "TEST " << ii << " SUCCEEDED - " << test.getName() << std::endl;
			WINDOWS::SetConsoleTextAttribute(hConsole, 15);
		}
		else
		{
			WINDOWS::SetConsoleTextAttribute(hConsole, 12);
			std::cerr << "TEST " << ii << " FAILED - " << test.getName() << std::endl;
			WINDOWS::SetConsoleTextAttribute(hConsole, 15);
		}
	}
}