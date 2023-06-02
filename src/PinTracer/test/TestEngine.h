#ifndef _TESTENGINE_H_
#define _TESTENGINE_H_

#include <iostream>
#include <vector>
#include "TestMilestone.h"
#include "Test.h"
#include <fstream>
#include <sstream>
#include <string>
#include "../utils/io/log.h"
#include <memory>
#include <cstdlib>

#ifndef _WINDOWS_HEADERS_H_
#define _WINDOWS_HEADERS_H_
#define _WINDOWS_H_PATH_ C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um
namespace WINDOWS
{
#include <windows.h>
#include <WinSock2.h>
}
#endif

class TestEngine
{
public:
	enum testlevel_t
	{
		NONE,
		ACTIVE
	};

private:
	testlevel_t testLevel = NONE;

	/**
	Set of tests registered in the testEngine, read from file specified by user
	*/
	std::vector<Test> testSet;

	/**
	Set of milestones that occured during the program execution
	*/
	std::vector<TestMilestone*> milestoneLog;

	const std::string TEST_START_LINE = "TESTSTART";
	const std::string TEST_END_LINE = "TESTEND";

	void parseTestLine();

public:
	TestEngine() {};

	testlevel_t getTestLevel();

	void setTestLevel(testlevel_t level);

	void addTest(Test test);

	void cleanTestSet();

	void logMilestone(TestMilestone* milestone);

	void cleanMilestoneLog();

	void loadTestsFromFile(std::string testFile);

	/**
	Evaluates all the tests, yields final results using the logged milestone data
	*/
	void evaluateTests();

	

};


#endif