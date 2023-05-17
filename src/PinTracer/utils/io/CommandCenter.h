#ifndef _COMMAND_CENTER_H_
#define _COMMAND_CENTER_H_

#include "pin.H"
#include "../../config/Command.h"
#include "log.h"
#include <iostream>
#include <fstream> 
#include <sstream>
#include <string>

namespace UTILS
{
	namespace IO 
	{
		namespace CommandCenter
		{
			/**
			Number of milliseconds between each query of command
			*/
			const UINT32 MILLIS_PERIOD_QUERY_COMMAND = 5000;

			/**
			Checks whether the string corresponds to a known command and, if so, executes it
			*/
			void executeCommand(std::string command);

			/**
			Periodically checks whether there is a command available to be executed.
			If there is, it executes it and removes it from the file.
			*/
			void queryCommandAvailable(VOID* arg);

			/**
			Starts a background threat that periodically queries whether there exists any command 
			that was entered by the user, and executes it if there is.
			*/
			void startCommandCenterJob();

			/**
			Registers a timer which, after waiting for the specified time, will stop the tracer execution
			*/
			void registerAnalysisTimeout(UINT32 millis);
		};
	}
}


#endif