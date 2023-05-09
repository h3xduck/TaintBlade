#ifndef _COMMAND_CENTER_H_
#define _COMMAND_CENTER_

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
		class CommandCenter
		{
		private:
			std::ifstream commandFile;
			void executeCommand();
		public:
			CommandCenter();

			/**
			Checks whether there is a command available to be executed.
			If there is, it executes it and removes it from the file.
			*/
			void queryCommandAvailable();
		};
	}
}


#endif