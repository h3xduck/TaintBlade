#include "CommandCenter.h"


void UTILS::IO::CommandCenter::executeCommand()
{

}

UTILS::IO::CommandCenter::CommandCenter()
{
	this->commandFile.open(PINTOOL_COMMAND_FILE);
}

void UTILS::IO::CommandCenter::queryCommandAvailable()
{
    std::string line;
    while (std::getline(this->commandFile, line))
    {
        std::istringstream iss(line);
        int a, b;
        if (!(iss >> a >> b)) { break; } // error, or nothing there

        //Read a line from the command file


    }
}