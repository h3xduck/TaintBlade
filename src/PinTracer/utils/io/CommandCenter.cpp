#include "CommandCenter.h"

//Functions from Core, these are usually called in PIN's Fini function, but we'll force them from here
extern void dumpEndInfo();
extern void resolveProtocol();

void UTILS::IO::CommandCenter::executeCommand(std::string command)
{
    if (command == COMMAND_CALL_APPLICATION_EXIT)
    {
        //Exit app
        LOG_DEBUG("Executed command for application exit");
        dumpEndInfo();
        resolveProtocol();
        PIN_ExitProcess(0);
    }
    else
    {
        LOG_ALERT("Tried to execute an unknown command: " << command);
    }
}

UTILS::IO::CommandCenter::CommandCenter()
{
	
}

void UTILS::IO::CommandCenter::queryCommandAvailable()
{
    this->commandFile.open(PINTOOL_COMMAND_FILE);
    std::string line;
    while (std::getline(this->commandFile, line))
    {
        std::istringstream iss(line);
        //Read a line from the command file
        LOG_DEBUG("Read line from commands file: " << line);
        this->commandFile.close();
        //This erases the file contents
        this->commandFile.open(PINTOOL_COMMAND_FILE, std::ofstream::out | std::ofstream::trunc);
        executeCommand(line);
    }
    this->commandFile.close();
}