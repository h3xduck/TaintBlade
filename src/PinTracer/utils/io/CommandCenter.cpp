#include "CommandCenter.h"

//Functions from Core, these are usually called in PIN's Fini function, but we'll force them from here
extern void dumpEndInfo();
extern void resolveProtocol();

std::ifstream commandFile;

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

void UTILS::IO::CommandCenter::startCommandCenterJob()
{
    THREADID threadId;
    PIN_THREAD_UID threadUid;

    LOG_DEBUG("Starting Command Center job");
    threadId = PIN_SpawnInternalThread(queryCommandAvailable, debugFile, 0, &threadUid);
    
    if (threadId == INVALID_THREADID)
    {
        LOG_ALERT("Unable to start command center job");
        PIN_ExitThread(-1);
    }
    LOG_DEBUG("Successfully started Command Center job");

    //Will not wait for the thread termination, just end the whole process when we are done
    /*BOOL waitStatus = PIN_WaitForThreadTermination(threadUid, PIN_INFINITE_TIMEOUT, 0);
    if (!waitStatus)
    {
        LOG_ALERT("Unable to wait for command center job termination");
        PIN_ExitThread(-1);
    }*/
}

void UTILS::IO::CommandCenter::queryCommandAvailable(VOID* arg)
{
    debugFile = (std::ostream*)(arg);
    
    //For every X seconds, try and see if there are commands to execute
    while (true)
    {
        PIN_Sleep(UTILS::IO::CommandCenter::MILLIS_PERIOD_QUERY_COMMAND);
        LOG_DEBUG("Querying");
        commandFile.open(PINTOOL_COMMAND_FILE);
        std::string line;
        while (std::getline(commandFile, line))
        {
            std::istringstream iss(line);
            //Read a line from the command file
            LOG_DEBUG("Read line from commands file: " << line);
            commandFile.close();
            //This erases the file contents
            commandFile.open(PINTOOL_COMMAND_FILE, std::ofstream::out | std::ofstream::trunc);
            executeCommand(line);
        }
        commandFile.close();
    }
}


void stopAnalysisWithDelay(VOID *arg)
{
    UINT32* millis = static_cast<UINT32*>(arg);
    PIN_Sleep(*millis);
    UTILS::IO::CommandCenter::executeCommand(COMMAND_CALL_APPLICATION_EXIT);
}

void UTILS::IO::CommandCenter::registerAnalysisTimeout(UINT32 millis)
{
    THREADID threadId;
    PIN_THREAD_UID threadUid;

    LOG_DEBUG("Registering analysis timeout after "<<millis<< " milliseconds");
    threadId = PIN_SpawnInternalThread(stopAnalysisWithDelay, &millis, 0, &threadUid);

    if (threadId == INVALID_THREADID)
    {
        LOG_ALERT("Unable to register analysis timeout");
        PIN_ExitThread(-1);
    }
    LOG_DEBUG("Successfully registered timeout");
}