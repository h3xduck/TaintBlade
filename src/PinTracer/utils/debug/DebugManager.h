#ifndef _DEBUG_MANAGER_H_
#define _DEBUG_MANAGER_H_

#include "pin.H"
#include "../io/log.h"

/**
This is currently deprecated - not supported by windows unless visual studio
*/
namespace UTILS
{
	namespace DEBUG
	{
		class DebugManager
		{
		public:
            DebugManager() {};

            void connectDebugger()
            {
                if (PIN_GetDebugStatus() != DEBUG_STATUS_UNCONNECTED)
                {
                    LOG_DEBUG("Application debugging is not active");
                    return;
                }

                DEBUG_CONNECTION_INFO info;
                if (!PIN_GetDebugConnectionInfo(&info) || info._type != DEBUG_CONNECTION_TYPE_TCP_SERVER)
                    return;

                LOG_DEBUG("Start debugger and connect to target remote :" << std::dec << info._tcpServer._tcpPort << std::endl);

                if (PIN_WaitForDebuggerToConnect(15000))
                {
                    return;
                }
            }
		};
	}
}


#endif