#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

#include "ProtocolNetworkBuffer.h"

namespace REVERSING
{
	namespace PROTOCOL
	{
		class Protocol
		{
		private:
			std::vector<ProtocolNetworkBuffer> networkBufferVector;
		public:
			std::vector<ProtocolNetworkBuffer> getNetworkBufferVector();
			void addBufferToNetworkBufferVector(ProtocolNetworkBuffer buf);
			int getNumberProtocolsStored();
		};

	}
}




#endif