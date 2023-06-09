#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>
#include "ProtocolBuffer.h"

namespace PROTOCOL
{
	class Protocol
	{
	private:
		std::vector<std::shared_ptr<ProtocolBuffer>> bufferVector_;

	public:
		Protocol()
		{
			this->bufferVector_ = std::vector<std::shared_ptr<ProtocolBuffer>>();
		}

		std::vector<std::shared_ptr<ProtocolBuffer>>& bufferVector() { return this->bufferVector_; }
	};
}

#endif