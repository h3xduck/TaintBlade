#ifndef PROTOCOLPOINTER_H
#define PROTOCOLPOINTER_H

#include <memory>
#include "ProtocolPointerByte.h"

namespace PROTOCOL
{
	class ProtocolPointer
	{
	private:
		std::shared_ptr<ProtocolBuffer> belongingBuffer_;
		std::vector<std::shared_ptr<ProtocolPointerByte>> byteVector_;
		int pointedColor_;
		std::shared_ptr<ProtocolByte> pointedByte_;

	public:
		std::shared_ptr<ProtocolBuffer> belongingBuffer() { return this->belongingBuffer_; }
		std::vector<std::shared_ptr<ProtocolPointerByte>>& byteVector() { return this->byteVector_; }
		int& pointedColor() { return this->pointedColor_; }
		std::shared_ptr<ProtocolByte> pointedByte() { return this->pointedByte_; }
	};
}


#endif