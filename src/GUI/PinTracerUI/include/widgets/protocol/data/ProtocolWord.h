#ifndef PROTOCOLWORD_H
#define PROTOCOLWORD_H

#include "ProtocolBuffer.h"
#include "ProtocolWordByte.h"
#include <memory>

namespace PROTOCOL
{
	class ProtocolWord
	{
	private:
		std::shared_ptr<ProtocolBuffer> belongingBuffer_;
		std::vector<std::shared_ptr<ProtocolWordByte>> byteVector_;
		int type_;
		int bufferStart_;
		int bufferEnd_;

	public:
		std::shared_ptr<ProtocolBuffer> belongingBuffer() { return this->belongingBuffer_; }
		std::vector<std::shared_ptr<ProtocolWordByte>>& byteVector() { return this->byteVector_; }
		int& type() { return this->type_; }
		int& bufferStart() { return this->bufferStart_; }
		int& bufferEnd() { return this->bufferEnd_; }
	};
}


#endif