#ifndef PROTOCOLBYTE_H
#define PROTOCOLBYTE_H

#include "ProtocolBuffer.h"
#include <string>

#include <memory>

namespace PROTOCOL
{
	class ProtocolByte
	{
	private:
		std::shared_ptr<ProtocolBuffer> belongingBuffer_;
		int byteOffset_;
		char byteValue_;
		std::string hexValue_;
		int color_;

		struct prot_word_data_t
		{
			int comparisonSuccess;
		}protWordData_;

	public:
		ProtocolByte(ProtocolBuffer* buffer, int offset, char byteValue, std::string hexValue, int color) :
			belongingBuffer_(buffer), byteOffset_(offset), byteValue_(byteValue), hexValue_(hexValue), color_(color) {}

		std::shared_ptr<ProtocolBuffer> belongingBuffer() { return this->belongingBuffer_; }
		int byteOffset() { return this->byteOffset_; }
		char byteValue() { return this->byteValue_; }
		std::string hexValue() { return this->hexValue_; }
		int color() { return this->color_; }
	};
}


#endif
