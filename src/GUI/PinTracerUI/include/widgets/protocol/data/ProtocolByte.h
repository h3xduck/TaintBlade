#ifndef PROTOCOLBYTE_H
#define PROTOCOLBYTE_H

#include "widgets/protocol/data/ProtocolBuffer.h"
#include <string>

#include <memory>

namespace PROTOCOL
{
	class ProtocolBuffer;
	class ProtocolByte
	{
	public:
		struct taint_lead_t
		{
			int leadClass = 0;
			std::string dllName = "";
			int argNumber = 0;
		};
	private:
		std::shared_ptr<ProtocolBuffer> belongingBuffer_;
		int byteOffset_;
		char byteValue_;
		std::string hexValue_;
		int color_;
		struct taint_lead_t taintLead_;

	public:
		ProtocolByte() {}
		ProtocolByte(std::shared_ptr<ProtocolBuffer> buffer, int offset, char byteValue, std::string hexValue, int color) :
			belongingBuffer_(buffer), byteOffset_(offset), byteValue_(byteValue), hexValue_(hexValue), color_(color) {}

		std::shared_ptr<ProtocolBuffer> belongingBuffer() { return this->belongingBuffer_; }
		int& byteOffset() { return this->byteOffset_; }
		char& byteValue() { return this->byteValue_; }
		std::string hexValue() { return this->hexValue_; }
		int& color() { return this->color_; }
		struct taint_lead_t& taintLead() { return this->taintLead_; }
	};
}


#endif
