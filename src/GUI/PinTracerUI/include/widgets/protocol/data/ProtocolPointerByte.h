#ifndef PROTOCOLPOINTERBYTE_H
#define PROTOCOLPOINTERBYTE_H

#include "ProtocolBuffer.h"
#include <string>

#include <memory>

namespace PROTOCOL
{
	class ProtocolPointer;
	class ProtocolPointerByte
	{
	private:
		std::shared_ptr<ProtocolPointer> belongingPointer_;
		int byteOffset_;
		char byteValue_;
		int color_;

	public:
		ProtocolPointerByte(std::shared_ptr<ProtocolPointer> pointer, int offset, char byteValue, int color) :
			belongingPointer_(pointer), byteOffset_(offset), byteValue_(byteValue), color_(color) {}

		std::shared_ptr<ProtocolPointer> belongingPointer() { return this->belongingPointer_; }
		int& byteOffset() { return this->byteOffset_; }
		char& byteValue() { return this->byteValue_; }
		int& color() { return this->color_; }
	};
}


#endif
