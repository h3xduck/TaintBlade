#ifndef PROTOCOLWORDBYTE_H
#define PROTOCOLWORDBYTE_H

#include "ProtocolBuffer.h"
#include <string>

#include <memory>

namespace PROTOCOL
{
	class ProtocolWord;
	class ProtocolWordByte
	{
	private:
		std::shared_ptr<ProtocolWord> belongingWord_;
		int byteOffset_;
		char byteValue_;
		int color_;
		int success_;

	public:
		ProtocolWordByte(std::shared_ptr<ProtocolWord> word, int offset, char byteValue, int color, int success) :
			belongingWord_(word), byteOffset_(offset), byteValue_(byteValue), color_(color), success_(success) {}

		std::shared_ptr<ProtocolWord> belongingWord() { return this->belongingWord_; }
		int& byteOffset() { return this->byteOffset_; }
		char& byteValue() { return this->byteValue_; }
		int& color() { return this->color_; }
		int& success() { return this->success_; }
	};
}


#endif
