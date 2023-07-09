#ifndef PROTOCOLBUFFER_H
#define PROTOCOLBUFFER_H

#include <vector>
#include "ProtocolByte.h"
#include "ProtocolPointer.h"
#include "ProtocolWord.h"

namespace PROTOCOL
{
	class ProtocolBuffer
	{
	private:
		std::vector<std::shared_ptr<ProtocolByte>> byteVector_;
		std::vector<std::shared_ptr<ProtocolWord>> wordVector_;
		std::vector<std::shared_ptr<ProtocolPointer>> pointerVector_;

	public:
		ProtocolBuffer() :
		byteVector_(), wordVector_(), pointerVector_(){}

		/**
		Returns the offset in the buffer corresponding to a color. Returns -1 if color not found
		*/
		int getOffsetOfColor(int color)
		{
			for (std::shared_ptr<ProtocolByte> byte : byteVector_)
			{
				if (byte.get()->color() == color)
				{
					return byte.get()->byteOffset();
				}
			}
			return -1;
		}

		std::vector<std::shared_ptr<ProtocolByte>>& byteVector() { return this->byteVector_; }
		std::vector<std::shared_ptr<ProtocolWord>>& wordVector() { return this->wordVector_; }
		std::vector<std::shared_ptr<ProtocolPointer>>& pointerVector() { return this->pointerVector_; }
	};
}


#endif