#include "widgets/protocol/ui/ByteBufferButton.h"

PROTOCOL::ByteBufferPushButton::ByteBufferPushButton(int byteIndex): QPushButton() 
{
	this->startByte = byteIndex;
	this->endByte = byteIndex;
}