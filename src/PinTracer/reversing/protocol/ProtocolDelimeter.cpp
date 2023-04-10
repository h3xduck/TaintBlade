#include "ProtocolDelimeter.h"

std::vector<UINT8> REVERSING::PROTOCOL::ProtocolDelimeter::getAllDelimeterBytes()
{
	return this->delimeterValue;
}

void REVERSING::PROTOCOL::ProtocolDelimeter::setDelimeterBytes(std::vector<UINT8> valBytes)
{
	this->delimeterValue = valBytes;
}

REVERSING::PROTOCOL::ProtocolNetworkBuffer* REVERSING::PROTOCOL::ProtocolDelimeter::getBuffer()
{
	return this->buffer;
}

void REVERSING::PROTOCOL::ProtocolDelimeter::setBuffer(ProtocolNetworkBuffer* buffer)
{
	this->buffer = buffer;
}

ADDRINT REVERSING::PROTOCOL::ProtocolDelimeter::getStartAddress()
{
	return this->bufferStartAddress;
}

void REVERSING::PROTOCOL::ProtocolDelimeter::setStartAddress(ADDRINT address)
{
	this->bufferStartAddress = address;
}

ADDRINT REVERSING::PROTOCOL::ProtocolDelimeter::getEndAddress()
{
	return this->bufferEndAddress;
}

void REVERSING::PROTOCOL::ProtocolDelimeter::setEndAddress(ADDRINT address)
{
	this->bufferEndAddress = address;
}