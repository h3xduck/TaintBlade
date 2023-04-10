#include "ProtocolNetworkBuffer.h"

REVERSING::PROTOCOL::ProtocolNetworkBuffer::ProtocolNetworkBuffer()
{
	this->startMemAddress = 0;
	this->endMemAddress = 0;
}

REVERSING::PROTOCOL::ProtocolNetworkBuffer::ProtocolNetworkBuffer(ADDRINT start, ADDRINT end)
{
	this->startMemAddress = start;
	this->endMemAddress = end;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setStartMemAddress(ADDRINT address)
{
	this->startMemAddress = address;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setEndMemAddress(ADDRINT address)
{
	this->endMemAddress = address;
}

ADDRINT REVERSING::PROTOCOL::ProtocolNetworkBuffer::getStartMemAddress()
{
	return this->startMemAddress;
}

ADDRINT REVERSING::PROTOCOL::ProtocolNetworkBuffer::getEndMemAddress()
{
	return this->endMemAddress;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setStartColor(UINT16 color)
{
	this->startColor = color;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setEndColor(UINT16 color)
{
	this->endColor = color;
}

UINT16 REVERSING::PROTOCOL::ProtocolNetworkBuffer::getStartColor()
{
	return this->startColor;
}

UINT16 REVERSING::PROTOCOL::ProtocolNetworkBuffer::getEndColor()
{
	return this->endColor;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setValuesVector(std::vector<UINT8> vec)
{
	this->valuesVector = vec;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::addValueToValuesVector(UINT8 val)
{
	this->valuesVector.push_back(val);
}

std::vector<UINT8> REVERSING::PROTOCOL::ProtocolNetworkBuffer::getValuesVector()
{
	return this->valuesVector;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::setColorsVector(std::vector<UINT16> vec)
{
	this->colorsVector = vec;
}

void REVERSING::PROTOCOL::ProtocolNetworkBuffer::addColorToColorsVector(UINT16 color)
{
	this->colorsVector.push_back(color);
}

std::vector<UINT16> REVERSING::PROTOCOL::ProtocolNetworkBuffer::getColorsVector()
{
	return this->colorsVector;
}