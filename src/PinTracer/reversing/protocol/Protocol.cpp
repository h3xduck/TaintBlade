#include "Protocol.h"

std::vector<REVERSING::PROTOCOL::ProtocolNetworkBuffer> REVERSING::PROTOCOL::Protocol::getNetworkBufferVector()
{
	return this->networkBufferVector;
}

void REVERSING::PROTOCOL::Protocol::addBufferToNetworkBufferVector(ProtocolNetworkBuffer buf)
{
	this->networkBufferVector.push_back(buf);
}

int REVERSING::PROTOCOL::Protocol::getNumberProtocolsStored()
{
	return this->networkBufferVector.size();
}