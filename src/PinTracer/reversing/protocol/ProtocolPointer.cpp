#include "ProtocolPointer.h"
#include "ProtocolNetworkBuffer.h"

std::string REVERSING::PROTOCOL::ProtocolPointer::toString()
{
	std::stringstream ss;
	ss << "POINTER FIELD: Pointed color = "<<this->pointedColor();
	for (int ii = 0; ii < this->pointerValue().size(); ii++)
	{
		ss << "\n\tPointer value (byte " << ii << "): " << InstructionWorker::byteToHexValueString(this->pointerValue().at(ii)) << " | Color: " << this->pointerColors().at(ii);
	}

	return ss.str();
}