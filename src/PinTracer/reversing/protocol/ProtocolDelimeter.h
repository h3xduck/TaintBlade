#ifndef _PROTOCOLDELIMETER_H_
#define _PROTOCOLDELIMETER_H_

#include "pin.H"
#include <vector>

namespace REVERSING
{
	namespace PROTOCOL
	{
		class ProtocolNetworkBuffer;
		class ProtocolDelimeter
		{
		private:
			/**
			Value that the delimeter holds. Vector of one byte
			*/
			std::vector<UINT8> delimeterValue;

			/**
			Protocol network buffer to which the delimeter is applied to
			*/
			ProtocolNetworkBuffer* buffer;

			/**
			Starting address at the buffer at which the delimeter applies to. Included in range.
			*/
			ADDRINT bufferStartAddress;

			/**
			Final address at the buffer at which the delimeter applies to. Included in range.
			*/
			ADDRINT bufferEndAddress;

		public:
			//Getters and setters
			std::vector<UINT8> getAllDelimeterBytes();
			void setDelimeterBytes(std::vector<UINT8> valBytes);
			ProtocolNetworkBuffer* getBuffer();
			void setBuffer(ProtocolNetworkBuffer* buffer);
			ADDRINT getStartAddress();
			void setStartAddress(ADDRINT address);
			ADDRINT getEndAddress();
			void setEndAddress(ADDRINT address);
		};


	}
}




#endif
