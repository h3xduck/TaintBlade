#ifndef _PROTOCOLNETWORKBUFFER_H_
#define _PROTOCOLNETWORKBUFFER_H_

#include "pin.H"

namespace REVERSING
{
	namespace PROTOCOL
	{
		/**
		Includes data about a buffer that was tainted by a taint rule, including colors of each of its bytes
		*/
		class ProtocolNetworkBuffer
		{
		private:
			/**
			Starting memory address of buffer. Included in range.
			*/
			ADDRINT startMemAddress;

			/**
			Final memory address of buffer. Included in range.
			*/
			ADDRINT endMemAddress;

			/**
			Vector of chars, where each char is one byte of the buffer, with its actual values.
			This is the data received from the network by the system.
			*/
			std::vector<char> valuesVector;

		public:
			ProtocolNetworkBuffer();
			ProtocolNetworkBuffer(ADDRINT start, ADDRINT end);

			void setStartMemAddress(ADDRINT address);
			void setEndMemAddress(ADDRINT address);
			ADDRINT getStartMemAddress();
			ADDRINT getEndMemAddress();
			void setValuesVector(std::vector<char> vec);
			void addValueToValuesVector(char val);
			
		};
	}
}





#endif
