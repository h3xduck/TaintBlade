#ifndef _PROTOCOLPOINTER_H_
#define _PROTOCOLPOINTER_H_

#include "pin.H"
#include "../../utils/inst/InstructionWorker.h"
#include <vector>

namespace REVERSING
{
	namespace PROTOCOL
	{
		class ProtocolNetworkBuffer;
		class ProtocolPointer
		{
		private:
			/**
			Value that the pointer holds to reference the offset to the pointed value. Vector of one byte.
			*/
			std::vector<UINT8> pointerValue_;

			/**
			Color that the pointer value has. Vector of colors, one per byte.
			*/
			std::vector<UINT16> pointerColors_;

			/**
			Color that the memory pointed by the pointer holds.
			*/
			UINT16 pointedColor_;

		public:
			ProtocolPointer(std::vector<UINT8> pointerValue, std::vector<UINT16> pointerColors, UINT16 pointedColor)
				: pointerValue_(pointerValue), pointerColors_(pointerColors), pointedColor_(pointedColor) {};
			
			//getters and setters
			std::vector<UINT8>& pointerValue() { return this->pointerValue_; }
			std::vector<UINT16>& pointerColors() { return this->pointerColors_; }
			UINT16& pointedColor() { return this->pointedColor_; }

			/**
			Gets contents of pointer as a string
			*/
			std::string toString();
		};


	}
}




#endif
