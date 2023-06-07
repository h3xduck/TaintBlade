#ifndef _PROTOCOLNETWORKBUFFER_H_
#define _PROTOCOLNETWORKBUFFER_H_

#include "pin.H"
#include "ProtocolWord.h"
#include "ProtocolPointer.h"
#include "../../taint/data/TagLog.h"

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
			Starting color of buffer. Included in range.
			*/
			ADDRINT startColor;

			/**
			Final color of buffer. Included in range.
			*/
			ADDRINT endColor;

			/**
			Vector of bytes, where each byte is one byte of the buffer, with its actual values.
			This is the data received from the network by the system.
			*/
			std::vector<UINT8> valuesVector;

			/**
			Vector of colors, where each color corresponds to one byte of the buffer, orderly.
			This is the data gathered by the tainting module.
			*/
			std::vector<UINT16> colorsVector;

			/**
			Vector of protocol words (delimeters and keywords) that apply to this network buffer
			*/
			std::vector<ProtocolWord> wordVector;

			/**
			Vector of protocol pointers (pointer fields) that apply to this network buffer
			*/
			std::vector<ProtocolPointer> pointerVector_;

			/**
			Vector of taint leads, one for each color, detailing whether there is a special use for
			any byte was tainted
			*/
			std::vector<TagLog::color_taint_lead_t> colorTaintLeadsVector;

		public:
			ProtocolNetworkBuffer();
			ProtocolNetworkBuffer(ADDRINT start, ADDRINT end);

			//Setters and getters - TODO refactoring to C++ syntax (check ProtocolPointer.h)
			void setStartMemAddress(ADDRINT address);
			void setEndMemAddress(ADDRINT address);
			ADDRINT getStartMemAddress();
			ADDRINT getEndMemAddress();
			void setStartColor(UINT16 color);
			void setEndColor(UINT16 color);
			UINT16 getStartColor();
			UINT16 getEndColor();
			void setValuesVector(std::vector<UINT8> vec);
			void addValueToValuesVector(UINT8 val);
			std::vector<UINT8> getValuesVector();
			void setColorsVector(std::vector<UINT16> vec);
			void addColorToColorsVector(UINT16 color);
			std::vector<UINT16> getColorsVector();
			void setWordVector(std::vector<ProtocolWord> vec);
			void addWordToWordVector(ProtocolWord &word);
			std::vector<ProtocolWord> getWordVector();
			void setcolorTaintLeadsVector(std::vector<TagLog::color_taint_lead_t> vec);
			void addLeadTocolorTaintLeadsVector(TagLog::color_taint_lead_t& lead);
			std::vector<TagLog::color_taint_lead_t> gecolorTaintLeadsVector();

			std::vector<ProtocolPointer>& pointerVector() { return this->pointerVector_; }
		};
	}
}





#endif
