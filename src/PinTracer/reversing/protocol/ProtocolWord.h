#ifndef _PROTOCOLWORD_H_
#define _PROTOCOLWORD_H_

#include "pin.H"
#include <vector>

namespace REVERSING
{
	namespace PROTOCOL
	{
		class ProtocolNetworkBuffer;
		class ProtocolWord
		{
		public:
			enum protocol_word_type_t
			{
				//Default
				UNDEFINED, 

				//Pure word types, these are the best we can find and we are quite sure they are this type of word
				DELIMETER,  //Type delimeter, the value is checked sequentially in the code, and there is a success at some point
				KEYWORD,	//Type keyword, the value is only checked for specific bytes in the code. It might be a failed comparison
							//it is made of multiple bytes (>1), so we have some confidence in this being a keyword

				//Mixed word types, these happen when, because of the program comparisons, we are not sure whether
				//it is a keyword, a delimiter or something else. So just store it as some broad classes
				SEPARATORLASTBYTE,	//A check that was done just for the last byte, not sure what it was
				FAILEDDELIMETER,	//Something that seems a delimeter (sequential checks) but without a success comparison
				BYTEKEYWORD			//A keyword... with just one byte. Because this provides us with a low degree of confidence
									//of it being a keyword, we define this other type.

			};
		private:
			/**
			Value that the delimeter holds. Vector of one byte
			*/
			std::vector<UINT8> wordValue;

			/**
			Protocol network buffer to which the delimeter is applied to
			*/
			//ProtocolNetworkBuffer* buffer;

			/**
			Starting index at the buffer at which the word starts. Included in range.
			*/
			int bufferStartIndex = -1;

			/**
			Final index at the buffer at which the word ends. Included in range.
			*/
			int bufferEndIndex = -1;

			/**
			Indicates whether the wordValue at that index was a successful comparison (1) or not (0).
			Each entry in the vector is one entry in the wordValue vector.
			Boundaries included in range.
			Failed comparisons appear as index 0.
			*/
			std::vector<int> successIndexes;

			/**
			Type of delimeter. It might be a delimeter, or a keyword
			*/
			protocol_word_type_t wordType = UNDEFINED;

		public:
			ProtocolWord();
			ProtocolWord(UINT8 wordValue, ADDRINT bufferStartIndex, ADDRINT bufferEndIndex, protocol_word_type_t wordType, int successIndex);
			ProtocolWord(std::vector<UINT8>& wordValueVec, ADDRINT bufferStartIndex, ADDRINT bufferEndIndex, protocol_word_type_t wordType, std::vector<int>& successIndexVec);

			//Getters and setters
			std::vector<UINT8> getAllBytes();
			void addByte(UINT8 valByte);
			void setBytes(std::vector<UINT8> valBytes);
			//ProtocolNetworkBuffer* getBuffer();
			//void setBuffer(ProtocolNetworkBuffer* buffer);
			int getStartIndex();
			void setStartIndex(int index);
			int getEndIndex();
			void setEndIndex(int index);
			void addSuccessIndex(int index);
			std::vector<int> getSuccessIndexes();
			protocol_word_type_t getWordType();
			void setWordType(protocol_word_type_t type);

			/**
			Gets contents of word as a string
			*/
			std::string toString();
		};


	}
}




#endif
