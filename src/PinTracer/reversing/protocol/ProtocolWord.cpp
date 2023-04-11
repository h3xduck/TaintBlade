#include "ProtocolWord.h"
#include "ProtocolNetworkBuffer.h"

REVERSING::PROTOCOL::ProtocolWord::ProtocolWord() {};

REVERSING::PROTOCOL::ProtocolWord::ProtocolWord(UINT8 wordValue, ADDRINT bufferStartIndex, ADDRINT bufferEndIndex, REVERSING::PROTOCOL::ProtocolWord::protocol_word_type_t wordType, int successIndex)
{
	this->wordValue.push_back(wordValue);
	this->bufferStartIndex = bufferStartIndex;
	this->bufferEndIndex = bufferEndIndex;
	this->wordType = wordType;
	this->successIndexes.push_back(successIndex);
}

REVERSING::PROTOCOL::ProtocolWord::ProtocolWord(std::vector<UINT8> &wordValueVec, ADDRINT bufferStartIndex, ADDRINT bufferEndIndex, REVERSING::PROTOCOL::ProtocolWord::protocol_word_type_t wordType, std::vector<int>& successIndexVec)
{
	this->wordValue = wordValueVec;
	this->bufferStartIndex = bufferStartIndex;
	this->bufferEndIndex = bufferEndIndex;
	this->wordType = wordType;
	this->successIndexes = successIndexVec;
}


std::vector<UINT8> REVERSING::PROTOCOL::ProtocolWord::getAllBytes()
{
	return this->wordValue;
}

void REVERSING::PROTOCOL::ProtocolWord::addByte(UINT8 valByte)
{
	this->wordValue.push_back(valByte);
}

void REVERSING::PROTOCOL::ProtocolWord::setBytes(std::vector<UINT8> valBytes)
{
	this->wordValue = valBytes;
}

/*REVERSING::PROTOCOL::ProtocolNetworkBuffer* REVERSING::PROTOCOL::ProtocolWord::getBuffer()
{
	return this->buffer;
}

void REVERSING::PROTOCOL::ProtocolWord::setBuffer(ProtocolNetworkBuffer* buffer)
{
	this->buffer = buffer;
}*/

int REVERSING::PROTOCOL::ProtocolWord::getStartIndex()
{
	return this->bufferStartIndex;
}

void REVERSING::PROTOCOL::ProtocolWord::setStartIndex(int index)
{
	this->bufferStartIndex = index;
}

int REVERSING::PROTOCOL::ProtocolWord::getEndIndex()
{
	return this->bufferEndIndex;
}

void REVERSING::PROTOCOL::ProtocolWord::setEndIndex(int index)
{
	this->bufferEndIndex = index;
}

void REVERSING::PROTOCOL::ProtocolWord::addSuccessIndex(int index)
{
	this->successIndexes.push_back(index);
}

std::vector<int> REVERSING::PROTOCOL::ProtocolWord::getSuccessIndexes()
{
	return this->successIndexes;
}

REVERSING::PROTOCOL::ProtocolWord::protocol_word_type_t REVERSING::PROTOCOL::ProtocolWord::getWordType()
{
	return this->wordType;
}

void REVERSING::PROTOCOL::ProtocolWord::setWordType(protocol_word_type_t type)
{
	this->wordType = type;
}

std::string REVERSING::PROTOCOL::ProtocolWord::toString()
{
	std::stringstream ss;
	ss << "Word TYPE : " << this->getWordType() << " STARTINDEX : " << this->getStartIndex() << " ENDINDEX : " << this->getEndIndex();
	std::vector<UINT8> &bytesVec = this->getAllBytes();
	std::vector<int> &compVec = this->getSuccessIndexes();
	for (int ii = 0; ii < bytesVec.size(); ii++)
	{
		ss << "\n\tByte " << ii << ": " << bytesVec.at(ii) << " | Comp res: " << compVec.at(ii);
	}

	return ss.str();
}