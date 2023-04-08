#ifndef _REV_DATAATOM_H_
#define _REV_DATAATOM_H_

#include <vector>
#include "pin.H"

/**
Contains the actual values of a RevAtom that are referenced by a 
memory address range or contained in a register.
If the atom does not have some of the values tainted, then this is 0,
it only stores tainted information.
*/
class RevDataAtom
{
private:
	//One char per byte
	std::vector<char> memSrcValueBytes;
	std::vector<char> memDestValueBytes;
	
	//One UINT8 for each byte of the register
	std::vector<UINT8> regSrcValueBytes;
	std::vector<UINT8> regDestValueBytes;

public:
	RevDataAtom() {};
	RevDataAtom(std::vector<char> memSrc, std::vector<char> memDest, std::vector<UINT8> regSrc, std::vector<UINT8> regDest)
	{
		this->memSrcValueBytes = memSrc;
		this->memDestValueBytes = memDest;
		this->regSrcValueBytes = regSrc;
		this->regDestValueBytes = regDest;
	}

	void setMemSrcValueBytes(std::vector<char> valueBytes)
	{
		this->memSrcValueBytes = valueBytes;
	}

	std::vector<char> getMemSrcValueBytes()
	{
		return this->memSrcValueBytes;
	}

	void addMemSrcValueByte(char valueByte)
	{
		this->memSrcValueBytes.push_back(valueByte);
	}

	void setMemDestValueBytes(std::vector<char> valueBytes)
	{
		this->memDestValueBytes = valueBytes;
	}

	std::vector<char> getMemDestValueBytes()
	{
		return this->memDestValueBytes;
	}

	void addMemDestValueByte(char valueByte)
	{
		this->memDestValueBytes.push_back(valueByte);
	}

	void setRegSrcValue(UINT8 *value, UINT32 byteSize)
	{
		this->regSrcValueBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regSrcValueBytes.push_back(value[ii]);
		}
	}

	std::vector<UINT8> getRegSrcValue()
	{
		return this->regSrcValueBytes;
	}

	void setRegDestValue(UINT8 *value, UINT32 byteSize)
	{
		this->regSrcValueBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regDestValueBytes.push_back(value[ii]);
		}
	}

	std::vector<UINT8> getRegDestValue()
	{
		return this->regDestValueBytes;
	}


};


#endif