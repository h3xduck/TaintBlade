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
	
	//One ADDRINT for the whole register
	ADDRINT regSrcValue = 0;
	ADDRINT regDestValue = 0;

public:
	RevDataAtom() {};
	RevDataAtom(std::vector<char> memSrc, std::vector<char> memDest, ADDRINT regSrc, ADDRINT regDest)
	{
		this->memSrcValueBytes = memSrc;
		this->memDestValueBytes = memDest;
		this->regSrcValue = regSrc;
		this->regDestValue = regDest;
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

	void setRegSrcValue(ADDRINT value)
	{
		this->regSrcValue = value;
	}

	ADDRINT getRegSrcValue()
	{
		return this->regSrcValue;
	}

	void setRegDestValue(ADDRINT value)
	{
		this->regDestValue = value;
	}

	ADDRINT getRegDestValue()
	{
		return this->regDestValue;
	}


};


#endif