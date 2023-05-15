#ifndef _REV_DATAATOM_H_
#define _REV_DATAATOM_H_

#include <vector>
#include "pin.H"

/**
Contains the actual values of a RevAtom that are referenced by a 
memory address range or contained in a register.
It stores ALL information, even if the element is not tainted
THEREFORE THIS SHOULD NOT BE USED AS RELIABLE DATA TO DETERMINE IF THE ELEMENT IS TAINTED
*/
class RevDataAtom
{
private:
	//One char per byte
	std::vector<UINT8> memSrcValueBytes;
	std::vector<UINT8> memDestValueBytes;
	
	//One UINT8 for each byte of the register
	std::vector<UINT8> regSrcValueBytes;
	std::vector<UINT8> regDestValueBytes;

	//One UINT8 for each byte of the immediate
	std::vector<UINT8> immSrcValueBytes;

	//One UINT8 for each Flag in flag register. We are only storing FLAGS, not RFLAGS:
	//https://en.wikipedia.org/wiki/FLAGS_register
	//These are the values of the flags AFTER execution the instruction.
	//Stored as one UINT8 PER FLAG (Where each Flag is 1 bit in the FLAGS register)
	//Will be empty except for operations when it's needed (e.g CMP after its execution)
	std::vector<UINT8> flags;

	//For REPNE SCAS operations
	std::vector<UINT8> scasMemBytes;
	std::vector<UINT8> regScasXAXBytes;
	std::vector<UINT8> regScasXCXBytes;
	std::vector<UINT8> regScasXDIBytes;

public:
	RevDataAtom() {};
	RevDataAtom(std::vector<UINT8> memSrc, std::vector<UINT8> memDest, std::vector<UINT8> regSrc, std::vector<UINT8> regDest, std::vector<UINT8> flags,
		std::vector<UINT8> scasMemBytes, std::vector<UINT8> regScasXAXBytes, std::vector<UINT8> regScasXCXBytes, std::vector<UINT8> regScasXDIBytes)
	{
		this->memSrcValueBytes = memSrc;
		this->memDestValueBytes = memDest;
		this->regSrcValueBytes = regSrc;
		this->regDestValueBytes = regDest;
		this->flags = flags;
		this->scasMemBytes = scasMemBytes;
		this->regScasXAXBytes = regScasXAXBytes;
		this->regScasXCXBytes = regScasXCXBytes;
		this->regScasXDIBytes = regScasXDIBytes;
	}

	void setMemSrcValueBytes(std::vector<char> valueBytes)
	{
		this->memSrcValueBytes.clear();
		for (int ii = 0; ii < valueBytes.size(); ii++)
		{
			this->memSrcValueBytes.push_back((UINT8)valueBytes.at(ii));
		}
	}

	std::vector<UINT8> getMemSrcValueBytes()
	{
		return this->memSrcValueBytes;
	}

	void addMemSrcValueByte(char valueByte)
	{
		this->memSrcValueBytes.push_back(valueByte);
	}

	void setMemDestValueBytes(std::vector<char> valueBytes)
	{
		this->memDestValueBytes.clear();
		for (int ii = 0; ii < valueBytes.size(); ii++)
		{
			this->memDestValueBytes.push_back((UINT8)valueBytes.at(ii));
		}
	}

	std::vector<UINT8> getMemDestValueBytes()
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

	std::vector<UINT8>& getRegSrcValue()
	{
		return this->regSrcValueBytes;
	}

	void setRegDestValue(UINT8 *value, UINT32 byteSize)
	{
		this->regDestValueBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regDestValueBytes.push_back(value[ii]);
		}
	}

	std::vector<UINT8>& getRegDestValue()
	{
		return this->regDestValueBytes;
	}

	//Asumming we get FLAGS. Get value of interesting bits
	void setFlagsValue(UINT8* value)
	{
		this->flags.clear();
		for (int ii = 0; ii < 2; ii++)
		{
			for (int jj = 0; jj < 8; jj++)
			{
				UINT8 bit = (value[ii] >> jj) & 1U;
				this->flags.push_back(bit);
			}
		}
	}

	std::vector<UINT8> getImmSrcValue()
	{
		return this->immSrcValueBytes;
	}

	void setImmSrcValue(ADDRINT value)
	{
		this->immSrcValueBytes.empty();
		this->immSrcValueBytes.reserve(sizeof(ADDRINT));
		for (int ii = 0; ii < 8; ii++)
		{
			this->immSrcValueBytes.push_back(value & 0xFF);
			value >>= 8;
		}
	}

	std::vector<UINT8> getFlagsValue()
	{
		return this->flags;
	}

	//REPE / REPNE SCAS
	std::vector<UINT8> getScasMemBytes()
	{
		return this->scasMemBytes;
	}
	std::vector<UINT8> getRegScasXAXBytes()
	{
		return this->regScasXAXBytes;
	}
	std::vector<UINT8> getRegScasXCXBytes()
	{
		return this->regScasXCXBytes;
	}
	std::vector<UINT8> getRegScasXDIBytes()
	{
		return this->regScasXDIBytes;
	}
	void setScasMemBytes(std::vector<UINT8> vec)
	{
		this->scasMemBytes = vec;
	}
	void setScasMemBytes(UINT8* value, UINT32 byteSize)
	{
		this->scasMemBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->scasMemBytes.push_back(value[ii]);
		}
	}
	void setRegScasXAXBytes(std::vector<UINT8> vec)
	{
		this->regScasXAXBytes = vec;
	}
	void setRegScasXAXBytes(UINT8* value, UINT32 byteSize)
	{
		this->regScasXAXBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regScasXAXBytes.push_back(value[ii]);
		}
	}
	void setRegScasXCXBytes(std::vector<UINT8> vec)
	{
		this->regScasXCXBytes = vec;
	}
	void setRegScasXCXBytes(UINT8* value, UINT32 byteSize)
	{
		this->regScasXCXBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regScasXCXBytes.push_back(value[ii]);
		}
	}
	void setRegScasXDIBytes(std::vector<UINT8> vec)
	{
		this->regScasXDIBytes = vec;
	}
	void setRegScasXDIBytes(UINT8* value, UINT32 byteSize)
	{
		this->regScasXDIBytes.clear();
		for (UINT32 ii = 0; ii < byteSize; ii++)
		{
			this->regScasXDIBytes.push_back(value[ii]);
		}
	}
};


#endif