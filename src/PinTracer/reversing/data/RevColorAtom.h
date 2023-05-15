#ifndef _REVCOLORATOM_H_
#define _REVCOLORATOM_H_

#include <vector>

#ifndef UINT16
typedef unsigned short UINT16;
#endif

/**
Determines the taint colors of a RevAtom for those fields that are tainted.
*/
class RevColorAtom
{
public:
	std::vector<UINT16> memSrcColor;
	INT32 memSrcLen = 0;
	std::vector<UINT16> memDestColor;
	INT32 memDestLen = 0;
	std::vector<UINT16> regSrcColor;
	std::vector<UINT16> regDestColor;
	UINT16 immSrcColor = 0;

	//For LEA operations
	UINT16 leaBaseColor = 0;
	UINT16 leaIndexColor = 0;

	//For REPE/REPNE SCAS operations
	std::vector<UINT16> scasMemColor;
	INT32 scasMemLen = 0;
	std::vector<UINT16> regScasXAXColor;
	std::vector<UINT16> regScasXCXColor;
	std::vector<UINT16> regScasXDIColor;

	RevColorAtom() {};

	RevColorAtom(UINT16 memSrcColor, INT32 memSrcLen, UINT16 memDestColor, INT32 memDestLen,
		UINT16 regSrcColor, UINT16 regDestColor, UINT16 leaBaseColor,
		UINT16 leaIndexColor, UINT16 immSrcColor,
		UINT16 scasMemColor, INT32 scasMemLen, UINT16 regScasXAXColor, UINT16 regScasXCXColor, UINT16 regScasXDIColor)
	{
		this->memSrcColor.push_back(memSrcColor);
		this->memSrcLen = memSrcLen;
		this->memDestColor.push_back(memDestColor);
		this->memDestLen = memDestLen;
		this->regSrcColor.push_back(regSrcColor);
		this->regDestColor.push_back(regDestColor);
		this->leaBaseColor = leaBaseColor;
		this->leaIndexColor = leaIndexColor;
		this->immSrcColor = immSrcColor;
		this->scasMemColor.push_back(scasMemColor);
		this->scasMemLen = scasMemLen;
		this->regScasXAXColor.push_back(regScasXAXColor);
		this->regScasXCXColor.push_back(regScasXCXColor);
		this->regScasXDIColor.push_back(regScasXDIColor);
	}

	RevColorAtom(std::vector<UINT16> memSrcColor, INT32 memSrcLen, std::vector<UINT16> memDestColor, INT32 memDestLen,
		std::vector<UINT16> regSrcColor, std::vector<UINT16> regDestColor, UINT16 leaBaseColor,
		UINT16 leaIndexColor, UINT16 immSrcColor,
		std::vector<UINT16> scasMemColor, INT32 scasMemLen, std::vector<UINT16> regScasXAXColor, std::vector<UINT16> regScasXCXColor, std::vector<UINT16> regScasXDIColor)
	{
		this->memSrcColor = memSrcColor;
		this->memSrcLen = memSrcLen;
		this->memDestColor = memDestColor;
		this->memDestLen = memDestLen;
		this->regSrcColor = regSrcColor;
		this->regDestColor = regDestColor;
		this->leaBaseColor = leaBaseColor;
		this->leaIndexColor = leaIndexColor;
		this->immSrcColor = immSrcColor;
		this->scasMemColor = scasMemColor;
		this->scasMemLen = scasMemLen;
		this->regScasXAXColor = regScasXAXColor;
		this->regScasXCXColor = regScasXCXColor;
		this->regScasXDIColor = regScasXDIColor;
	}

	//Setters and getters
	std::vector<UINT16>& getRegSrcColor()
	{
		return this->regSrcColor;
	}
	std::vector<UINT16>& getRegDestColor()
	{
		return this->regDestColor;
	}
	std::vector<UINT16>& getMemSrcColor()
	{
		return this->memSrcColor;
	}
	std::vector<UINT16>& getMemDestColor()
	{
		return this->memDestColor;
	}
	std::vector<UINT16>& getImmSrcColorVector()
	{
		std::vector<UINT16> vec;
		vec.push_back(this->immSrcColor);
		return vec;
	}
	UINT16 getImmSrcColor()
	{
		return this->immSrcColor;
	}


	//TODO Don't think we'll need this anymore
	/**
	Returns whether an heuristic atom (this) is containted on another (other).
	For this to be true, the instructions must be the same, and the tainted elements on (other)
	must always be present on (this).
	*/
	/*bool containtedIn(const RevColorAtom& other)
	{
		if (this->instType != other.instType)
		{
			return false;
		}

		if ((other.immSrcTainted && !this->immSrcTainted) ||
			(other.leaBaseTainted && !this->leaBaseTainted) ||
			(other.leaIndexTainted && !this->leaIndexTainted) ||
			(other.memDestTainted && !this->memDestTainted) ||
			(other.memSrcTainted && !this->memSrcTainted) ||
			(other.regDestTainted && !this->regDestTainted) ||
			(other.regSrcTainted && !this->regSrcTainted))
		{
			return false;
		}

		return true;
	}*/
};

#endif
