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

	RevColorAtom() {};

	RevColorAtom(UINT16 memSrcColor, INT32 memSrcLen, UINT16 memDestColor, INT32 memDestLen,
		UINT16 regSrcColor, UINT16 regDestColor, UINT16 leaBaseColor,
		UINT16 leaIndexColor, UINT16 immSrcColor)
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
	}

	RevColorAtom(std::vector<UINT16> memSrcColor, INT32 memSrcLen, std::vector<UINT16> memDestColor, INT32 memDestLen,
		std::vector<UINT16> regSrcColor, std::vector<UINT16> regDestColor, UINT16 leaBaseColor,
		UINT16 leaIndexColor, UINT16 immSrcColor)
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
	}

	//TODO
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
