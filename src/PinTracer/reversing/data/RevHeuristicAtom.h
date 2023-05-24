#ifndef _REVHEURISTICATOM_H_
#define _REVHEURISTICATOM_H_

#include "../../utils/io/log.h"

/**
Determines the fields of a RevAtom which should be tainted for the instruction
to be considered part of a heuristic.
The RevHeuristic also incorporates data about the operands and instruction type, 
for cases when we find the heuristic without an atom. If it is contained in an atom
already, then this value is the same as the atom.
*/
class RevHeuristicAtom
{
public:
	//Describes the type of operands contained in the instruction
	//e.g., register to register, or mem to reg, etc.
	//All operands, not the tainted ones
	enum atom_operands_type_t
	{
		INVALID,
		REG2REG,
		MEM2REG,
		REG2MEM,
		MEM2MEM,
		IMM2REG,
		IMM2MEM,
		MEM2REG_LEA
	};

	int instType = 0;
	atom_operands_type_t operandsType = INVALID;
	bool memSrcTainted = 0;
	bool memDestTainted = 0;
	bool regSrcTainted = 0;
	bool regDestTainted = 0;
	//Never tainted, but important to know we have one
	bool hasImmSrc = 0;

	//For LEA operations
	bool leaBaseTainted = 0;
	bool leaIndexTainted = 0;

	//For REPE/REPNE SCAS operations
	bool scasMemTainted = 0;
	bool regScasXAXTainted = 0;
	bool regScasXCXTainted = 0;
	bool regScasXDITainted = 0;

	RevHeuristicAtom() {};

	RevHeuristicAtom(int instType, atom_operands_type_t operandsType,
		bool memSrcTainted, bool memDestTainted, bool regSrcTainted,
		bool regDestTainted, bool leaBaseTainted,
		bool leaIndexTainted, bool hasImmSrc,
		bool scasMemTainted, bool regScasXAXTainted, bool regScasXCXTainted, bool regScasXDITainted)
		: instType(instType), operandsType(operandsType), memSrcTainted(memSrcTainted), memDestTainted(memDestTainted),
		regSrcTainted(regSrcTainted), regDestTainted(regDestTainted), leaBaseTainted(leaBaseTainted),
		leaIndexTainted(leaIndexTainted), hasImmSrc(hasImmSrc), scasMemTainted(scasMemTainted),
		regScasXAXTainted(regScasXAXTainted), regScasXCXTainted(regScasXCXTainted),
		regScasXDITainted(regScasXDITainted) {}

	/**
	Returns whether an heuristic atom (this) is containted on another (other).
	For this to be true, the instructions must be the same, and the tainted elements on (other)
	must always be present on (this).
	*/
	bool containtedIn(const RevHeuristicAtom& other)
	{
		//Check instruction types
		if (this->instType != other.instType)
		{
			return false;
		}

		//Check operands type
		if (this->operandsType != other.operandsType)
		{
			return false;
		}

		//If either the heuristic or the atom have an immSrc, then the other MUST too
		//otherwise it is not the same instruction
		if ((other.hasImmSrc && !this->hasImmSrc) || (!other.hasImmSrc && this->hasImmSrc))
		{
			return false;
		}

		//Check tainting
		if ((other.leaBaseTainted && !this->leaBaseTainted) || 
			(other.leaIndexTainted && !this->leaIndexTainted) || 
			(other.memDestTainted && !this->memDestTainted) || 
			(other.memSrcTainted && !this->memSrcTainted) || 
			(other.regDestTainted && !this->regDestTainted) || 
			(other.regSrcTainted && !this->regSrcTainted) ||
			(other.scasMemTainted && !this->scasMemTainted) ||
			(other.regScasXAXTainted && !this->regScasXAXTainted) ||
			(other.regScasXCXTainted && !this->regScasXCXTainted) ||
			(other.regScasXDITainted && !this->regScasXDITainted)
			)
		{
			return false;
		}

		return true;
	}

	/**
	Returns whether the RevHeuristicAtom has any field active (=tainted)
	*/
	bool containsAnyData()
	{
		if (this->hasImmSrc || this->instType != 0 || this->leaBaseTainted ||
			this->leaIndexTainted || this->memDestTainted || this->memSrcTainted ||
			this->regDestTainted || this->regSrcTainted || this->scasMemTainted ||
			this->regScasXAXTainted || this->regScasXCXTainted || this->regScasXDITainted)
		{
			return true;
		}

		return false;
	}
};

#endif
