#include "RevLog.h"

int getTotalHeuristicsNumber()
{
	return HLComparison::getRevHeuristicNumber() + HLPointerField::getRevHeuristicNumber();
}

template <typename T>
RevLog<T>::RevLog()
{
	this->revLogVector.clear();
	this->lastHeuristicHits = std::vector<int>(getTotalHeuristicsNumber(), -1);
}

//https://isocpp.org/wiki/faq/templates#separate-template-class-defn-from-decl
template class RevLog<RevAtom>;
template class RevLog<HLComparison>;
template class RevLog<HLPointerField>;

template <typename T> 
void RevLog<T>::cleanLog()
{
	this->revLogVector.clear();
	this->lastHeuristicHits = std::vector<int>(getTotalHeuristicsNumber(), -1);
}

template <typename T>
void RevLog<T>::cleanFirstX(int x)
{
	if (x < 0) return;
	if (x >= this->revLogVector.size()) this->revLogVector.clear();
	this->revLogVector.erase(this->revLogVector.begin(), this->revLogVector.begin() + x);
	
	//Reduce the index at which heuristics last hit an instruction
	//Bare in mind overflows
	for (int &ii : this->lastHeuristicHits)
	{
		ii -= x;
		if (ii < 0) ii = -1;
	}
}

template <typename T>
void RevLog<T>::logInsert(T value)
{
	this->revLogVector.push_back(value);
}

template <typename T>
std::vector<T> RevLog<T>::getLogVector()
{
	return this->revLogVector;
}

template <typename T>
int RevLog<T>::getHeuristicLastHitIndex(int heuristicIndex)
{
	return this->lastHeuristicHits.at(heuristicIndex);
}

template <typename T>
void RevLog<T>::setHeutisticLastHit(int heuristicIndex, int instructionHitIndex)
{
	this->lastHeuristicHits.at(heuristicIndex) = instructionHitIndex;
}