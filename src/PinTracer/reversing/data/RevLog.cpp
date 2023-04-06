#include "RevLog.h"

template <typename T>
RevLog<T>::RevLog()
{
	this->revLogVector.clear();
}

//https://isocpp.org/wiki/faq/templates#separate-template-class-defn-from-decl
template class RevLog<RevAtom>;
template class RevLog<HLComparison>;

template <typename T> 
void RevLog<T>::cleanLog()
{
	this->revLogVector.clear();
}

template <typename T>
void RevLog<T>::cleanFirstX(int x)
{
	if (x < 0) return;
	if (x >= this->revLogVector.size()) this->revLogVector.clear();
	this->revLogVector.erase(this->revLogVector.begin(), this->revLogVector.begin() + x);
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
