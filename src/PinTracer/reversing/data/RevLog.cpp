#include "RevLog.h"

template <typename T>
RevLog<T>::RevLog()
{
	
}

//https://isocpp.org/wiki/faq/templates#separate-template-class-defn-from-decl
template class RevLog<RevAtom>;

template <typename T> 
void RevLog<T>::cleanLog()
{
	this->revLogVector.clear();
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