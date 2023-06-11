#ifndef PROTOUTILS_H
#define PROTOUTILS_H

#include <QString>

namespace UTILS
{
	QString getHexValueOfByte(int charValue, int maxHexLen);
	QString getHexValueOfByteAuto(int charValue);
	QString getHexValueOfByteNo0x(int charValue, int maxHexLen);
	QString getHexValueOfByteNo0xAuto(int charValue);
}




#endif // !PROTOUTILS_H
