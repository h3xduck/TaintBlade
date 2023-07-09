#include "utils/proto/ProtoUtils.h"

QString UTILS::getHexValueOfByte(int charValue, int maxHexLen)
{
	QString hexValue = QString("0x%1").arg(charValue, maxHexLen, 16, QLatin1Char('0'));
	return hexValue;
}

QString UTILS::getHexValueOfByteAuto(int charValue)
{
	QString hexValue = QString("%1").arg(charValue, 16, 16, QLatin1Char('0'));
	while (hexValue.startsWith('0') && hexValue != "0") { hexValue.remove(0, 1); }
	hexValue = QString("0x%1").arg(hexValue);
	return hexValue;
}

QString UTILS::getHexValueOfByteNo0x(int charValue, int maxHexLen)
{
	QString hexValue = QString("%1").arg(charValue, maxHexLen, 16, QLatin1Char('0'));
	return hexValue;
}

QString UTILS::getHexValueOfByteNo0xAuto(int charValue)
{
	int numberOfDigits = charValue ? static_cast<int>(log10(abs(charValue))) + 1 : 1;
	QString hexValue = QString("%1").arg(charValue, 16, 16, QLatin1Char('0'));
	while (hexValue.startsWith('0') && hexValue != "0") { hexValue.remove(0, 1); }
	return hexValue;
}