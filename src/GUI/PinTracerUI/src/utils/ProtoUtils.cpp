#include "utils/proto/ProtoUtils.h"

QString UTILS::getHexValueOfByte(int charValue, int maxHexLen)
{
	QString hexValue = QString("0x%1").arg(charValue, maxHexLen, 16, QLatin1Char('0'));
	return hexValue;
}