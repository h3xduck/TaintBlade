#include "Tag.h"
#include "../../utils/io/log.h"

UINT16 Tag::lastColor = 0;

Tag::Tag(UINT16 color)
{
	this->color = color;
	if (color > Tag::lastColor)
	{
		Tag::lastColor = color;
	}
}

Tag::Tag(UINT16 color, UINT16 derivate1, UINT16 derivate2)
{
	this->color = color;
	this->derivate1 = derivate1;
	this->derivate2 = derivate2;
}

Tag::Tag(UINT16 derivate1, UINT16 derivate2)
{
	Tag::lastColor++;
	this->color = Tag::lastColor;

	std::string logLine = "Generated new color [";
	logLine += color;
	logLine += "] by mixing [";
	logLine += derivate1;
	logLine += "] and [";
	logLine += derivate2;
	logLine += "]";
	LOG_DEBUG(logLine);

	this->derivate1 = derivate1;
	this->derivate2 = derivate2;
}