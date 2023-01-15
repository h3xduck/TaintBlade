#include "Tag.h"

UINT16 Tag::lastColor = 0;

Tag Tag::tagNext()
{
	Tag tag = Tag();
	Tag::lastColor++;
	tag.color = Tag::lastColor;
	return tag;
}

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

	/*std::string logLine = "Generated new color [";
	logLine += std::to_string(color);
	logLine += "] by mixing [";
	logLine += std::to_string(derivate1);
	logLine += "] and [";
	logLine += std::to_string(derivate2);
	logLine += "]";*/
	//LOG_DEBUG(logLine.c_str());


	this->derivate1 = derivate1;
	this->derivate2 = derivate2;
}

Tag Tag::simpleColorMix(UINT16 src1, UINT16 src2)
{
	//TODO: Register the mix somewhere.
	Tag::lastColor++;
	Tag tag(color, src1, src2);
	return tag;
}