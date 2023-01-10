#ifndef _TAG_H_
#define _TAG_H_

#include "pin.H"

class Tag
{
public:
	Tag(UINT16 color);
	//COLOR_BYTES = 2
	UINT16 color;
};


#endif