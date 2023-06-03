#ifndef _DATA_DUMP_LINE_H_
#define _DATA_DUMP_LINE_H_

#include "pin.H"

namespace UTILS
{
	namespace IO
	{
		namespace DataDumpLine
		{

			typedef struct extended_data_dump_line_t
			{
				int funcDllIndex;
				char positionContext; //0 if entry arg, 1 if exit arg, 2 if somewhere else
				ADDRINT memAddrRangeFirst;
				ADDRINT memAddrRangeLast;
			};

			typedef struct org_colors_dump_line_t
			{
				UINT16 color;
			};

			typedef struct func_dll_names_dump_line_t
			{
				std::string dllFrom;
				std::string funcFrom;
				ADDRINT memAddrFrom;
				std::string dllTo;
				std::string funcTo;
				ADDRINT memAddrTo;
				std::string arg0;
				std::string arg1;
				std::string arg2;
				std::string arg3;
				std::string arg4;
				std::string arg5;
			};

			typedef struct taint_routine_dump_line_t
			{
				std::string dll;
				std::string func;
				ADDRINT instAddrEntry;
				ADDRINT instAddrLast;
			};

			typedef enum memory_color_event
			{
				UNDEFINED,  //Undefined
				UNTAINT,	//Untainted memory location
				TAINT,		//Tainted new memory location (happens naturally at the program, not manual by a rule)
				CHANGE,		//Changed the color of an already tainted memrory location, no mix
				MIX,		//Mixed two colors into a new one, or reutilized a previous mix
				TAINTGEN,	//Explicitely tainted a memory location because of a rule specified at a function
				CHANGEGEN,  //Explicitely changed the taint of a memory location because of a rule specified at a function
			};

			typedef struct memory_color_event_line_t
			{
				memory_color_event eventType = UNDEFINED;
				ADDRINT memAddr = 0;
				UINT16 color = 0;
			};
		}
	}
}

#endif