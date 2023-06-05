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

			typedef enum contained_taint_events_type
			{
				NONE,			//No event
				TAINT_SRC,		//Taint was manually originated from this routine
				TAINT_SINK,		//The routine is surely operating with tainted data
				TAINT_EVENTFUL, //The taint changed at some point inside this routine = taint events happened while running
				TAINT_INDIRECT, //The routine is part of a scoped image, and it was the one which called the code that caused the taint event

				//The next taint types are only selected when we do not trace that DLL, we just guess what happens inside
				TAINT_SUS_ARGS	//We believe that some argument which was tainted was passed to this routine
			};

			typedef struct taint_routine_dump_line_t
			{
				std::string dll;
				std::string func;
				ADDRINT instAddrEntry;
				ADDRINT instAddrLast;
				contained_taint_events_type containedEventsType;
				bool optionalBaseAddrs = false; //optional, indicates base addresses are included
				ADDRINT instAddrEntryBase; //optional, if not passed then the image at dll is assumed not to be stale and it will be calculated from instAddrEntry
				ADDRINT instAddrLastBase; //optional, if not passed then the image at dll is assumed not to be stale and it will be calculated from instAddrLast
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