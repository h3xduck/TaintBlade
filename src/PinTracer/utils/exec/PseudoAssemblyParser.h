#ifndef _PSEUDO_ASSEMBLY_PARSER_H_
#define _PSEUDO_ASSEMBLY_PARSER_H_

#include "../io/log.h"
#include "pin.H"
#include <xed-category-enum.h>

namespace UTILS
{
	namespace EXEC
	{
		/**
		Pseudo assembly is a simple input format for the user so that the value of registers can be
		specified (usually after skipping over a NOP-ed section)
		*/
		namespace PseudoAssemblyParser
		{
			/**
			Instrumentates the codeline and executes any operation specified on it
			*/
			void instrumentAssemblyLine(INS ins, std::string codeLine);
		}
	}
}
#endif