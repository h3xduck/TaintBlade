#ifndef _EXECUTION_MANAGER_H_
#define _EXECUTION_MANAGER_H_

#include <vector>
#include "DllImageLoad.h"
#include "NopSection.h"
#include "PseudoAssemblyParser.h"

namespace UTILS
{
	namespace EXEC
	{
		class ExecutionManager
		{
		private:
			/**
			Includes list of loaded images and the address at which they were loaded
			*/
			std::vector<DllImageLoad> imageVector;

			/**
			List of instructions that will not be executed by the system since the user requested so
			*/
			std::vector<NopSection> nopSectionVector;

		public:
			/**
			Adds an image that was found by the system into the internal registry
			*/
			void addImage(IMG img);

			/**
			Registers a set of instructions in a range at a certain image so that they are not executed.
			The start and end of the range are included.
			*/
			void registerNopSection(std::string dllName, ADDRINT rangeStart, ADDRINT rangeEnd, std::vector<std::string> userAssemblyLines);

			/**
			Checks whether an instruction belongs to a noped section
			*/
			bool isInNopSection(INS ins);

			/**
			Instruments the instructions of an image corresponding to nop sections so that the IP skips 
			over the nop-ed instruction. 
			Basically, we'll ensure the first instruction of the range does not get executed and then the IP
			moves to the instruction next to the end of the NOP-ed range.
			*/
			void instrumentNopSection(INS ins);

		};
	}
}




#endif