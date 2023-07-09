#include "TraceManager.h"
#include "../io/DataDumper.h"
#include "../../common/Context.h"

extern Context ctx;
UTILS::TRACE::TraceManager::TraceManager() {};

void UTILS::TRACE::TraceManager::addTracePoint(const std::string& dllName, const std::string& funcName, const int numArgs)
{
	TracePoint tp(dllName, funcName, numArgs);
	this->traceVector.push_back(tp);

	LOG_DEBUG("Added function to trace with DLL:" << dllName << " FUNC:" << funcName << " NUMARGS:" << numArgs);
}

void UTILS::TRACE::TraceManager::traceFunction(RTN rtn, const std::string& dllName, const std::string& funcName)
{
	for (TracePoint tp : this->traceVector)
	{
		if (tp.getDllName() == dllName && tp.getFuncName() == funcName)
		{
			//Function was set to be traced
			this->traceTracePoint(rtn, tp);
		}
	}
}

static void genericFunctionTraceEnter(ADDRINT retIp, VOID* dllNamePtr, VOID* funcNamePtr, UINT32 numArgs, void* arg1, void* arg2, void* arg3, void* arg4, void* arg5, void* arg6)
{
	const std::string* dllName = static_cast<std::string*>(dllNamePtr);
	const std::string* funcName = static_cast<std::string*>(funcNamePtr);
	UTILS::TRACE::TracePoint tp(*dllName, *funcName, numArgs);

	//Extract argument of function
	std::vector<std::string> argsVec;
	std::vector<void*> argsVecPtr;
	
	//optimizable, but we were out of variadic functions due to msvc and x32, so will do for now
	switch (numArgs)
	{
	case 0:
		break;
	case 1:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	case 2:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg2);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	case 3:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg2);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg3);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	case 4:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg2);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg3);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg4);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	case 5:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg2);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg3);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg4);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg5);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	case 6:
		argsVecPtr.push_back((void*)arg1);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg2);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg3);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg4);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg5);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		argsVecPtr.push_back((void*)arg6);
		argsVec.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argsVecPtr.back())));
		break;
	}
	

	tp.setArgsPre(argsVec);
	tp.setArgsPrePtr(argsVecPtr);
	
	UTILS::TRACE::interFunctionCallsVector.push_back(tp);

	LOG_DEBUG("TRACED FUNCTION AT ENTER DLL:" << *dllName << " FUNC:" << *funcName);

}

static void genericFunctionTraceExit(ADDRINT retValue, VOID* dllNamePtr, VOID* funcNamePtr)
{
	const std::string* dllName = static_cast<std::string*>(dllNamePtr);
	const std::string* funcName = static_cast<std::string*>(funcNamePtr);

	//LOG_DEBUG("miniexit: " << std::endl << "\tDLL:" << *dllName << " FUNC:" << *funcName);

	//Check if the trace point was inserted (it should, as the exit event should be called after the enter one)
	for (int ii=0; ii< UTILS::TRACE::interFunctionCallsVector.size(); ii++)
	{
		UTILS::TRACE::TracePoint& tp = UTILS::TRACE::interFunctionCallsVector.at(ii);
		if (tp.getDllName() == *dllName && tp.getFuncName() == *funcName)
		{
			//Found it
			std::vector<std::string> argsVecPost;
			for (void* argPtr : tp.getArgsPrePtr())
			{
				argsVecPost.push_back(InstructionWorker::utf8Encode(InstructionWorker::printFunctionArgument(argPtr)));
			}
			tp.setArgsPost(argsVecPost);

			LOG_DEBUG("TRACED FUNCTION AT EXIT: " << std::endl << "\tDLL:" << tp.getDllName() << " FUNC:" << tp.getFuncName());
			for (int jj = 0; jj < tp.getNumArgs(); jj++)
			{
				std::string arg = argsVecPost.at(jj);
				LOG_DEBUG("arg" << jj << ": " << arg);
			}

			ctx.getDataDumper().writeTraceDumpLine(tp);

			UTILS::TRACE::interFunctionCallsVector.erase(UTILS::TRACE::interFunctionCallsVector.begin() + ii);
			return;
		}
	}

	
}

void UTILS::TRACE::TraceManager::traceTracePoint(RTN &rtn, TracePoint &tp)
{
	//We will trace the arguments before and after the execution
	LOG_DEBUG("Tracing function DLL:" << tp.getDllName() << " FUNC:" << tp.getFuncName()<<" NUM:"<<tp.getNumArgs());
	FUNCTION_TRACE(rtn, tp.getDllName(), tp.getFuncName(), tp.getNumArgs(), genericFunctionTraceEnter, genericFunctionTraceExit);
}