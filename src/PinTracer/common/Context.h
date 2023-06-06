#ifndef _CONTEXT_H_
#define _CONTEXT_H_

#include "pin.H"
#include "../reversing/core/RevContext.h"
#include "../utils/trace/TraceManager.h"
#include "../utils/exec/ExecutionManager.h"
#include "../utils/io/CommandCenter.h"
#include "../utils/io/DataDumper.h"
#include "../utils/db/DatabaseManager.h"

class Context {
public:
	//This struct contains information about the last routine that was executed and was contained in the DLLs that the user specified to trace
	struct currentRoutineInfo_t
	{
		std::string funcName;
		std::string dllName;
		ADDRINT routineStart;
		ADDRINT routineBaseStart;
		ADDRINT possibleJumpPoint; //possible address at which the routine jumped to another non-traced dll
		ADDRINT possibleBaseJumpPoint; //same as previous, but base address
	};
private:
	ADDRINT currentInstructionFullAddress; //full dynamic address of instruction inside de process
	ADDRINT currentBaseInstruction; //offset from the start of the image
	std::string lastMemoryValue;
	int lastMemoryLength;
	RevContext revContext;
	UTILS::TRACE::TraceManager traceManager;
	UTILS::EXEC::ExecutionManager executionManager;
	UTILS::DB::DatabaseManager databaseManager;
	DataDumper dataDumper;
	struct currentRoutineInfo_t currentRoutineInfo_;

public:
	ADDRINT getCurrentInstructionFullAddress();
	ADDRINT getCurrentBaseInstruction();
	std::string getLastMemoryValue();
	int getLastMemoryLength();

	void updateCurrentInstructionFullAddress(ADDRINT instAddr);
	void updateCurrentBaseInstruction(ADDRINT instAddr);
	void updateLastMemoryValue(std::string value, int len);

	/**
	Get RevContext object
	*/
	RevContext* getRevContext();
	
	UTILS::TRACE::TraceManager& getTraceManager();
	UTILS::EXEC::ExecutionManager& getExecutionManager();
	UTILS::DB::DatabaseManager& getDatabaseManager();
	DataDumper& getDataDumper();

	struct currentRoutineInfo_t& currentRoutineInfo() { return this->currentRoutineInfo_; };
};

#endif
