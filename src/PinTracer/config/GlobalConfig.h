#ifndef _GLOBAL_CONFIG_H_
#define _GLOBAL_CONFIG_H_

//******************************* DEBUGGING CONFIG *******************************//

//0 - Normal, 1 - Debug, 2 - Verbose Debug
#define DEBUG_LEVEL 1

//0 - log RTN calls and all instructions in debug files (slows down program A LOT!)
#define CONFIG_INST_LOG_FILES 0

//0 - Do not report about unsupported instructions, 1 - Do it
#define REPORT_UNSUPPORTED_INS 0

//0 - Do not report about unsupported registers, 1 - Do it
#define REPORT_UNSUPPORTED_REG 0

//Debug write memory addresses in hexadecimal or decimal notation
#define DEBUG_IN_HEX 1

//******************************* DATA DUMPING CONFIG *******************************//

//Data dumping files
#define CURRENT_TAINTED_MEMORY_DUMP_FILE "memdump.dfx"
#define TAINT_EVENT_DUMP_FILE "tainteventdump.dfx"
#define ORG_COLORS_DUMP_FILE "orgcolorsdump.dfx"
#define COLOR_TRANS_DUMP_FILE "colortransdump.dfx"
#define FUNC_DLL_NAMES_DUMP_FILE "funcdllnames.dfx"
#define HEURISTIC_RESULTS_DUMP_FILE "heuristics.dfx"
#define PROTOCOL_RESULTS_DUMP_FILE "protocol.dfx"
#define TRACE_RESULTS_DUMP_FILE "trace.dfx"
#define DUMP_INTER_SEPARATOR "%"
#define DUMP_OUTER_SEPARATOR std::endl

//******************************* REVERSING CONFIG *******************************//
//Value at which, when finding a control flow instruction, the system will truncate the RevLog
#define REVLOG_TRUNCATE_THRESHOLD 150

//When truncating the RevLog, we will also delete a bit more than just the threshold,
//to avoid continously erasing values when we soon surpass it again. This sets how
//many values are deleted apart from the truncation.
#define REVLOG_TRUNCATE_ADDITIONAL 30


#endif
