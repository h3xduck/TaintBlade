#ifndef _GLOBAL_CONFIG_H_
#define _GLOBAL_CONFIG_H_

//0 - Normal, 1 - Debug, 2 - Verbose Debug
#define DEBUG_LEVEL 1

//0 - log RTN calls and all instructions in debug files (slows down program!)
#define CONFIG_INST_LOG_FILES 0

//0 - Do not report about unsupported instructions, 1 - Do it
#define REPORT_UNSUPPORTED_INS 0

//0 - Do not report about unsupported registers, 1 - Do it
#define REPORT_UNSUPPORTED_REG 0

//Debug write memory addresses in hexadecimal or decimal notation
#define DEBUG_IN_HEX 0

//Data dumping files
#define CURRENT_TAINTED_MEMORY_DUMP_FILE "memdump.dfx"
#define MEMORY_COLOR_EVENT_DUMP_FILE "memcoloreventdump.dfx"
#define ORG_COLORS_DUMP_FILE "orgcolorsdump.dfx"
#define COLOR_TRANS_DUMP_FILE "colortransdump.dfx"
#define FUNC_DLL_NAMES_DUMP_FILE "funcdllnames.dfx"
#define DUMP_INTER_SEPARATOR "%"
#define DUMP_OUTER_SEPARATOR std::endl

#endif
