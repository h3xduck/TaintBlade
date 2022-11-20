/*
 * Copyright (C) 2022-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*
 * This pintool is testing the libpindwarf.so library.
 * Pintool mode of operation:
 * The pintool does not actually use any instrumentations and does not run the application.
 * It runs its logic from the main() function and uses the API of libpindwarf.so directly.
 * The subprograms list returned from the library is dumped to a file in a specific format
 * that needs to match the format in the reference file since the files will be compared.
 * The reason for using a pintool for this purpose is because it is already linked with Pin CRT and is simple to use.
 * The pintool itself will only fail in case there is an error in retrieving the data.
 */

#include "pin.H"
#include <iostream>
#include <fstream>
using std::cerr;
using std::endl;
using std::string;

#include "pindwarf.h"

// The input file - the binary for which we are extracting the dwarf data
KNOB< string > KnobBinary(KNOB_MODE_WRITEONCE, "pintool", "bin", "", "specify binary file name for dwarf parsing");
// The output file - where to dump the subroutines list
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify stdout file name");

INT32 Usage()
{
    std::cerr << "This tool parses the DWARF of the given file." << std::endl;
    std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;
    return -1;
}

void parse_binary_dwarf(const char* binary)
{
    std::string fileName = KnobOutputFile.Value();
    std::ofstream outfile(fileName.empty() ? "subprograms.out" : fileName.c_str());

    SubprogramInfo* subprograms;
    unsigned num_subprograms;
    PINDWARF_RES res = GetSubprogramsListInImage(binary, &num_subprograms, &subprograms);
    ASSERTX(res == PINDWARF_SUCCESS);
    for (unsigned i = 0; i < num_subprograms; i++)
    {
        // The format of the printed lines should match the format in the reference files (llvm-diff.intel64.ref.log / llvm-diff.ia32.ref.log)
        outfile << std::hex << subprograms[i].low_pc << " | " << std::hex << subprograms[i].high_pc << " | "
                << subprograms[i].linkage_name << " | " << subprograms[i].short_name << " | "
                << (subprograms[i].inlined ? "inline=YES" : "inline=NO") << std::endl;
    }
    res = DeallocateSubprogramsList(num_subprograms, subprograms);
    ASSERTX(res == PINDWARF_SUCCESS);
    outfile.close();
}

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    parse_binary_dwarf(KnobBinary.Value().c_str());
    return 0;
}
