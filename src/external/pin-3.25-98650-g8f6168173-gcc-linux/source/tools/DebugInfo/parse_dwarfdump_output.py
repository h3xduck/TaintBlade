#!/usr/intel/bin/python

#
# Copyright (C) 2022-2022 Intel Corporation.
# SPDX-License-Identifier: MIT
#

#
# This script is being used to parse the DWARF information in a binary, filter only the subprogram and inline entries and dump it to a file.
# The script is using objdump to read the DWARF using the following command:   objdump --dwarf=info <binary_file>
# The output of this command is a textual respresentation of the DWARF tree. The script is parsing the lines and processes the entries that are subprograms or inlined.
# A subprogram may have more than one entry to represent its full data.
# For example, the below entry <27c1d0> which is DW_TAG_subprogram has a link (DW_AT_abstract_origin) to another node <0x27c190>,
# that has a link (DW_AT_specification) to another node <0x167bfe> that has the name.
# Therefore the script allows moving between nodes and aggregates the subprogram data from all the relevant nodes.
#
#  <1><27c1d0>: Abbrev Number: 26 (DW_TAG_subprogram)
#     <27c1d1>   DW_AT_abstract_origin: <0x27c190>
#     <27c1d5>   DW_AT_linkage_name: (indirect string, offset: 0x286c23): _ZN4llvm7APFloat7StorageC2IJRmEEERKNS_12fltSemanticsEDpOT_
#     <27c1d9>   DW_AT_object_pointer: <0x27c202>
#     <27c1dd>   DW_AT_low_pc      : 0x41d03e
#     <27c1e5>   DW_AT_high_pc     : 0xc7
#     <27c1ed>   DW_AT_frame_base  : 1 byte block: 9c     (DW_OP_call_frame_cfa)
#     <27c1ef>   DW_AT_call_all_tail_calls: 1
#     <27c1ef>   DW_AT_sibling     : <0x27c222>
#
#  <1><27c190>: Abbrev Number: 34 (DW_TAG_subprogram)
#     <27c191>   DW_AT_specification: <0x167bfe>
#     <27c195>   DW_AT_object_pointer: <0x27c1ad>
#     <27c199>   DW_AT_inline      : 2    (declared as inline but ignored)
#     <27c19a>   DW_AT_sibling     : <0x27c1d0>
#
# <4><167bfe>: Abbrev Number: 175 (DW_TAG_subprogram)
#     <167c00>   DW_AT_external    : 1
#     <167c00>   DW_AT_name        : (indirect string, offset: 0x2324fa): Storage<long unsigned int&>
#     <167c04>   DW_AT_decl_file   : 14
#     <167c05>   DW_AT_decl_line   : 718
#     <167c07>   DW_AT_decl_column : 5
#     <167c08>   DW_AT_linkage_name: (indirect string, offset: 0x29c018): _ZN4llvm7APFloat7StorageC4IJRmEEERKNS_12fltSemanticsEDpOT_
#     <167c0c>   DW_AT_declaration : 1
#     <167c0c>   DW_AT_object_pointer: <0x167c1f>
#
# The output of the script is a file containing lines in this format:
# LOW_PC | HIGH_PC | MANGLED_NAME | NAME | inline=<YES/NO>
#
# Please note the output file may require some manual adjustments in the HIGH_PC for some functions.
# See the comment below when parsing DW_AT_high_pc.
import argparse
import os
import sys
import subprocess
import re

subprograms_dict = {}

class DwarfEntry:
    def __init__(self, entry=None):
        if entry:
            self.id = entry.id
            self.is_subprogram = entry.is_subprogram
            self.is_inlined_subroutine = entry.is_inlined_subroutine
            self.low_pc = entry.low_pc
            self.size = entry.size
            self.mangled_name = entry.mangled_name
            self.name = entry.name
            self.specification = entry.specification
            self.abstract_origin = entry.abstract_origin
        else:
            self.reset()

    def reset(self):
        self.id = None
        self.is_subprogram = False
        self.is_inlined_subroutine = False
        self.low_pc = None
        self.size = None
        self.mangled_name = None
        self.name = None
        self.specification = None
        self.abstract_origin = None

    def dump(self, outfile):
        if not (self.is_subprogram or self.is_inlined_subroutine):
            return
        if self.mangled_name and self.name and self.low_pc and self.size:
            print("%x | %x | %s | %s | %s" % (
                    self.low_pc, 
                    self.low_pc + self.size - 1, 
                    self.mangled_name, 
                    self.name, 
                    "inline=YES" if self.is_inlined_subroutine else "inline=NO"),
                file=outfile)


def hash_subprograms_to_dict(binary):
    """
    This function parses the stdout of the "objdump --dwarf=info" command and hashes
    the DWARF entries which are subprograms or inlines to a dictionary where the key
    is the DWARF entry id (is unique) and the value is a DwarfEntry object.
    """
    global subprograms_dict
    line = ""
    entry = DwarfEntry()

    cmd = 'objdump --dwarf=info {}'.format(binary)
    p = subprocess.Popen(cmd, shell=True, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
        line = p.stdout.readline()

        # If the line matches the pattern below then this is a new dwarf entry
        if re.match( r'[\s]*<[0-9a-fA-F]+><[0-9a-fA-F]+>:.*\(DW_TAG.*', line):

            # Hash the current entry. The attributes have been aggregated into the entry object.
            if (entry.is_subprogram or entry.is_inlined_subroutine): # DW_TAG_subprogram / DW_TAG_inlined_subroutine
                subprograms_dict[entry.id] = DwarfEntry(entry)

            # Reset the object as we are starting a new DWARF entry
            entry.reset()

            if 'DW_TAG_subprogram' in line: 
                entry.is_subprogram = True
                entry.id = int(line.lstrip().split(':')[0].replace('<',' ').replace('>','').split()[-1], 16)
            if 'DW_TAG_inlined_subroutine' in line: 
                entry.is_inlined_subroutine = True
                entry.id = int(line.lstrip().split(':')[0].replace('<',' ').replace('>','').split()[-1], 16)

        # If we are currently inside a DW_TAG_subprogram or DW_TAG_inlined_subroutine entry then
        # extract the values from the relevant attributes
        if entry.is_subprogram or entry.is_inlined_subroutine:
            # Unmangled name
            if 'DW_AT_name' in line:
                entry.name = line.split('DW_AT_name')[1].lstrip().lstrip(':').strip()
                if '):' in entry.name:
                    entry.name = "):".join(entry.name.split('):')[1:]).lstrip().rstrip()
            # mangled name
            elif 'DW_AT_linkage_name' in line:
                entry.mangled_name = line.split('DW_AT_linkage_name')[1].lstrip().lstrip(':').strip()
                if '):' in entry.mangled_name:
                    entry.mangled_name = "):".join(entry.mangled_name.split('):')[1:]).lstrip().rstrip()
            # routine base adderss
            elif 'DW_AT_low_pc' in line: 
                entry.low_pc = int(line.split(':')[-1].lstrip().rstrip(),16)
            # In objdump output, in most cases c is actually the size and not the high pc.
            # Out of 60,000 functions, there were 5 functions where DW_AT_high_pc was the real high pc,
            # and those functions should be fixed manually.
            # The DWARF document notes that DT_AT_high_pc can be either an offset relative to DT_AT_low_pc
            # or an address (since DWARF 4).
            elif 'DW_AT_high_pc' in line:
                entry.size = int(line.split(':')[-1].lstrip().rstrip(),16)
            # specification is the id of another dwarf entry (that may have the name or linkage name)
            elif 'DW_AT_specification' in line:
                entry.specification = int(line.rstrip().split(':')[-1].lstrip().replace('<','').replace('>',''), 16)
            # abstract_origin is the id of another dwarf entry that may have the specification
            elif 'DW_AT_abstract_origin' in line:
                entry.abstract_origin = int(line.rstrip().split(':')[-1].lstrip().replace('<','').replace('>',''), 16)

        if not line and p.poll() is not None:  # no more output and the process is done, i.e. there WILL be no output
            break
    return (p.returncode==0) # return code 0 means Success


def resolve_subprogram_attributes():
    """
    This function executes after all the DWARF entries have been hashed to the dictionary.
    DWARF tree nodes have links from one node to another using attributes like DW_AT_abstract_origin or DW_AT_specification.
    This function iterates on the entries in the dictionary and follows those links to complete missing information.
    """
    global subprograms_dict
    for id, entry in subprograms_dict.items():
        # If this node has a DW_AT_specification then follow the link to the specification node,
        # and if it has either a name or a mangled name then copy them (if they are missing).
        if entry.specification and entry.specification in subprograms_dict:
            ref_entry = subprograms_dict[entry.specification]
            if not entry.name and ref_entry.name: 
                entry.name = ref_entry.name
            if not entry.mangled_name and ref_entry.mangled_name: 
                entry.mangled_name = ref_entry.mangled_name
        # If this node has a DW_AT_abstract_origin then follow the link to the abstract origin node.
        # If it has a name then copy it.
        # If it has a DW_AT_specification then follow the link to the specification node,
        # and if it has either a name or a mangled name then copy them (if they are missing).
        if entry.abstract_origin and entry.abstract_origin in subprograms_dict:
            ref_entry = subprograms_dict[entry.abstract_origin]
            if ref_entry.name: 
                entry.name = ref_entry.name
            if ref_entry.specification and ref_entry.specification in subprograms_dict:
                ref_entry = subprograms_dict[ref_entry.specification]
                if not entry.name and ref_entry.name: 
                    entry.name = ref_entry.name
                if not entry.mangled_name and ref_entry.mangled_name: 
                    entry.mangled_name = ref_entry.mangled_name
        # If the node has a name but not a mangled name then use the name as mangled.
        if not entry.mangled_name and entry.name: 
            entry.mangled_name = entry.name


def run_cmd_and_parse(binary, output_filename):
    """
    This function executes three steps:
    1) Hash the DWARF subprogram and inline entries to the dictionary
    2) Resolve the subprograms attributes by traversing the tree
    3) Dump the entries to a file in a specific format
    """
    if not hash_subprograms_to_dict(binary):
        return False

    resolve_subprogram_attributes()

    # Print the collected subprograms to a file
    out = open(output_filename, "w")
    for id, entry in subprograms_dict.items():
        entry.dump(out)
    out.close()
    return True
    
def parse_args():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description="Executable tool for parsing the output of llvm-dwarfdump\n"
                                     )
    parser.add_argument('--binary', help='Binary to parse')
    parser.add_argument('--out', help='Output file', default='dwarfdump.log')
    args = parser.parse_args()

    if not args.binary:
        print('Missing --binary')
        return None
    if not os.path.exists(args.binary):
        print("File does not exist ({})".format(args.bin))
        return None
    return args

def main():
    args = parse_args()
    if not args:
        return False
    return run_cmd_and_parse(args.binary, args.out)

# main function
if __name__ == "__main__":
    sys.exit( 0 if main() else 1)
