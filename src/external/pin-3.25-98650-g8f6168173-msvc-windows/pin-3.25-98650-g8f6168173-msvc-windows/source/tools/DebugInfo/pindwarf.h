/*
 * Copyright (C) 2013-2022 Intel Corporation.
 * 
 * This software and the related documents are Intel copyrighted materials, and your
 * use of them is governed by the express license under which they were provided to
 * you ("License"). Unless the License provides otherwise, you may not use, modify,
 * copy, publish, distribute, disclose or transmit this software or the related
 * documents without Intel's prior written permission.
 * 
 * This software and the related documents are provided as is, with no express or
 * implied warranties, other than those that are expressly stated in the License.
 */

// <COMPONENT>: pindwarf
// <FILE-TYPE>: implementation

#ifndef PINDWARF_H
#define PINDWARF_H

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PINDWARF_SUCCESS,
    PINDWARF_EBEFORE,     // Failed to open or parse this image in a previous attempt
    PINDWARF_EOPEN,       // Failed to open the image at the given path
    PINDWARF_EEXIST,      // Image doesn't exist in memory
    PINDWARF_EFOUND       // Failed to find line informationa at the given address
} PINDWARF_RES;

typedef struct _SubprogramInfo {
    const char*     short_name;
    const char*     linkage_name;
    uint64_t        low_pc;         // static pc, relative to the base of the image
    uint64_t        high_pc;        // static pc, relative to the base of the image
    bool            inlined;
} SubprogramInfo;

/*!
  Find the line number, file, and column number corresponding to a memory address.

  @param[in] path       The image path to search in.
  @param[in] address    The code address to lookup.
  @param[out] column    A pointer to the variable that will hold the column number.  Returns -1
                         if the address has no valid column information or if the compiler
                         did not annotate a specific column for this address.
  @param[out] line      A pointer to the variable that will hold the line number.  Returns zero
                         if the address has no valid line information.
  @param[out] file      A pointer to the variable that will hold the file name.  Returns NULL
                         if the address has no valid file information.
  @return               0 for success, positive enum values for failures.

  @par Availability:
  \b Mode:  JIT & Probe\n
  \b O/S:   macOS*\n
  \b CPU:   All\n
 */
PINDWARF_RES FindColumnLineInfoByAddress(const char* fn_arg, uintptr_t address,
                                        unsigned *column, unsigned *line, const char ** file) 
                                        __attribute__ ((visibility ("default")));

/*!
  InvalidateImage free's all the stored debug information for the given image.

  @param[in] path      The image path to search

  @return              0 for success, positive enum values for failures.

  @par Availability:
  \b Mode:  JIT & Probe\n
  \b O/S:   macOS*\n
  \b CPU:   All\n
 */
PINDWARF_RES InvalidateImage(const char* path) __attribute__ ((visibility ("default")));

/*!
  Get Subprograma debug information for the given image.

  @param[in] path              The image path to search
  @param[out] list_size        The size of the subprogram_list
                               If no dwarf information exists for this image or an error occurred then the 
                               value of this argument is 0.
  @param[out] subprorams_list  A list of SubprogramInfo holding the dwarf information of the subprograms in the image.
                               The function allocates the array of SubprogramInfo.
                               If no dwarf information exists for this image or an error occurred then the value 
                               of this argument is NULL.
  @return              0 for success, positive enum values for failures.

  @par Availability:
  \b Mode:  JIT & Probe\n
  \b O/S:   Linux\n
  \b CPU:   All\n
 */
PINDWARF_RES GetSubprogramsListInImage(const char* path,
                                       unsigned* list_size,
                                       SubprogramInfo** subprorams_list) __attribute__ ((visibility ("default")));

/*!
  Free a subprogram info list previously allocated by GetSubprogramsListInImage

  @param[in] list_size             The size of the subprogram_list
  @param[in] subprorams_list   A list of SubprogramInfo holding the dwarf information of the subprograms in the image.
  @return              0 for success, positive enum values for failures.

  @par Availability:
  \b Mode:  JIT & Probe\n
  \b O/S:   Linux\n
  \b CPU:   All\n
 */
PINDWARF_RES DeallocateSubprogramsList( unsigned list_size,
                                        SubprogramInfo* subprorams_list) __attribute__ ((visibility ("default")));

#ifdef __cplusplus
} // extern "C"
#endif


#endif // PINDWARF_H

