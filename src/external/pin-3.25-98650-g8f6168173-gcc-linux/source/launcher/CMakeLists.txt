#
# Copyright (C) 2021-2022 Intel Corporation.
# SPDX-License-Identifier: MIT
#

cmake_minimum_required (VERSION 3.19)

enable_language(CXX C ASM)

message(STATUS "==> Entering launcher_u")

# This file builds Unix's launcher

#
# Targets
#

add_executable(launcher)
if (__linux_os)
    target_link_libraries(launcher crtbeginend c-static os-apis)
    set(lflags -Wl,-z,noexecstack -Wl,-z,relro,-z,now ${CBIN_OPT} -nostdlib -static)
else()
    set(lflags -Wl,-pie -m64 -mmacosx-version-min=10.7)
endif()
target_link_options(launcher BEFORE PUBLIC ${lflags})

### End Targets

#
# Include directories
#

if (__linux_os)
    set(isystem
        ${CMAKE_SOURCE_DIR}/Source/bionic/libc/additional/include
        ${CMAKE_SOURCE_DIR}/Source/bionic/libc/include
        ${CMAKE_SOURCE_DIR}/Source/bionic/libc/arch-${bit_suffix}/include
        ${CMAKE_SOURCE_DIR}/Source/bionic/libc/kernel/uapi
        ${CMAKE_SOURCE_DIR}/Source/bionic/libc/kernel/uapi/asm-x86
        ${CMAKE_SOURCE_DIR}/Source/os-apis/00-export-include)
endif()

set(include
    ${CMAKE_SOURCE_DIR}/External/System/Include_unix
    ${CMAKE_SOURCE_DIR}/External/jitprofiling
    ${CMAKE_SOURCE_DIR}/Source/pin
    ${CMAKE_SOURCE_DIR}/Source/pin/include_wrappers_unix
    ${CMAKE_SOURCE_DIR}/Source/pin/include
    ${CMAKE_SOURCE_DIR}/Source/atomic/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/debugger-protocol/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/os-apis/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/os-apis/signals
    ${CMAKE_SOURCE_DIR}/Source/os-services/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/sync/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/util/00-export-include
    ${CMAKE_SOURCE_DIR}/Source/pinvm
    ${CMAKE_SOURCE_DIR}/Source/pinvm/breakpoints
    ${CMAKE_SOURCE_DIR}/Source/pinvm/debugger-connection
    ${CMAKE_SOURCE_DIR}/Source/pinvm/debugger-image-list
    ${CMAKE_SOURCE_DIR}/Source/pinvm/exception-details
    ${CMAKE_SOURCE_DIR}/Source/pinvm/memlog
    ${CMAKE_SOURCE_DIR}/Source/pinvm/misc-api
    ${CMAKE_SOURCE_DIR}/Source/pinvm/pinsync
    ${CMAKE_SOURCE_DIR}/Source/pinvm/signal-details
    ${CMAKE_SOURCE_DIR}/Source/pinvm/singleton-manager
    ${CMAKE_SOURCE_DIR}/Source/pinvm/thread-depot
    ${CMAKE_SOURCE_DIR}/Source/pinvm/vsignal
    ${CMAKE_SOURCE_DIR}/Source/pinvm/vsignal/x86)

target_include_directories(launcher SYSTEM PRIVATE ${isystem})
target_include_directories(launcher PRIVATE ${include})

#
# build options and definitions
#

set(flags -Werror -pedantic -Wno-long-long -Wall -Wtype-limits)
set(defs PIN_COMPAT_OLDPIN PIN_DEPRECATED_WARNINGS=0 ATOMIC_ASSERT=ASSERTX ATOMIC_NO_ASSERTSLOW SYNC_ASSERT=ASSERTX PIN_CRT=1)
if (__linux_os)
    list(APPEND flags ${CBIN_OPT} -fno-stack-protector)
    list(APPEND defs CC_FAST_LOOKUP)
elseif (__mac_os)
    list(APPEND flags -fPIC -Wformat -Wformat-security)
    list(APPEND defs _FORTIFY_SOURCE=2 nasm NEWLINE=ASM_NEWLINE)
endif()

target_compile_options(launcher PRIVATE ${flags})
target_compile_definitions(launcher PRIVATE ${defs})

### End build options and definitions

#
# Source files
#

if (__linux_os)
    set(SOURCES utils.c os_specific_l.c launcher_u.c)
elseif (__mac_os)
    set(SOURCES utils.c os_specific_m.c launcher_u.c)
endif()

target_sources(launcher PUBLIC ${SOURCES})
set_target_properties(launcher PROPERTIES OUTPUT_NAME pin)

### end Source

install(TARGETS launcher DESTINATION ${PIN_INSTALL_DIR})
