/*
 * Copyright (C) 2013-2022 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/* ===================================================================== */
/*! @file
 *
 * This application records finds the VDSO and VVAR address ranges and a range of 
 * addresses that is neither, starts pin with the -restric_memory knob with the 
 * addresses that the application found. Pin then attaches to the parent process
 * and instruments it with the restrict_memory_vdso.cpp tool to makes sure that 
 * the VDSO and VVAR address ranges were not restricted.
 */

#include <stdio.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <assert.h>
#include <pthread.h>
#include <sstream>
#include <sys/auxv.h>
#include <fstream>
using std::ifstream;
using std::list;
using std::string;
using std::stringstream;

void* findMinMappedAddr()
{
    string line;
    ifstream maps("/proc/self/maps");
    void* min_addr = NULL;

    while (std::getline(maps, line))
    {
        size_t idx = line.find("-");
        if (string::npos == idx)
        {
            continue;
        }
        void* curr = (void*)strtoul(line.substr(0, idx).c_str(), NULL, 0x10);
        if (min_addr == NULL || curr < min_addr)
        {
            min_addr = curr;
        }
    }
    return min_addr;
}

void* findVvar()
{
    string line;
    ifstream maps("/proc/self/maps");
    const string vvar = "[vvar]";

    while (std::getline(maps, line))
    {
        size_t idx = line.find(vvar);
        if (string::npos != idx && line.substr(idx) == vvar)
        {
            idx = line.find("-");
            if (string::npos == idx)
            {
                return NULL;
            }
            return (void*)strtoul(line.substr(0, idx).c_str(), NULL, 0x10);
        }
    }
    return NULL;
}

/* Pin doesn't kill the process if if failed to attach, exit on SIGALRM */
void ExitOnAlarm(int sig)
{
    fprintf(stderr, "Pin is not attached, exit on SIGALRM\n");
    exit(0);
}

extern "C" int PinAttached() { return 0; }

void PrintArguments(char** inArgv)
{
    fprintf(stderr, "Going to run: ");
    for (unsigned int i = 0; inArgv[i] != 0; ++i)
    {
        fprintf(stderr, "%s ", inArgv[i]);
    }
    fprintf(stderr, "\n");
}

/*
 * Expected command line: <this exe> -pin $PIN -vdso/-vvar/-none -pinarg <pin args > -t tool <tool args>
 */

void ParseCommandLine(int argc, char* argv[], list< string >* pinArgs)
{
    string pinBinary;
    int page_size = getpagesize();
    for (int i = 1; i < argc; i++)
    {
        string arg = string(argv[i]);
        if (arg == "-pin")
        {
            pinBinary = argv[++i];
        }
        // Reserve memory that is not in VDSO or VVAR address ranges
        else if (arg == "-none")
        {
            pinArgs->push_back("-restrict_memory");
            void* min_mapped = findMinMappedAddr();
            assert(min_mapped);
            // Intentionally miss all mapped addresses
            void* none = min_mapped - (2 * page_size);
            stringstream ss;
            ss << none << ":" << (none + page_size);
            pinArgs->push_back(ss.str());
        }
        else if (arg == "-vdso")
        {
            pinArgs->push_back("-restrict_memory");
            void* vdso = (void*)getauxval(AT_SYSINFO_EHDR);
            assert(vdso);
            stringstream ss;
            ss << vdso << ":" << (vdso + page_size);
            pinArgs->push_back(ss.str());
        }
        else if (arg == "-vvar")
        {
            pinArgs->push_back("-restrict_memory");
            void* vvar = findVvar();
            assert(vvar);
            stringstream ss;
            ss << vvar << ":" << (vvar + page_size);
            pinArgs->push_back(ss.str());
        }
        else if (arg == "-pinarg")
        {
            for (int parg = ++i; parg < argc; parg++)
            {
                pinArgs->push_back(string(argv[parg]));
                ++i;
            }
        }
    }
    assert(!pinBinary.empty());
    pinArgs->push_front(pinBinary);
}

void StartPin(list< string >* pinArgs)
{
    pid_t appPid = getpid();
    pid_t child  = fork();
    if (child != 0) return;

    /* here is the child */
    // sleeping to give the parent time to diminish its privileges.
    sleep(2);
    printf("resumed child \n");

    // start Pin from child
    char** inArgv = new char*[pinArgs->size() + 10];

    // Pin binary in the first
    list< string >::iterator pinArgIt = pinArgs->begin();
    string pinBinary                  = *pinArgIt;
    pinArgIt++;

    // build pin arguments:
    unsigned int idx = 0;
    inArgv[idx++]    = (char*)pinBinary.c_str();
    inArgv[idx++]    = (char*)"-pid";
    inArgv[idx]      = (char*)malloc(10);
    sprintf(inArgv[idx++], "%d", appPid);

    for (; pinArgIt != pinArgs->end(); pinArgIt++)
    {
        inArgv[idx++] = (char*)pinArgIt->c_str();
    }
    inArgv[idx] = 0;

    PrintArguments(inArgv);

    // since we're exiting at this point we don't free the dynmically allocated memory
    execvp(inArgv[0], inArgv);
    fprintf(stderr, "ERROR: execv %s failed\n", inArgv[0]);

    exit(1);
}

int main(int argc, char* argv[])
{
    int i;

    list< string > pinArgs;

    ParseCommandLine(argc, argv, &pinArgs);

    StartPin(&pinArgs);

    /* Exit in 20 sec */
    signal(SIGALRM, ExitOnAlarm);
    alarm(20);

    printf("Before pause, waiting on PinAttached\n");

    while (!PinAttached())
    {
        // Sleep should cause a context switch for Pin to be attached
        sleep(2);
    }

    printf("After pause\n");

    return 0;
}
/*
 *  eof
 */
