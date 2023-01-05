#ifndef _TAINT_IO_H_
#define _TAINT_IO_H_

#include <iostream>
#include <cstdio>

#define LOG(msg, ...) fprintf(stderr, msg, __FILE__, __LINE__, ##__VA_ARGS__)


#define LOG_ERR(msg, ...) LOG("[ERROR] " msg "\n")
#endif