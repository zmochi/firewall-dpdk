#ifndef __UTIL_H
#define __UTIL_H

extern "C" {

#include <stdio.h>

#define ERROR(fmt, ...) do { fprintf(stderr, "ERROR: %s:" fmt "\n", __func__, ##__VA_ARGS__); } while(0)
#define LOG(fmt, ...) do { printf("LOG: " fmt "\n", ##__VA_ARGS__); } while(0)

}

#endif /* __UTIL_H */
