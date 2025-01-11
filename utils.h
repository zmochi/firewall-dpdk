#ifndef __UTIL_H
#define __UTIL_H

#include <vector>
extern "C" {

#include <stdio.h>

#define ERROR(fmt, ...) do { fprintf(stderr, "ERROR: %s: " fmt "\n", __func__, ##__VA_ARGS__); } while(0)
#define ERROR_EXIT(fmt, ...) do { ERROR(fmt, ##__VA_ARGS__); exit(1); } while(0)
#define LOG(fmt, ...) do { printf("LOG: " fmt "\n", ##__VA_ARGS__); } while(0)

}

#include <string>

std::vector<char> load_file(size_t offset, ssize_t len);

#endif /* __UTIL_H */
