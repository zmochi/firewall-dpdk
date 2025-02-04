/* trick to compile this library even though it doesn't have `extern "C"` */
extern "C" {
#include "picohttpparser/picohttpparser.c"
#include "picohttpparser/picohttpparser.h"
}

#include "http_methods.hpp"
#include "http_parser.hpp"

http_parsed_req http_parse_request(char* req, size_t len) {
}
