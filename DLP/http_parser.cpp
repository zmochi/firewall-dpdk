/* trick to compile this library even though it doesn't have `extern "C"` */
extern "C" {
#include "picohttpparser/picohttpparser.c"
#include "picohttpparser/picohttpparser.h"
}

#include "http_methods.hpp"
#include "http_parser.hpp"

http_parsed_req::http_parsed_req() {}

#include <iostream>
http_parsed_req http_parse_request(const char *req, size_t len) {
    http_parsed_req   result;
    struct phr_header headers[STATIC_NUM_HEADERS];
    size_t            num_headers = STATIC_NUM_HEADERS;

    const char *method;
    const char *path;
    size_t      method_len, path_len;
    int         minor_version;
    int         req_len =
        phr_parse_request(req, len, &method, &method_len, &path, &path_len,
                          &minor_version, headers, &num_headers, 0);
    if ( req_len < 0 ) {
        result.metadata_len = -1;
    } else {
        result.metadata_len = req_len;
    }

    result.num_headers = num_headers;

    result.method = get_method_code(method);
    static_assert(result.headers.size() ==
                  sizeof(headers) / sizeof(headers[0]));
    for ( int i = 0; i < num_headers; i++ ) {
        result.headers.at(i).name =
            std::string_view(headers[i].name, headers[i].name_len);
        result.headers.at(i).value =
            std::string_view(headers[i].value, headers[i].value_len);
    }

    return result;
}
