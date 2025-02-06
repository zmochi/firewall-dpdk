#include "http_methods.hpp"
#include <array>
#include <string_view>
#include <sys/types.h>

struct http_header {
    std::string_view name;
    std::string_view value;
};

constexpr auto STATIC_NUM_HEADERS = 50;

struct http_parsed_req {
    std::array<struct http_header, STATIC_NUM_HEADERS> headers;

    http_method method;
    size_t      num_headers;
    // How many bytes from start of the request until content start (the final
    // \r\n\r\n)
    ssize_t metadata_len;

    http_parsed_req();
};

http_parsed_req http_parse_request(const char *req, size_t len);
