#include "http_methods.hpp"
#include <string_view>

struct http_header {
	std::string_view name;
	std::string_view len;
};

constexpr auto STATIC_NUM_HEADERS = 50;

struct http_parsed_req {
	const http_method method;
	struct http_header headers[STATIC_NUM_HEADERS];
	size_t num_headers;
};

http_parsed_req http_parse_request(char* req, size_t len);
