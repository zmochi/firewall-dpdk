#include "filter.hpp"
#include "SimilarityMatcher.hpp"
#include "http_parser.hpp"

#include <cstring>
#include <string>

static std::string c_similarities[] = {
    "#ifdef",       "#ifndef",  "void main(int argc, char* argv[])",
    "#define",      "typedef",  "char *",
    "int *",        "char*",    "int*",
    "int",          "char",     "size_t",
    "return NULL;", "#include", "stdio.h",
    "stdlib.h"};

static SimilarityMatcher c_code_matcher(c_similarities,
                                        sizeof(c_similarities) /
                                            sizeof(c_similarities[0]));

#include <iostream>
static score_t filter_handle_http(const char *request, size_t size) {
    http_parsed_req req = http_parse_request(request, size);
	if(req.metadata_len < 0) {
		// couldn't parse request, so filter it
		return MAX_SCORE;
	}
    // TODO: recognize method without parsing entire request?
    if ( req.method != M_POST ) {
        // 0 should always pass
        return 0;
    }

    static_assert(sizeof(*request) == sizeof(char));
    score_t score = c_code_matcher.match(request + req.metadata_len, size);

    return score;
}

static bool is_http_request(const char *str, size_t size) {
    const char *ch = str;
    int         num_spaces = 0;
    // if there are no spaces, don't keep going 'forever'
    constexpr auto MAX_ITER = 300;
    // how much of the string was processed
    size_t offset = 0;
    // example: "GET /home HTTP/1.1"
    // after the loop:	 ch^
    while ( num_spaces < 2 && offset < MAX_ITER ) {
        num_spaces += (*ch == ' ');
        ch++;
        offset++;
    }
    if ( size <= offset ) return false;

    const char *is_http_str = "HTTP/1";
    size_t      strncmp_size = std::min(strlen(is_http_str), size - offset);
    bool res = !static_cast<bool>(strncmp(is_http_str, ch, strncmp_size));
    return res;
}

static bool is_smtp(const char *tcp_data, size_t size) { return false; }

#include <iostream>
filter_dc filter_c_code(char *pkt_tcp_data, size_t size) {
    constexpr score_t passing_score = 20;
    score_t           score;
    char             *data;
    size_t            data_size;

    // TODO: separate HTTP request and responses, filter indepedently
    if ( is_http_request(pkt_tcp_data, size) ) {
        score = filter_handle_http(pkt_tcp_data, size);
    } else if ( is_smtp(pkt_tcp_data, size) ) {
        std::cout << "Not implemented" << std::endl;
        return FILTER_DROP;
    }

    if ( score >= passing_score ) {
        return FILTER_DROP;
    }

    return FILTER_PASS;
}

#ifdef FILTER_UNIT_TEST
#include <sstream>

int main(void) {
    std::string non_c_code_text = R"EOF(
// Strings are just arrays of chars terminated by a NULL (0x00) byte,
// represented in strings as the special character '\0'.
// (We don't have to include the NULL byte in string literals; the compiler
//  inserts it at the end of the array for us.)

// i.e., byte #17 is 0 (as are 18, 19, and 20)

// If we have characters between single quotes, that's a character literal.
// It's of type `int`, and *not* `char` (for historical reasons).
  )EOF";
    std::string c_code_text =
        R"EOF(
#include <stdio.h>
#include <stdlib.h>

#define FILE_OK 0
#define FILE_NOT_EXIST 1
#define FILE_TOO_LARGE 2
#define FILE_READ_ERROR 3

char * c_read_file(const char * f_name, int * err, size_t * f_size) {
    char * buffer;
    size_t length;
    FILE * f = fopen(f_name, "rb");
    size_t read_length;
    
    if (f) {
        fseek(f, 0, SEEK_END);
        length = ftell(f);
        fseek(f, 0, SEEK_SET);
        
        // 1 GiB; best not to load a whole large file in one string
        if (length > 1073741824) {
            *err = FILE_TOO_LARGE;
            
            return NULL;
        }
        
        buffer = (char *)malloc(length + 1);
        
        if (length) {
            read_length = fread(buffer, 1, length, f);
            
            if (length != read_length) {
                 free(buffer);
                 *err = FILE_READ_ERROR;

                 return NULL;
            }
        }
        
        fclose(f);
        
        *err = FILE_OK;
        buffer[length] = '\0';
        *f_size = length;
    }
    else {
        *err = FILE_NOT_EXIST;
        
        return NULL;
    }
    
    return buffer;
}
		)EOF";

    auto http_wrap = [](std::string str) {
        std::stringstream textstream;
        textstream << "POST /home HTTP/1.1\r\n"
                      "Host: test\r\n"
                      "Content-Length: "
                   << str.size()
                   << "\r\n"
                      "\r\n"
                   << str;

        return textstream.str();
    };

    std::string http_c_code = http_wrap(c_code_text);
    std::string http_non_c_code = http_wrap(non_c_code_text);

    if ( filter_c_code(http_c_code.data(), http_c_code.size()) !=
         FILTER_DROP ) {
        std::cout << "Filter test failed: filter_c_code(), false negative"
                  << std::endl;
    }

    if ( filter_c_code(http_non_c_code.data(), http_non_c_code.size()) !=
         FILTER_PASS ) {
        std::cout << "Filter test failed: filter_c_code(), false positive"
                  << std::endl;
    }

    std::string is_http_str = "GET /home HTTP/1.0\r\n";
    std::string isnt_http_str = "POST /hello HTTP1\r\n\r\n";

    if ( !is_http_request(is_http_str.data(), is_http_str.size()) )
        std::cout << "Filter test failed: is_http_request(), false negative"
                  << std::endl;
    if ( is_http_request(isnt_http_str.data(), isnt_http_str.size()) )
        std::cout << "Filter test failed: is_http_request(), false positive"
                  << std::endl;
}

#endif /* FILTER_UNIT_TEST */
