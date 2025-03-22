#include "filter.hpp"
#include "C_CodeMatcher.hpp"
#include "http_parser.hpp"

#include <cstring>

C_CodeMatcher c_matcher;

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

filter_dc filter_c_code(char *pkt_tcp_data, size_t size) {
    constexpr score_t passing_score = 20;
    score_t           score = 0;
    char             *data;
    size_t            data_size;

	std::string_view text(pkt_tcp_data, size);
	score = c_matcher.match(text);

	printf("Text:\n%.*s\n", (int)size, pkt_tcp_data);
	printf("Score = %d\n", score);

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
