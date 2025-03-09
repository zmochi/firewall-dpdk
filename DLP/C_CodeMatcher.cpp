#include "C_CodeMatcher.hpp"
#include <iostream>

static std::string c_similarities[] = {
    "#ifdef",       "#ifndef",  "void main(int argc, char* argv[])",
    "#define",      "typedef",  "char *",
    "int *",        "char*",    "int*",
    "int",          "char",     "size_t",
    "return NULL;", "#include", "stdio.h",
    "stdlib.h"};

C_CodeMatcher::C_CodeMatcher() {
    std::string codeblock_pattern;

    std::string codeblock_keywords;
    for ( int i = 0; i < sizeof(c_similarities) / sizeof(c_similarities[0]);
          i++ ) {
        // surrounding a pattern with \Q...\E interprets its contents as
        // literals and not regex expressions
        codeblock_keywords += "\\Q";
        codeblock_keywords += c_similarities[i];
        codeblock_keywords += "\\E";
        codeblock_keywords += "|";
    }
    codeblock_keywords.pop_back(); // remove trailing |

    codeblock_pattern = "\\(.*\\)\\s*{.*(";
    codeblock_pattern += codeblock_keywords;
    codeblock_pattern += ").*}";

    int        pcre2_err;
    PCRE2_SIZE pcre2_erroffset;

    pcre2_code *regex = pcre2_compile((PCRE2_SPTR)codeblock_pattern.data(),
                                      codeblock_pattern.size(), PCRE2_DOTALL,
                                      &pcre2_err, &pcre2_erroffset, nullptr);
    std::cout << "Regex: " << codeblock_pattern << std::endl << std::endl;
    if ( regex == nullptr ) {
        char buffer[256];
        pcre2_get_error_message(pcre2_err, (PCRE2_UCHAR *)buffer,
                                sizeof(buffer));
        std::cout << "Couldn't compile PCRE2 regex: " << codeblock_pattern
                  << std::endl;
        throw std::runtime_error(buffer);
    }

    patterns.push_back(std::make_pair(regex, 1));
}

C_CodeMatcher::~C_CodeMatcher() {
    for ( auto re_weight_pair : patterns ) {
        pcre2_code_free(re_weight_pair.first);
    }
}

static std::string c_code_pattern;

score_t C_CodeMatcher::match(const std::string &text) {
    score_t           score = MIN_SCORE;
    score_t           pattern_weight;
    pcre2_code       *re;
    PCRE2_SIZE        start_offset = 0;
    pcre2_match_data *match_data;
    PCRE2_SIZE       *ovector;

    for ( auto re_weight_pair : patterns ) {
        re = re_weight_pair.first;
        pattern_weight = re_weight_pair.second;
        match_data = pcre2_match_data_create_from_pattern(re, NULL);
        ovector = pcre2_get_ovector_pointer(match_data);
        ovector[1] = 0;

        while ( true ) {
            auto match_result =
                pcre2_match(re, (PCRE2_SPTR)text.data(), text.size(),
                            ovector[1], 0, match_data, nullptr);
            printf("rc = %d\n", match_result);
            for ( int i = 0; i < match_result; i++ ) {
                printf("offset = %zu\n", ovector[i * 2 + 1]);
                printf("%.*s\n", (int)ovector[i * 2 + 1],
                       text.data() + ovector[i * 2]);
            }

            if ( match_result < 0 ) {
                switch ( match_result ) {
                    case PCRE2_ERROR_NOMATCH:
                        printf("Done, score = %d\n", score);
                        break;
                    default:
                        printf("Unknown error when matching: %d\n",
                               match_result);
                        pcre2_match_data_free(match_data);
                        return MAX_SCORE;
                }
                // break out of while loop
                break;
            }
            // continue while loop
            score += pattern_weight;
        }
        pcre2_match_data_free(match_data);
    }

    return score;
}

#define C_CodeMatcher_UNIT_TEST
#ifdef C_CodeMatcher_UNIT_TEST
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
    std::string c_code_text = R"EOF(
(hello){
#define
char*
size_t
size_t
#ifdef
}
	)EOF";
    /*
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
            */

    C_CodeMatcher matcher;
    score_t       non_c_code_score = matcher.match(non_c_code_text);
    score_t       c_code_score = matcher.match(c_code_text);
    std::cout << "Non-C-code score = " << non_c_code_score;
    std::cout << "C-code score = " << c_code_score;
}
#endif
