#include "C_CodeMatcher.hpp"
#include <iostream>
#include <limits>

static std::string c_similarities[] = {
    "#ifdef",       "#ifndef",  "void main(int argc, char* argv[])",
    "#define",      "typedef",  "char *",
    "int *",        "char*",    "int*",
    "int",          "char",     "size_t",
    "return NULL;", "#include", "stdio.h",
    "stdlib.h"};

C_CodeMatcher::C_CodeMatcher() {
    std::string codeblock_pattern;
    int         pcre2_err;
    PCRE2_SIZE  pcre2_erroffset;

    for ( int i = 0; i < sizeof(c_similarities) / sizeof(c_similarities[0]);
          i++ ) {

        // surrounding a pattern with \Q...\E interprets its contents as
        // literals and not regex expressions
        codeblock_pattern = "\\Q";
        codeblock_pattern += c_similarities[i];
        codeblock_pattern += "\\E";

        // free'd at desctructor
        pcre2_code *regex = pcre2_compile(
            (PCRE2_SPTR)codeblock_pattern.data(), codeblock_pattern.size(),
            PCRE2_DOTALL, &pcre2_err, &pcre2_erroffset, nullptr);
        if ( regex == nullptr ) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(pcre2_err, buffer, sizeof(buffer));
            std::cout << "Couldn't compile PCRE2 regex: " << codeblock_pattern
                      << std::endl;
            throw std::runtime_error((char *)buffer);
        }

        patterns.push_back(std::make_pair(regex, 1));
    }
}

C_CodeMatcher::~C_CodeMatcher() {
    for ( auto re_weight_pair : patterns ) {
        pcre2_code_free(re_weight_pair.first);
    }
}

static std::vector<std::pair<size_t, size_t>>
find_braces(const char open, const char close, const std::string_view text) {
    std::vector<size_t>                    braces_stack;
    std::vector<std::pair<size_t, size_t>> brace_locations;

    for ( size_t i = 0; i < text.size(); i++ ) {
        if ( text.at(i) == open ) {
            brace_locations.push_back(
                std::make_pair(i, std::numeric_limits<size_t>::max()));
            braces_stack.push_back(brace_locations.size() - 1);
        } else if ( text.at(i) == close ) {
            brace_locations.at(braces_stack.back()).second = i;
            braces_stack.pop_back();
        }
    }

    return brace_locations;
}

score_t C_CodeMatcher::match(const std::string_view text) {
    using namespace std;
    score_t           score = MIN_SCORE;
    score_t           pattern_weight;
    pcre2_code       *re;
    PCRE2_SIZE        start_offset = 0;
    pcre2_match_data *match_data;
    PCRE2_SIZE       *ovector;

    vector<pair<size_t, size_t>> curly_braces = find_braces('{', '}', text);

    /*
     * search inside all of non-nested instances of {...} in `text`
     */
    size_t min_brace_idx;
    for ( size_t i = 0; i < curly_braces.size(); ) {
        auto brace_pair = curly_braces.at(i);
        min_brace_idx = brace_pair.second + 1;

        if ( curly_braces.size() < 1 ||
             brace_pair.second == std::numeric_limits<size_t>::max() ) {
            // couldn't find opening {, or couldn't find closing }
            return score;
        }

        std::string_view text_tomatch(text.data() + brace_pair.first,
                                      brace_pair.second - brace_pair.first - 1);
        /*
printf("Matching inside:\n%.*s", (int)text_tomatch.size(),
       text_tomatch.data());
   */
        for ( auto re_weight_pair : patterns ) {
            re = re_weight_pair.first;
            pattern_weight = re_weight_pair.second;
            match_data = pcre2_match_data_create_from_pattern(re, NULL);
            ovector = pcre2_get_ovector_pointer(match_data);
            ovector[1] = 0;

            while ( true ) {
                auto match_result = pcre2_match(
                    re, (PCRE2_SPTR)text_tomatch.data(), text_tomatch.size(),
                    ovector[1], 0, match_data, nullptr);
                /*
printf("rc = %d\n", match_result);
for ( int i = 0; i < match_result; i++ ) {
    printf("%.*s\n", (int)(ovector[i * 2 + 1] - ovector[i * 2]),
           text_tomatch.data() + ovector[i * 2]);
}
                */

                if ( match_result < 0 ) {
                    switch ( match_result ) {
                        case PCRE2_ERROR_NOMATCH:
							/*
                            printf("Done, score = %d\n", score);
							*/
                            break;
                        default:
                            printf("Unknown error when matching: %d\n",
                                   match_result);
                            pcre2_match_data_free(match_data);
                            return MAX_SCORE;
                    }
                    break;
                }
                score += pattern_weight;
            }
            pcre2_match_data_free(match_data);
        }

        // skip over all nested braces
        do {
            i++;
        } while ( i < curly_braces.size() &&
                  curly_braces.at(i).second < min_brace_idx );
    }

    return score;
}

#ifdef C_CodeMatcher_UNIT_TEST
#include <cassert>
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

    //							   						  0123456789012
    std::string                            braces_test = "{}{a{a}a{a}a}";
    std::vector<std::pair<size_t, size_t>> expected = {
        {0, 1}, {2, 12}, {4, 6}, {8, 10}};
    assert(find_braces('{', '}', braces_test) == expected);

    C_CodeMatcher matcher;
    score_t       non_c_code_score = matcher.match(non_c_code_text);
    score_t       c_code_score = matcher.match(c_code_text);
    std::cout << "Non-C-code score = " << non_c_code_score << std::endl;
    ;
    std::cout << "C-code score = " << c_code_score << std::endl;
    ;
}
#endif
