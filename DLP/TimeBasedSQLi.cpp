#include "TimeBasedSQLi.hpp"
#include <iostream>
#include <string>

#define PCRE2_CODE_UNIT_WIDTH 8
#include "../external/PCRE2.build/pcre2.h"

static std::string patterns[] = {
    // %20 is space, %28 is (, %29 is ), %2c is , (comma)
    R"END(^POST /.*SELECT%20if%28.+%2csleep%28[\d\.]+%29%2c\d%29.*-- HTTP.*$)END",
};

filter_dc TimeBasedSQLi::filter_time_based_sqli(const char *data, size_t size) {
    filter_dc         dc = FILTER_DROP;
    PCRE2_SIZE        start_offset = 0;
    pcre2_match_data *match_data;
    PCRE2_SIZE       *ovector;
    match_data = pcre2_match_data_create_from_pattern(compiled, NULL);
    ovector = pcre2_get_ovector_pointer(match_data);
    ovector[1] = 0;

    auto match_result = pcre2_match(compiled, (PCRE2_SPTR)data, size,
                                    ovector[1], 0, match_data, nullptr);

    if ( match_result < 0 ) {
        switch ( match_result ) {
            case PCRE2_ERROR_NOMATCH:
                dc = FILTER_PASS;
                break;
            default:
                printf("Unknown error when matching: %d\n", match_result);
                dc = FILTER_DROP;
                break;
        }
    }

    // match_result >= 0, found pattern
    pcre2_match_data_free(match_data);

    return dc;
}

TimeBasedSQLi::TimeBasedSQLi() {
    int          pcre2_err = 0;
    PCRE2_SIZE   pcre2_erroffset = 0;
    std::string &pattern = patterns[0];

    compiled = pcre2_compile((PCRE2_SPTR)pattern.data(), pattern.size(),
                             PCRE2_DOTALL | PCRE2_MULTILINE, &pcre2_err,
                             &pcre2_erroffset, nullptr);
    if ( compiled == nullptr ) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(pcre2_err, buffer, sizeof(buffer));
        std::cout << "Couldn't compile PCRE2 regex: " << pattern << std::endl;
        throw std::runtime_error((char *)buffer);
    }
}

TimeBasedSQLi::~TimeBasedSQLi() { pcre2_code_free(compiled); }
