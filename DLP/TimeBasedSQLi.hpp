#include "filter.hpp"

class TimeBasedSQLi {
    struct pcre2_real_code_8 *compiled;

  public:
    TimeBasedSQLi();
    ~TimeBasedSQLi();
    filter_dc filter_time_based_sqli(const char *data, size_t size);
};
