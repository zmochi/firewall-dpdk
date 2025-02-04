#include "http_methods.hpp"

#include <stdlib.h>
#include <string.h>

#define ARR_SIZE(arr) sizeof(arr)/sizeof(arr[0])

/* struct for associating HTTP method string with its enum code */
struct method_str_code {
    const char      *method_str;
    size_t           method_strlen;
    enum http_method method_code;
};

/* macro must match the name format in `enum http_method` */
#define structify_method(method_name)                                          \
    {#method_name, strlen(#method_name), M_##method_name}

static struct method_str_code methods_strings[] = {
    structify_method(GET),     structify_method(HEAD),
    structify_method(POST),    structify_method(PUT),
    structify_method(DELETE),  structify_method(CONNECT),
    structify_method(OPTIONS), structify_method(TRACE),
};

enum http_method get_method_code(const char *method) {
    struct method_str_code known_method;
    size_t                 num_methods = ARR_SIZE(methods_strings);

    for ( unsigned int i = 0; i < num_methods; i++ ) {
        known_method = methods_strings[i];

        if ( strncmp(method, known_method.method_str,
                     known_method.method_strlen) == 0 )
            return known_method.method_code;
    }

    return M_UNKNOWN;
}
