#ifndef __HTTP_METHODS_H_
#define __HTTP_METHODS_H_

enum http_method {
    M_GET,
    M_HEAD,
    M_POST,
    M_PUT,
    M_DELETE,
    M_CONNECT,
    M_OPTIONS,
    M_TRACE,
    M_UNKNOWN,
};

enum http_method get_method_code(const char *method);

#endif /* __HTTP_METHODS_H_ */
