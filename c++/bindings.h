#pragma once

#include <cstdint>

enum Method {
    GET,
    POST,
    PUT,
    OPTIONS,
    DELETE,
    TRACH,
    HEAD
};

namespace bindings {
    extern "C" {
    int init_http();

    int set_header_json(int id, const char *header);

    int add_header(int id, const char *key, const char *value);

    int set_alpn(int id, const char *alpn);

    int set_proxy(int id, const char *proxy);

    int set_url(int id, const char *url);

    int add_param(int id, const char *name, const char *value);

    int set_data(int id, const char *data);

    int set_json(int id, const char *json);

    int set_bytes(int id, const char *bytes, uint32_t len);

    int set_content_type(int id, const char *content_type);

    int set_timeout(int id, const char *timeout);

    int set_cookie(int id, const char *cookie);

    int add_cookie(int id, const char *name, const char *value);

    char *get(int id);

    char *post(int id);

    char *put(int id);

    char *options(int id);

    char *head(int id);

// #define delete delete_
//     char *delete_(int id);

    char *trach(int id);

    void destroy(int id);

    void free_pointer(char *p);
    }
}
