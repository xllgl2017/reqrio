//
// Created by XLX on 2026/1/1.
//

#ifndef UNTITLED_REQRIO_H
#define UNTITLED_REQRIO_H
#include <string>

#include "Response.h"
using namespace std;

enum ALPN {
    HTTP20,
    HTTP11,
};


class Reqrio {
    int hid;

public:
    explicit Reqrio();

    explicit Reqrio(ALPN alpn);

    void set_header_json(const string &header) const;

    void add_header(const string &name, const string &value) const;

    void set_alpn(ALPN alpn) const;

    void set_proxy(const string &proxy) const;

    void add_param(const string &name, const string &value) const;

    void set_data(const string &data) const;

    void set_json(const string &json) const;

    void set_bytes(const char *bytes) const;

    void set_content_type(const string &content_type) const;

    void set_timeout();

    void set_cookie(const string &cookie) const;

    void add_cookie(const string &name, const string &value) const;

    Response get(const string &url) const;

    Response post(const string &url) const;

    Response put(const string &url) const;

    Response options(const string &url) const;

    Response head(const string &url) const;

    Response delete_(const string &url) const;

    Response trach(const string &url) const;

private:
    void set_url(const string &url) const;

    Response send(Method method) const;

    static const char *alpn_str(ALPN alpn) {
        switch (alpn) {
            case HTTP20:
                return "h2";
            case HTTP11:
                return "http/1.1";
        }
        return "";
    };
};


#endif //UNTITLED_REQRIO_H
