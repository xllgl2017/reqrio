//
// Created by XLX on 2026/1/1.
//

#include "Reqrio.h"

#include <iostream>

#include "bindings.h"

Reqrio::Reqrio() {
    this->hid = bindings::init_http();
}


Reqrio::Reqrio(ALPN alpn) {
    this->hid = bindings::init_http();
    bindings::set_alpn(this->hid, alpn_str(alpn));
}

void Reqrio::set_header_json(const string &header) const {
    bindings::set_header_json(this->hid, header.c_str());
}

void Reqrio::add_header(const string &name, const string &value) const {
    bindings::add_header(this->hid, name.c_str(), value.c_str());
}

void Reqrio::set_alpn(const ALPN alpn) const {
    const char *alpn_str = Reqrio::alpn_str(alpn);
    bindings::set_alpn(this->hid, alpn_str);
}

void Reqrio::set_proxy(const string &proxy) const {
    bindings::set_proxy(this->hid, proxy.c_str());
}

void Reqrio::set_url(const string &url) const {
    bindings::set_url(this->hid, url.c_str());
}

void Reqrio::add_param(const string &name, const string &value) const {
    bindings::add_param(this->hid, name.c_str(), value.c_str());
}

void Reqrio::set_data(const string &data) const {
    bindings::set_data(this->hid, data.c_str());
}

void Reqrio::set_json(const string &json) const {
    bindings::set_json(this->hid, json.c_str());
}

void Reqrio::set_bytes(const char *bytes) const {
    bindings::set_bytes(this->hid, bytes, sizeof(bytes));
}

void Reqrio::set_content_type(const string &content_type) const {
    bindings::set_content_type(this->hid, content_type.c_str());
}

void Reqrio::set_timeout() {
}

void Reqrio::set_cookie(const string &cookie) const {
    bindings::set_cookie(this->hid, cookie.c_str());
}

void Reqrio::add_cookie(const string &name, const string &value) const {
    bindings::add_cookie(this->hid, name.c_str(), value.c_str());
}

Response Reqrio::send(Method method) const {
    char *ptr = nullptr;
    switch (method) {
        case GET:
            ptr = bindings::get(this->hid);
            break;
        case POST:
            ptr = bindings::post(this->hid);
            break;
        case PUT:
            ptr = bindings::put(this->hid);
            break;
        case DELETE:
            // ptr = bindings::delete_(this->hid);
            break;
        case OPTIONS:
            ptr = bindings::options(this->hid);
            break;
        case TRACH:
            ptr = bindings::trach(this->hid);
            break;
        case HEAD:
            ptr = bindings::head(this->hid);
            break;
    }
    if (ptr == nullptr) { return {}; }
    string hex_res = string(ptr);
    std::cout << hex_res<<std::endl;

    Response resp;
    bindings::free_pointer(ptr);
    return resp;
}


Response Reqrio::get(const string &url) const {
    set_url(url);
    return send(GET);
}


Response Reqrio::post(const string &url) const {
    set_url(url);
    return send(POST);
}

Response Reqrio::put(const string &url) const {
    set_url(url);
    return send(PUT);
}

Response Reqrio::head(const string &url) const {
    set_url(url);
    return send(HEAD);
}

Response Reqrio::options(const string &url) const {
    set_url(url);
    return send(OPTIONS);
}

Response Reqrio::trach(const string &url) const {
    set_url(url);
    return send(TRACH);
}

Response Reqrio::delete_(const string &url) const {
    set_url(url);
    return send(DELETE);
}
