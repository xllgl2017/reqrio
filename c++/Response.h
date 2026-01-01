//
// Created by XLX on 2026/1/1.
//

#ifndef REQRIO_RESPONSE_H
#define REQRIO_RESPONSE_H
#include <list>
#include <string>

#include "bindings.h"
using namespace std;

class Cookie {
    string name;
    string value;
    int age = 0;
    string domain;
    string path;
    bool httpOnly = false;
    bool secure = false;
    string expires;
    string sameSite;
    bool icpsp = false;

public:
    explicit Cookie();

    explicit Cookie(string name, string value);

    string getName();

    string getValue();
};

class Header {
    string name;
    string value;
};

class Headers {
    Method method = GET;
    string agreement;
    string uri;
    int status = -1;
    list<Cookie> cookies;
    list<Header> keys;
};


class Response {
    Headers headers;
    char *body = nullptr;

public:
    Response() = default;
    Response(string res);
    int length() const;

};


#endif //REQRIO_RESPONSE_H
