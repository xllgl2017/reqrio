//
// Created by XLX on 2026/1/1.
//

#include "Response.h"

#include <utility>

Cookie::Cookie() = default;

Cookie::Cookie(string name, string value) {
    this->name = std::move(name);
    this->value = std::move(value);
}

string Cookie::getName() {
    return this->name;
}

string Cookie::getValue() {
    return this->value;
}

Response::Response(string res) {
}

int Response::length() const {
    return sizeof(this->body);
}
