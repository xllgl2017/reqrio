//
// Created by XLX on 2026/1/1.
//

#include <iostream>
#include <ostream>

#include "Reqrio.h"

int main(int argc, char *argv[]) {
    Reqrio reqrio(HTTP11);
    Response resp = reqrio.get("https://www.baidu.com");
    cout << resp.length() << endl;
}
