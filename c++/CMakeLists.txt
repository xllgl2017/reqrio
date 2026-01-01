cmake_minimum_required(VERSION 4.1)
project(reqrio)

set(CMAKE_CXX_STANDARD 20)

add_library(reqrio STATIC bindings.h
        reqrio.cpp
        reqrio.h
        Response.cpp
        Response.h)
link_directories(${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(reqrio reqrio_rs)

add_executable(test_reqrio test.cpp)
target_link_libraries(test_reqrio reqrio)