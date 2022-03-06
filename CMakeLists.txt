cmake_minimum_required(VERSION 3.18)
project(ua2f)

set(CMAKE_CXX_STANDARD 20)

add_executable(ua2f ua2f.cpp)

target_link_libraries(ua2f mnl netfilter_queue)
