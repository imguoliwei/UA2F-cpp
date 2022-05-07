cmake_minimum_required(VERSION 3.18)
project(ua2f)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-O3")

add_executable(ua2f ua2f-mix.cpp)

target_link_libraries(ua2f mnl netfilter_queue pthread)
