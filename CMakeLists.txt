cmake_minimum_required(VERSION 3.16)
project(VerifyUP)

set(CMAKE_CXX_STANDARD 17)
find_package(OpenSSL REQUIRED)

add_executable(uptool UPtools.cpp)
target_link_libraries(uptool ${OPENSSL_LIBRARIES})

add_executable(imx6boot imx6boot.cpp)

add_executable(failsafe failsafe.cpp)

add_executable(gencert gencert.cpp)
target_link_libraries(gencert ${OPENSSL_LIBRARIES})


