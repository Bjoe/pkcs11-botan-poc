cmake_minimum_required(VERSION 3.10)

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://codeload.github.com/Bjoe/hunter/legacy.zip/f6ca0b87eb346500546a637288d06797a3d5be15"
    SHA1 "a12427ec2bab7f6ee1adf7e380943c57d53a51a6"
    LOCAL
)

project(pkcs11-botan-poc)

#hunter_add_package(OpenSC)
hunter_add_package(botan)
hunter_add_package(Boost COMPONENTS program_options filesystem system)

#find_package(opensc-pkcs11 CONFIG REQUIRED)
find_package(botan-2 CONFIG REQUIRED)
find_package(Boost REQUIRED program_options filesystem system)

add_executable(pbp main.cpp)
target_link_libraries(pbp PUBLIC Boost::program_options Boost::filesystem Boost::system PkgConfig::botan-2 dl)
