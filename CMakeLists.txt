cmake_minimum_required(VERSION 3.10)

include("cmake/HunterGate.cmake")
HunterGate(
  URL "https://codeload.github.com/Bjoe/hunter/legacy.zip/2f74dcf3f8e0dbd2cb775ea936f8874c49c6b2e9"
  SHA1 "d0e4fd92cfc3169734784038720ee77eca2eadae"
  LOCAL
)

project(pkcs11-botan-poc)

#hunter_add_package(OpenSC)
hunter_add_package(botan)
hunter_add_package(Boost COMPONENTS program_options filesystem system)

#find_package(opensc-pkcs11 CONFIG REQUIRED)
find_package(botan-2 CONFIG REQUIRED)
find_package(Boost REQUIRED program_options filesystem system)

add_executable(pbp
  main.cpp
  session.cpp
  deencryptor.cpp
  signverifier.cpp
  generatekey.cpp
)
target_link_libraries(pbp PUBLIC Boost::program_options Boost::filesystem Boost::system PkgConfig::botan-2 dl)
