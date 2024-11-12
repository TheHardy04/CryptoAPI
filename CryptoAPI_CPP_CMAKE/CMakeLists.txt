# Minimum required CMake version
cmake_minimum_required(VERSION 3.16)

# Project name
project(CryptoAPI_CPP VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Include directories for external libraries
include_directories(include)
include_directories(Dependencies/openssl/include)  # Path to OpenSSL headers
include_directories(Dependencies/Curl/include)     # Path to cURL headers

# Add source files
set(SOURCES
    Src/main.cpp
)

# Add executable
add_executable(CryptoAPI_CPP ${SOURCES})

if(UNIX OR APPLE)
    # Find OpenSSL (using system-installed OpenSSL)
    find_package(OpenSSL REQUIRED)
    # Find and Link cURL (using system-installed cURL)
    find_package(CURL REQUIRED)
    # Link system libraries
    target_link_libraries(CryptoAPI_CPP OpenSSL::SSL OpenSSL::Crypto CURL::libcurl)
elseif(WIN32)
    # Manually link OpenSSL and cURL on Windows
    target_link_libraries(CryptoAPI_CPP
        ${CMAKE_SOURCE_DIR}/Dependencies/openssl/lib/libcrypto.lib  # Static OpenSSL library
        ${CMAKE_SOURCE_DIR}/Dependencies/openssl/lib/libssl.lib     # Static SSL library
        ${CMAKE_SOURCE_DIR}/Dependencies/Curl/lib/libcurl.lib       # Static cURL library
    )

    # Copy the DLLs to the output directory after build
    add_custom_command(TARGET CryptoAPI_CPP POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_SOURCE_DIR}/Dependencies/openssl/bin/libssl-3-x64.dll
            ${CMAKE_SOURCE_DIR}/Dependencies/openssl/bin/libcrypto-3-x64.dll
            ${CMAKE_SOURCE_DIR}/Dependencies/Curl/bin/libcurl.dll
            ${CMAKE_SOURCE_DIR}/Dependencies/zlib/bin/zlib1.dll
            $<TARGET_FILE_DIR:CryptoAPI_CPP>) # Output directory of the .exe
endif()