cmake_minimum_required(VERSION 3.14)
project(roughtime_cpp VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(ENABLE_SANITIZERS "Enable sanitizers (ASan, UBSan)" OFF)
option(ENABLE_COVERAGE "Enable code coverage" OFF)
option(ENABLE_LTO "Enable Link Time Optimization" OFF)
option(BUILD_TESTS "Build tests" ON)

# Add compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)

    # Additional warnings for better code quality
    add_compile_options(
        -Wshadow
        -Wnon-virtual-dtor
        -Wold-style-cast
        -Wcast-align
        -Wunused
        -Woverloaded-virtual
        -Wconversion
        -Wsign-conversion
        -Wformat=2
    )

    # Sanitizers
    if(ENABLE_SANITIZERS)
        message(STATUS "Enabling sanitizers (ASan, UBSan)")
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()

    # Code coverage
    if(ENABLE_COVERAGE)
        message(STATUS "Enabling code coverage")
        add_compile_options(--coverage -fprofile-arcs -ftest-coverage)
        add_link_options(--coverage)
    endif()

    # Link Time Optimization
    if(ENABLE_LTO)
        message(STATUS "Enabling Link Time Optimization")
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# Find required packages
find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.2.0 REQUIRED)
find_package(glog REQUIRED)

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Core library sources (protocol, crypto, config)
set(CORE_LIBRARY_SOURCES
    src/crypto.cpp
    src/protocol.cpp
    src/config.cpp
)

# Create core static library
add_library(roughtime STATIC ${CORE_LIBRARY_SOURCES})
target_link_libraries(roughtime
    PUBLIC
        nlohmann_json::nlohmann_json
        OpenSSL::Crypto
        glog::glog
)
target_include_directories(roughtime
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

# Client library
add_library(roughtime_client STATIC client/src/client.cpp)
target_link_libraries(roughtime_client
    PUBLIC
        roughtime
)

# Client executable
add_executable(getroughtime client/src/main.cpp)
target_link_libraries(getroughtime
    PRIVATE
        roughtime_client
        roughtime
)

# Server library
add_library(roughtime_server STATIC server/src/server.cpp)
target_link_libraries(roughtime_server
    PUBLIC
        roughtime
)

# Server executable
add_executable(roughtime-server server/src/main.cpp)
target_link_libraries(roughtime-server
    PRIVATE
        roughtime_server
        roughtime
)

# Install targets
install(TARGETS roughtime roughtime_client roughtime_server getroughtime roughtime-server
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY include/
    DESTINATION include
)

# Testing
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "==========================================")
message(STATUS "Roughtime C++ Configuration Summary:")
message(STATUS "==========================================")
message(STATUS "  C++ Standard:        ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type:          ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix:      ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
message(STATUS "  Build Options:")
message(STATUS "    Tests:             ${BUILD_TESTS}")
message(STATUS "    Sanitizers:        ${ENABLE_SANITIZERS}")
message(STATUS "    Coverage:          ${ENABLE_COVERAGE}")
message(STATUS "    LTO:               ${ENABLE_LTO}")
message(STATUS "")
message(STATUS "  Executables:         getroughtime, roughtime-server")
message(STATUS "==========================================")
message(STATUS "")
