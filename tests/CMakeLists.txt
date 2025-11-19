cmake_minimum_required(VERSION 3.14)

# Find GTest
find_package(GTest REQUIRED)
include(GoogleTest)

# Protocol unit tests
add_executable(protocol_test protocol_test.cpp)
target_link_libraries(protocol_test
    PRIVATE
        roughtime
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(protocol_test)

# Crypto unit tests
add_executable(crypto_test crypto_test.cpp)
target_link_libraries(crypto_test
    PRIVATE
        roughtime
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(crypto_test)

# Client integration tests (server as fixture)
add_executable(client_integration_test client_integration_test.cpp)
target_link_libraries(client_integration_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
)
gtest_discover_tests(client_integration_test)

# Server integration tests (client tests server)
add_executable(server_integration_test server_integration_test.cpp)
target_link_libraries(server_integration_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(server_integration_test)

# Rogue server tests (security tests)
add_executable(rogue_server_test rogue_server_test.cpp)
target_link_libraries(rogue_server_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(rogue_server_test)

# Security and robustness tests
add_executable(security_test security_test.cpp)
target_link_libraries(security_test
    PRIVATE
        roughtime
        roughtime_client
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(security_test)

# Server performance tests
add_executable(server_performance_test server_performance_test.cpp)
target_link_libraries(server_performance_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(server_performance_test)

# Causal ordering tests (RFC 8.2 compliance)
add_executable(causal_ordering_test causal_ordering_test.cpp)
target_link_libraries(causal_ordering_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(causal_ordering_test)

# Grease tests (RFC Section 7 compliance)
add_executable(grease_test grease_test.cpp)
target_link_libraries(grease_test
    PRIVATE
        roughtime
        roughtime_client
        roughtime_server
        GTest::gtest
        GTest::gtest_main
)
gtest_discover_tests(grease_test)

# Add custom target to run all tests
add_custom_target(check
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS protocol_test crypto_test client_integration_test server_integration_test rogue_server_test security_test server_performance_test causal_ordering_test grease_test
    COMMENT "Running all tests..."
)
