# Tests using Catch2 framework with ctest integration

# Source files for our unit tests (excluding main test files, we'll create one per executable)
set(COMMON_TEST_LIBS
    nlohmann_json::nlohmann_json
    Catch2::Catch2WithMain
    OpenSSL::Crypto
)

# Define test executables with Catch2
add_executable(test_parser test_parser.cpp)
target_link_libraries(test_parser PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_rule_manager test_rule_manager.cpp)
target_link_libraries(test_rule_manager PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_engine test_engine.cpp)
target_link_libraries(test_engine PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_sni test_sni.cpp)
target_link_libraries(test_sni PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_http test_http.cpp)
target_link_libraries(test_http PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_flowtracker test_flowtracker.cpp)
target_link_libraries(test_flowtracker PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_pcapng test_pcapng.cpp)
target_link_libraries(test_pcapng PRIVATE ${COMMON_TEST_LIBS})

add_executable(test_golden test_golden.cpp)
target_link_libraries(test_golden PRIVATE ${COMMON_TEST_LIBS})

# Register tests with ctest
add_test(NAME parser COMMAND test_parser)
add_test(NAME rule_manager COMMAND test_rule_manager)
add_test(NAME engine COMMAND test_engine)
add_test(NAME sni COMMAND test_sni)
add_test(NAME http COMMAND test_http)
add_test(NAME flowtracker COMMAND test_flowtracker)
add_test(NAME pcapng COMMAND test_pcapng)
add_test(NAME golden COMMAND test_golden)
