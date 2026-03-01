# simple tests built alongside main project

add_executable(test_parser test_parser.cpp)
add_executable(test_rule_manager test_rule_manager.cpp)
add_executable(test_engine test_engine.cpp)
add_executable(test_sni test_sni.cpp)
add_executable(test_http test_http.cpp)
add_executable(test_flowtracker test_flowtracker.cpp)
add_executable(test_pcapng test_pcapng.cpp)
add_executable(test_golden test_golden.cpp)

# golden test requires JSON library as well

target_link_libraries(test_parser PRIVATE nlohmann_json::nlohmann_json)
# all of the tests may use json, link globally for simplicity
foreach(t IN ITEMS test_parser test_rule_manager test_engine test_sni test_http test_flowtracker test_pcapng test_golden)
    target_link_libraries(${t} PRIVATE nlohmann_json::nlohmann_json)
endforeach()
