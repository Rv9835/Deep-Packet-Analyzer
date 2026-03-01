cmake_minimum_required(VERSION 3.10)
project(Packet_analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

file(GLOB SOURCES
    "src/*.cpp"
)

add_executable(packet_analyzer ${SOURCES})

# bring in nlohmann_json header‑only library via FetchContent
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(nlohmann_json)

target_link_libraries(packet_analyzer PRIVATE nlohmann_json::nlohmann_json)

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    target_link_libraries(packet_analyzer PRIVATE OpenSSL::Crypto)
endif()

# For future: link libraries like pcap if needed
# find_package(PCAP REQUIRED)
# target_link_libraries(packet_analyzer PRIVATE ${PCAP_LIBRARIES})

# build tests
add_subdirectory(tests)
