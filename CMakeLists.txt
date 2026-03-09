cmake_minimum_required(VERSION 3.10)
project(Packet_analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ===== Build Configuration =====
# Set standardized build output directories
set(CMAKE_BINARY_DIR "${CMAKE_SOURCE_DIR}/engine/build")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib")

# Add the source directory
include_directories(include)

# ===== Compiler Flags =====
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# Enable sanitizers for non-Windows debug builds
if(NOT WIN32)
    set(SANITIZER_FLAGS "-fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} ${SANITIZER_FLAGS}")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} ${SANITIZER_FLAGS}")
endif()

# ===== Dependencies =====
include(FetchContent)

# nlohmann_json (header-only)
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
)
FetchContent_MakeAvailable(nlohmann_json)

# Catch2 (test framework)
FetchContent_Declare(
    Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.4.0
)
FetchContent_MakeAvailable(Catch2)

# OpenSSL
find_package(OpenSSL REQUIRED)

# ===== Main Executable =====
file(GLOB SOURCES
    "src/*.cpp"
)

add_executable(packet_analyzer ${SOURCES})

target_link_libraries(packet_analyzer PRIVATE 
    nlohmann_json::nlohmann_json
    OpenSSL::Crypto
)

# ===== Testing =====
enable_testing()
add_subdirectory(tests)
