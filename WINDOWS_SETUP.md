# Windows Setup Instructions

1. Install Visual Studio 2019 or later with C++ development tools.
2. Install CMake (https://cmake.org/download/).
3. Open a Developer Command Prompt and navigate to the project directory.
4. Create a build folder:
   ```
   mkdir build && cd build
   cmake ..
   cmake --build .
   ```
5. Run the produced executable from the build directory.
