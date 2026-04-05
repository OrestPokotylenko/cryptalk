# Build Instructions

## ESP32 Build (with ESP-IDF)

```bash
idf.py build
idf.py flash
```

## PC Build (Standalone Test)

### Prerequisites
- CMake >= 3.16
- mbedTLS installed on your system

### Linux / macOS
```bash
mkdir build_pc
cd build_pc
cmake -f ../CMakeLists_PC.txt ..
cmake --build .
./cryptalk_test_pc
```

### Windows (with MinGW or MSVC)
```bash
mkdir build_pc
cd build_pc
cmake -f ../CMakeLists_PC.txt .. -G "Unix Makefiles"  # or -G "Visual Studio 17"
cmake --build .
./cryptalk_test_pc
```

### Install mbedTLS

**Ubuntu/Debian:**
```bash
sudo apt-get install libmbedtls-dev
```

**macOS (with Homebrew):**
```bash
brew install mbedtls
```

**Windows (with vcpkg):**
```bash
vcpkg install mbedtls
```

## Project Structure

- `main/` - ESP32 firmware (ESP-IDF component)
- `main/app/main.cpp` - ESP32 entry point (`app_main`)
- `main/core/` - Crypto and messaging logic (shared)
- `tests/` - PC test executables
- `tests/test_main.cpp` - PC test entry point (`main()`)
- `CMakeLists.txt` - ESP-IDF build config
- `CMakeLists_PC.txt` - PC standalone build config
