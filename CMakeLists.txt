cmake_minimum_required(VERSION 3.16)
project(netscope VERSION 2.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # feeds clangd / the VS Code C++ plugin

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "-g -O0")
set(CMAKE_CXX_FLAGS_RELEASE "-O2")

# libpcap has no CMake config package, so look for the header and library.
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY NAMES pcap)
if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
  message(FATAL_ERROR
    "libpcap not found.\n"
    "  Debian/Ubuntu: sudo apt install libpcap-dev\n"
    "  Fedora:        sudo dnf install libpcap-devel\n"
    "  Arch:          sudo pacman -S libpcap")
endif()

# Everything except main() lives in a library so the unit tests can link the
# same objects the binary uses, rather than a recompiled copy.
add_library(netscope_core STATIC
  src/parser.cpp
  src/flow_table.cpp
  src/reassembly.cpp
  src/dissect.cpp
  src/stats.cpp
  src/capture_pcap.cpp
  src/capture_raw.cpp
  src/pcap_writer.cpp
  src/dashboard.cpp
)
target_include_directories(netscope_core PUBLIC include ${PCAP_INCLUDE_DIR})
target_compile_options(netscope_core PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(netscope_core PUBLIC ${PCAP_LIBRARY} pthread)

add_executable(netscope src/main.cpp)
target_compile_options(netscope PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(netscope PRIVATE netscope_core)

# ------------------------------------------------------------------ tests (M13)
enable_testing()
add_executable(netscope_tests tests/test_netscope.cpp)
target_compile_options(netscope_tests PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(netscope_tests PRIVATE netscope_core)
add_test(NAME unit COMMAND netscope_tests)

# Capture needs elevated rights. Linux can grant them per-binary with setcap;
# macOS and the BSDs capture through /dev/bpf*, so permissions go on the devices.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_custom_target(caps
    COMMAND sudo setcap cap_net_raw,cap_net_admin=eip $<TARGET_FILE:netscope>
    DEPENDS netscope
    COMMENT "Granting CAP_NET_RAW to the netscope binary")
else()
  add_custom_target(caps
    COMMAND sudo chgrp admin /dev/bpf*
    COMMAND sudo chmod g+rw /dev/bpf*
    COMMENT "Opening /dev/bpf* to the admin group (resets on reboot)")
endif()
