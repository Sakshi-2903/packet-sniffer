# Plain make alternative to the CMake build.
#   make            build a debug binary at build/netscope
#   make release    optimised build
#   make sample     regenerate captures/sample.pcap
#   make run        replay the sample capture (no root required)
#   make live       live capture on the loopback interface (uses sudo)
#   make caps       grant CAP_NET_RAW so live capture works without sudo
#   make test       build and run the unit test suite
#   make clean      remove build artefacts

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Wpedantic -Iinclude -g -O0
LDFLAGS  ?= -lpcap -lpthread

CORE_SRC := $(filter-out src/main.cpp,$(wildcard src/*.cpp))
CORE_OBJ := $(patsubst src/%.cpp,build/obj/%.o,$(CORE_SRC))
OBJ      := $(CORE_OBJ) build/obj/main.o
TARGET   := build/netscope
TEST_BIN := build/netscope_tests

.PHONY: all release sample run live caps test clean

all: $(TARGET)

$(TARGET): $(OBJ)
	@mkdir -p build
	$(CXX) $(OBJ) -o $@ $(LDFLAGS)
	@echo "built $@"

$(TEST_BIN): $(CORE_OBJ) build/obj/test_netscope.o
	@mkdir -p build
	$(CXX) $(CORE_OBJ) build/obj/test_netscope.o -o $@ $(LDFLAGS)

build/obj/test_netscope.o: tests/test_netscope.cpp
	@mkdir -p build/obj
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

test: $(TEST_BIN)
	./$(TEST_BIN)

build/obj/%.o: src/%.cpp
	@mkdir -p build/obj
	$(CXX) $(CXXFLAGS) -MMD -MP -c $< -o $@

-include $(OBJ:.o=.d)

release: CXXFLAGS := -std=c++17 -Wall -Wextra -Iinclude -O2 -DNDEBUG
release: clean $(TARGET)

sample:
	python3 tools/make_test_pcap.py captures/sample.pcap

run: $(TARGET) sample
	./$(TARGET) -r captures/sample.pcap

live: $(TARGET)
	sudo ./$(TARGET) -i $(if $(filter Darwin,$(shell uname)),lo0,lo)

# Linux grants capture rights on the binary; macOS/BSD grant them on the BPF
# devices, since capture there goes through /dev/bpf* rather than a socket option.
caps: $(TARGET)
ifeq ($(shell uname),Darwin)
	sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*
	@echo "BPF devices opened to the admin group (resets on reboot)"
else
	sudo setcap cap_net_raw,cap_net_admin=eip $(TARGET)
	@echo "capabilities granted; live capture no longer needs sudo"
endif

clean:
	rm -rf build build-release
