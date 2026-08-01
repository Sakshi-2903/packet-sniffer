# netscope runbook

This is the shortest path to run tests and record live traffic.

## 1) Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(getconf _NPROCESSORS_ONLN)
```

## 2) Run unit tests

```bash
cmake --build build -j$(getconf _NPROCESSORS_ONLN) --target netscope_tests
./build/netscope_tests
```

## 3) Record live traffic to a pcap

macOS (loopback):

```bash
sudo ./build/netscope -i lo0 -w captures/out.pcap -c 200
```

Linux (loopback):

```bash
sudo ./build/netscope -i lo -w captures/out.pcap -c 200
```

If you want continuous recording, remove the packet limit:

```bash
sudo ./build/netscope -i lo0 -w captures/out.pcap
```

## 4) Replay the recorded file

```bash
./build/netscope -r captures/out.pcap
```

## 5) Optional: generate local traffic while capturing

In another terminal:

```bash
ping -c 5 127.0.0.1
```

## VS Code tasks equivalent

Run these tasks in order:

1. build
2. test
3. run: capture to a pcap file
4. run: replay sample capture (no root needed)

If you captured to captures/out.pcap, replay it with:

```bash
./build/netscope -r captures/out.pcap
```
