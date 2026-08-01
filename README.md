# netscope — packet sniffer and protocol analyser

A Linux packet capture and analysis tool in C++17. It decodes Ethernet, IPv4/IPv6,
TCP, UDP and ICMP headers straight off the wire, tracks every conversation as a
bidirectional flow with a TCP connection-state machine, reassembles TCP streams
to identify application protocols, estimates round-trip time passively, and
reports protocol distribution, retransmission rate and throughput in a live
terminal dashboard.

Built in fourteen independently testable milestones -- see
[MILESTONES.md](MILESTONES.md) for the breakdown, the design decision behind
each one, and the command that proves it works.

Two interchangeable capture backends are included: **libpcap** (portable, also
replays `.pcap` files) and a raw **AF_PACKET** socket with a kernel-attached BPF
program, which is what libpcap uses underneath on Linux.

```
 netscope  iface=eth0  backend=libpcap  bpf="tcp"  up 2m14s
 pkts 48.2K   vol 41.7 MB   now 3.71 Mbps / 412 pps   avg 2.55 Mbps   flows 37/291
 drops 0   decode-err 0   trunc 0   bad-cksum 0   frags 0   snaplen 262144

 PROTOCOL DISTRIBUTION
  TCP   ████████████████████████████████░░░░░░░░  81%      39.1K pkts    38.2 MB
  UDP   ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  16%       7.7K pkts     3.1 MB
  ICMP  █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   2%        980 pkts      412 KB

 THROUGHPUT  (last 90s, peak 8.42 Mbps)
  ▁▂▂▃▅▄▃▂▂▁▁▂▄▆▇█▇▅▃▂▂▂▃▃▄▄▅▆▇▇▆▄▃▂▂▁▁▂▃▄▄▅▅▄▃▃▂▂▂▃▄▅▆▆▅▄▃▂▂▁▁▂▃▄▅▅▄▃▂▂▁▂▃▄▅▆▇▇▆

 TCP HEALTH  established 21   syn 302   fin 264   rst 7   retrans 118 / 31402 (0.38%)   ooo 44   rtt 24.8 ms
 APPLICATION  TLS 24  HTTP 9  DNS 6  SSH 1

 TOP FLOWS  sorted by bytes
  PROTO ENDPOINTS                                STATE        PKTS   BYTES RETX     RTT   AGE  APPLICATION
  TCP   93.184.216.34:443 <-> 192.168.1.50:51000 ESTABLISHED 12.1K  11.8MB   41  22.4ms  1m2s  TLS1.3 sni=example.com
  TCP   140.82.121.4:443 <-> 192.168.1.50:51122  ESTABLISHED  8.4K   7.9MB    3  31.7ms   58s  TLS1.3 sni=github.com
  UDP   192.168.1.1:53 <-> 192.168.1.50:53535    -             214  31.2KB    0       -  2m11s  DNS query A example.com
  TCP   10.0.0.7:8080 <-> 192.168.1.50:51001     RESET           2    108B    0       -    9s

 q quit   p pause   s sort   r reset
```

---

## Build

Dependencies: a C++17 compiler, `libpcap` development headers, and CMake (or just
`make`).

```bash
# Debian / Ubuntu
sudo apt install build-essential cmake libpcap-dev

# Fedora
sudo dnf install gcc-c++ cmake libpcap-devel

# Arch
sudo pacman -S base-devel cmake libpcap

# macOS -- libpcap ships with the system; you only need the toolchain
xcode-select --install
brew install cmake
```

Then:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(nproc)
```

or, without CMake:

```bash
make            # debug build at build/netscope
make release    # optimised build
```

### Running in VS Code

Open the folder (`code .`) and install the recommended extensions when prompted
(C/C++ and CMake Tools).

| Action | How |
| --- | --- |
| Build | `Ctrl+Shift+B` (`Cmd+Shift+B` on macOS) |
| Debug against a capture file (no root) | `F5` → *Debug: replay sample.pcap* |
| Run tests | `Ctrl+Shift+P` → *Tasks: Run Test Task* |
| Run any preset | `Ctrl+Shift+P` → *Tasks: Run Task* |

The tasks detect the platform, so *grant capture permissions* and the loopback
capture tasks do the right thing on both Linux and macOS. Debug configurations
use gdb on Linux and lldb on macOS automatically.

The tasks list includes generating the sample capture, replaying it, live capture
on loopback, granting capture capabilities, and starting a `sudo gdbserver` for
debugging live capture (pair it with the *Attach to live capture* launch config —
a debugger cannot trace a privileged process otherwise).

### Capture permissions

Reading raw frames is privileged on every platform, but the mechanism differs.

**Linux** grants capture rights per binary. Run with `sudo`, or once per rebuild:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip build/netscope   # or: make caps
./build/netscope -i eth0                                   # no sudo needed
```

**macOS** captures through the BPF character devices, so the permission lives on
`/dev/bpf*` rather than on the binary. Either run with `sudo`, or open the
devices to your admin group (this resets on reboot):

```bash
sudo chgrp admin /dev/bpf* && sudo chmod g+rw /dev/bpf*     # or: make caps
```

Wireshark's ChmodBPF helper does the same thing persistently, if you have it
installed.

### Platform notes

The libpcap backend works on Linux, macOS and the BSDs. The AF_PACKET backend
(`-b raw`) is **Linux only** -- `AF_PACKET`, `SO_ATTACH_FILTER` and
`<linux/filter.h>` are kernel interfaces with no portable equivalent. On macOS
and the BSDs, capture goes through `/dev/bpf*`, which is exactly what libpcap
wraps: there the libpcap backend already *is* the raw path, so reimplementing it
would duplicate libpcap rather than reveal anything. `src/capture_raw.cpp`
compiles to a stub off Linux and `-b raw` explains itself instead of failing.

Interface names differ too: loopback is `lo` on Linux and `lo0` on macOS, and
your main NIC is typically `eth0`/`enp3s0` versus `en0`. Run
`./build/netscope -L` to see what your system actually has. On macOS, `lo0` uses
the `DLT_NULL` link type (a 4-byte address family instead of an Ethernet
header), which the decoder handles.

---

## Usage

```
netscope [options]

capture source
  -i, --interface <name>   interface to capture from (default: first active NIC)
  -r, --read <file.pcap>   replay a capture file instead of a live interface
  -L, --list               list available interfaces and exit

filtering and limits
  -f, --filter <bpf>       BPF expression, e.g. "tcp port 443 or icmp"
  -c, --count <n>          stop after n packets
  -s, --snaplen <n>        bytes to capture per frame (default 262144)
  -P, --no-promisc         do not put the interface in promiscuous mode

backend and output
  -b, --backend <pcap|raw> capture backend (default pcap; raw = AF_PACKET socket)
  -w, --write <file.pcap>  save captured frames to a pcap file (readable by Wireshark)
  -t, --text               print one line per packet instead of the dashboard
  -q, --quiet              with --text, print only the closing summary
  -e, --expire <sec>       idle timeout before a flow is evicted (default 120)
  -D, --no-dissect         skip stream reassembly and application decoding
```

```bash
# Live dashboard on eth0
sudo ./build/netscope -i eth0

# Web traffic only, ignoring your own SSH session
sudo ./build/netscope -i eth0 -f "tcp port 443 or tcp port 80 and not port 22"

# Raw AF_PACKET backend, 200 packets, tcpdump-style output
sudo ./build/netscope -i eth0 -b raw -t -c 200

# No hardware needed: replay the synthetic capture
python3 tools/make_test_pcap.py captures/sample.pcap
./build/netscope -r captures/sample.pcap

# Record traffic for later analysis (the file opens in Wireshark)
sudo ./build/netscope -i eth0 -f "tcp port 443" -w captures/tls.pcap
```

Dashboard keys: `q` quit, `p` pause, `s` cycle flow sort (bytes → packets →
retransmits → most recent), `r` reset counters.

Every run ends with a summary: totals, protocol breakdown, TCP health, RTT,
application protocols identified, top service ports, top talkers and the
heaviest flows.

### Tests

```bash
make test          # or: cmake --build build --target netscope_tests && ./build/netscope_tests
```

171 checks covering sequence wraparound, reordered and overlapping segments,
truncated and malformed headers, DNS compression-pointer loops, Karn's
algorithm and a pcap write/read round-trip. In VS Code: *Tasks: Run Test Task*.

---

## How it works

```
                                              ┌─► reassembly ─► dissectors
                                              │   (M9)          HTTP/TLS/DNS/SSH
   NIC ──► capture backend ──► decoder ──► flow table ──► statistics
           libpcap / AF_PACKET   parser  │  TCP state  │    counters
           + BPF in kernel               │  machine    │    + throughput ring
                    │                    └─► RTT       │
                    └─► pcap writer (M12)    (M11)     │
                                                       │
                                    capture thread     │     UI thread
                                    ──────────────────────────────────
                                                     terminal dashboard
```

The capture backend runs on its own thread and hands each frame to `Analyzer`,
which decodes it, updates the flow table and the counters under a single mutex.
The main thread renders the dashboard at 10 fps from the same structures. The
critical section is a few hundred nanoseconds of integer work per packet, so
contention never becomes the bottleneck — the kernel's ring buffer does.

**Decoding.** Every protocol header is a packed struct matching the on-wire byte
layout (`include/protocol.hpp`), and all reads go through a bounds-checked cursor,
so a malformed or snaplen-truncated frame can never walk off the end of the
buffer. The decoder unwraps up to two levels of VLAN tagging, skips IPv6
extension headers, honours the IPv4 IHL and TCP data-offset fields when locating
the payload, and verifies the IPv4 header checksum.

**Flow tracking.** Both directions of a conversation map to one table entry: the
key is the 5-tuple canonicalised so the numerically lower `(address, port)` is
always endpoint A. Per-direction counters cover packets, wire bytes, payload
bytes, retransmissions, out-of-order segments and TCP flag tallies.

**Connection state.** A simplified TCP state machine advances
`SYN_SENT → SYN_RECV → ESTABLISHED → FIN_WAIT → CLOSING → CLOSED`, with `RST`
short-circuiting to `RESET`. It is deliberately observational rather than
authoritative: a sniffer can join mid-connection or miss packets, so a flow whose
first packet is ordinary data is recorded as already established instead of being
discarded.

**Retransmission detection** uses two signals per direction. A 64-entry window of
recent `(sequence, length)` fingerprints catches exact duplicates, and any data
segment ending at or below the highest sequence number already seen is old data
being resent. Segments arriving beyond the expected sequence number are counted
as out-of-order instead. Comparisons use signed differences, so the analysis
stays correct across the 2³² sequence-number wrap.

**Stream reassembly and dissection.** TCP is a byte stream, but capture delivers
segments that arrive out of order, overlap after a retransmission, and repeat.
A per-direction reassembler puts them back in the order the receiving
application would have seen, and the dissectors read *that* — so a TLS
ClientHello split across reordered segments still yields its SNI. Only a bounded
prefix (8 KB) is retained; application protocols announce themselves early, so
once the protocol is identified the buffers are released and memory stays flat
on long-lived connections. Ports only decide which dissector to try first: each
one validates its own magic bytes, so HTTP on 8080 or SSH on 443 is still found.
All extracted text is sanitised, because a hostile stream must not be able to
write escape sequences to your terminal.

**Round-trip time** comes from two passive sources: the SYN → SYN/ACK delay, and
data → ACK timing for connections joined mid-stream. Retransmitted segments
produce no samples (Karn's algorithm) — an ACK cannot be attributed to the
original or the retry, so such samples would bias the estimate. Values are
smoothed the way TCP smooths its own RTT (RFC 6298, α = 1/8).

**Throughput** is accumulated into a ring of 90 one-second buckets, giving both
the sparkline and the "last 5 seconds" rate without storing any packet history.

**Flow-table growth** is bounded: idle flows are expired on a timer (closed and
reset flows sooner), and if the table hits its cap the least recently active entry
is evicted.

### Verifying the analysis

`tools/make_test_pcap.py` writes a synthetic capture containing a full TCP
handshake and teardown, a duplicated data segment, a sequence gap, a refused
connection, DNS, HTTP and SSH exchanges, a TLS ClientHello split across
reordered segments, ICMP echoes and a packet with a deliberately corrupted IPv4
checksum — so every code path above can be exercised without
special privileges or live traffic:

```
$ ./build/netscope -r captures/sample.pcap -q
tcp
  flows tracked     : 9 (9 still active)
  syn/fin/rst       : 9 / 2 / 1
  retransmissions   : 1 of 10 data segments (10.00%)
  out-of-order      : 4 segments
  stream reassembly : 1.9 KB delivered in order
  round-trip time   : 19.00 ms mean over 7 samples

application protocols identified
  DNS           2 flows
  TLS           2 flows
  SSH           1 flows
  HTTP          1 flows
```

The TLS flow in that capture has its ClientHello split across two segments that
arrive **out of order**, so `TLS1.3 sni=secure.example.org` in the flow table is
proof that reassembly ran before dissection.

---

## Layout

```
include/
  protocol.hpp    on-wire header structs, decoded-packet representation
  parser.hpp      decoder interface, checksum, formatting helpers
  capture.hpp     capture backend interface and configuration
  flow.hpp        flow key, TCP state machine, per-flow counters, RTT
  reassembly.hpp  in-order TCP stream reconstruction
  dissect.hpp     application protocol identification
  pcap_writer.hpp pcap file output
  stats.hpp       aggregate counters and throughput ring
  analyzer.hpp    thread-safe decode → flow → stats pipeline
  dashboard.hpp   terminal UI and summary reporter
src/
  parser.cpp        Ethernet / VLAN / IPv4 / IPv6 / TCP / UDP / ICMP decoding
  capture_pcap.cpp  libpcap live capture, file replay, BPF compilation
  capture_raw.cpp   AF_PACKET socket with SO_ATTACH_FILTER
  flow_table.cpp    flow tracking, state machine, retransmission, RTT
  reassembly.cpp    segment reordering, overlap trimming, bounded buffering
  dissect.cpp       HTTP, TLS (SNI), DNS, SSH, DHCP, NTP
  pcap_writer.cpp   pcap file format writer
  stats.cpp         protocol distribution, throughput, top ports and talkers
  dashboard.cpp     ANSI dashboard (no ncurses) and closing report
  main.cpp          CLI, signal handling, capture thread and render loop
tests/
  test_netscope.cpp dependency-free unit test suite
tools/
  make_test_pcap.py synthetic capture generator
```

## Known limits

- Only the first 8 KB of each stream direction is reassembled -- enough to
  identify a protocol, not to extract a full response body.
- TLS is read only up to the handshake: SNI is visible, payload is not.
- IPv4/IPv6 fragments are counted but not reassembled; only the first fragment
  carries a transport header, and later ones are attributed to the flow by
  addresses alone.
- Retransmission detection is heuristic. A capture point that sees only one
  direction, or drops packets under load, will inflate the count — the reported
  kernel drop counter is the number to sanity-check first.
- The AF_PACKET backend is Linux-only, by design (see Platform notes). The
  libpcap backend is portable and is what runs everywhere else.

## Possible extensions

See the closing section of [MILESTONES.md](MILESTONES.md): a `TPACKET_V3` mmap
ring for zero-copy capture, IP fragment reassembly, a Prometheus metrics
endpoint, and port-scan / SYN-flood detection built on the per-flow SYN and RST
counters that are already collected.
