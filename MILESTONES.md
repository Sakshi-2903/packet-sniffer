# Milestones

The project is built in fourteen milestones. Each one is independently
demonstrable: it has a goal, a small set of files, and a command that proves it
works. Nothing depends on a milestone that comes after it, so the build is never
in a half-working state.

If you are rebuilding this from scratch to learn it, work down the list and do
not move on until the "proof" command for the current milestone passes. If you
are reading the finished code, the milestone numbers appear in the header
comments (`// M9: ...`) so you can find where each piece lives.

| # | Milestone | Status |
| --- | --- | --- |
| M0 | Project scaffold and CLI | done |
| M1 | Capture loop | done |
| M2 | Header decoding | done |
| M3 | BPF filtering | done |
| M4 | Flow tracking and TCP state | done |
| M5 | Retransmission heuristics | done |
| M6 | Statistics and summary | done |
| M7 | Terminal dashboard | done |
| M8 | Raw AF_PACKET backend | done |
| M9 | TCP stream reassembly | done |
| M10 | Application protocol dissection | done |
| M11 | Round-trip time estimation | done |
| M12 | pcap file output | done |
| M13 | Unit test suite | done |

---

## Stage 1 — a working sniffer

### M0 · Project scaffold and CLI
**Goal.** A binary that builds, parses arguments, and lists capture interfaces.
**Files.** `CMakeLists.txt`, `Makefile`, `.vscode/*`, `src/main.cpp`, `include/capture.hpp`
**Key decisions.** Header/source split from the start; CMake exports
`compile_commands.json` so IntelliSense and clangd work without extra setup.
**Proof.** `./build/netscope --list` prints your interfaces.

### M1 · Capture loop
**Goal.** Pull frames from a live interface or a `.pcap` file and count them.
**Files.** `src/capture_pcap.cpp`
**Key decisions.** `pcap_create`/`pcap_activate` rather than `pcap_open_live`, so
immediate mode can be requested — without it the kernel batches packets and a
live display updates in visible bursts. `pcap_next_ex` in a loop rather than
`pcap_loop`, so the run flag is checked on every timeout tick and Ctrl-C exits
promptly instead of hanging until the next packet arrives.
**Proof.** `./build/netscope -r captures/sample.pcap -q` reports 79 packets.

### M2 · Header decoding
**Goal.** Turn bytes into fields: Ethernet, VLAN, IPv4, IPv6, TCP, UDP, ICMP.
**Files.** `include/protocol.hpp`, `include/parser.hpp`, `src/parser.cpp`
**Key decisions.** Packed structs matching the on-wire layout, read through a
bounds-checked cursor. Every length in a packet is attacker-controlled, so the
IHL and data-offset fields are validated rather than trusted. IPv4 header
checksums are verified, which costs almost nothing and catches corruption.
**Proof.** `./build/netscope -r captures/sample.pcap -t` output matches
`tcpdump -r captures/sample.pcap`.

### M3 · BPF filtering
**Goal.** Accept a tcpdump-style filter expression.
**Files.** `src/capture_pcap.cpp` (`validate_bpf_filter`)
**Key decisions.** Filters are compiled with `pcap_open_dead` *before* the
capture device is opened, so a typo produces an error immediately instead of
after a `sudo` prompt.
**Proof.** `./build/netscope -r captures/sample.pcap -f "tcp port 443" -q`
counts fewer packets than the unfiltered run; a bad filter is rejected with a
message rather than a crash.

### M4 · Flow tracking and TCP state
**Goal.** Group packets into bidirectional conversations and track connection state.
**Files.** `include/flow.hpp`, `src/flow_table.cpp`
**Key decisions.** The 5-tuple key is canonicalised so both directions hash to
one entry. The state machine is observational, not authoritative: a sniffer can
join mid-connection, so a flow whose first packet is ordinary data is recorded
as already established rather than discarded. The table is bounded and expires
idle flows, because an unbounded map is a memory leak on a busy link.
**Proof.** The sample capture reports 9 flows and states including
`ESTABLISHED`, `CLOSED` and `RESET`.

### M5 · Retransmission heuristics
**Goal.** Detect retransmitted and out-of-order segments.
**Files.** `src/flow_table.cpp` (`track_sequence`)
**Key decisions.** Sequence numbers are compared as signed differences so the
analysis survives the 2³² wrap. Three cases are distinguished: an exact
`(seq, len)` duplicate is a retransmission; a forward jump records a hole and
counts as out-of-order; a late segment that *fills a recorded hole* is a delayed
original, not a resend. That last distinction is the one most naive
implementations get wrong, and it inflates the reported loss rate when missed.
**Proof.** `make test` — the `late hole-filling segment` test fails if the
distinction is dropped.

### M6 · Statistics and summary
**Goal.** Protocol mix, throughput, top talkers, and a closing report.
**Files.** `include/stats.hpp`, `src/stats.cpp`
**Key decisions.** Throughput lives in a ring of 90 one-second buckets, giving
both the sparkline and a "last 5 seconds" rate without storing packet history.
**Proof.** `./build/netscope -r captures/sample.pcap -q` prints the full summary.

### M7 · Terminal dashboard
**Goal.** A live, readable display.
**Files.** `include/dashboard.hpp`, `src/dashboard.cpp`
**Key decisions.** Raw ANSI escapes rather than ncurses — one fewer dependency,
and the escape sequences are worth understanding. The alternate screen buffer
keeps the user's scrollback intact. Each frame is assembled in a reused string
and written in a single `write()`, which removes flicker. Terminal state is
restored on every exit path, including signals.
**Proof.** `./build/netscope -i lo` renders and responds to `q`, `p`, `s`, `r`.

### M8 · Raw AF_PACKET backend
**Goal.** Capture without libpcap's capture path, to show what it does underneath.
**Files.** `src/capture_raw.cpp`
**Key decisions.** `PF_PACKET`/`SOCK_RAW` bound to one interface, with a BPF
program compiled by libpcap and attached with `SO_ATTACH_FILTER` so filtering
happens in the kernel. The filter is attached *before* `bind()` to close the
window where unfiltered frames could already be queued. `struct bpf_insn` and
`struct sock_filter` have identical layouts, which is what makes the handoff
possible.
**Portability.** Linux only, deliberately. macOS and the BSDs capture through
`/dev/bpf*`, which is what libpcap already wraps -- there is no AF_PACKET to
reimplement, so the file compiles to a stub off Linux and `-b raw` says why.
**Proof.** `sudo ./build/netscope -i lo -b raw -f "udp port 9999" -t -c 8`
captures only matching frames (on Linux).

---

## Stage 2 — from sniffer to analyser

### M9 · TCP stream reassembly
**Goal.** Reconstruct the byte stream an application would have received.
**Files.** `include/reassembly.hpp`, `src/reassembly.cpp`
**Why it is needed.** TCP is a byte stream but capture delivers segments. They
arrive out of order, overlap after a retransmission, and repeat. Anything that
reads stream *content* must see the bytes in the order the receiver would.
**Key decisions.** Only a bounded prefix of each direction is kept (8 KB by
default) — application protocols announce themselves in their first few
kilobytes, so once that much is delivered the buffers are released. Overlapping
segments are trimmed rather than rejected, since a retransmission with different
boundaries is normal.
**Proof.** `make test` — reordering, overlap, duplicate and cap tests.

### M10 · Application protocol dissection
**Goal.** Name the protocol: HTTP, TLS (with SNI), DNS, SSH, DHCP, NTP.
**Files.** `include/dissect.hpp`, `src/dissect.cpp`
**Key decisions.** Ports are a hint, not an answer — HTTP runs on 8080, and SSH
on 443 is a standard way through a restrictive firewall — so every dissector
validates its own magic bytes and the port only chooses what to try first. TLS
1.3 is read from the `supported_versions` extension, because the legacy version
field must stay `0x0303` for middlebox compatibility and therefore lies. All
extracted text is sanitised before display: a hostile stream must not be able to
put escape sequences on your terminal.
**Proof.** The sample capture reports `TLS1.3 sni=secure.example.org` for a
ClientHello deliberately split across two segments that arrive out of order —
which only works because M9 runs first.

### M11 · Round-trip time estimation
**Goal.** Measure connection latency from passively observed traffic.
**Files.** `include/flow.hpp` (`RttStats`), `src/flow_table.cpp` (`track_rtt`)
**Key decisions.** Two sources: the SYN → SYN/ACK delay, which is unambiguous,
and data → ACK timing for connections joined mid-stream. Following Karn's
algorithm, retransmitted segments produce no samples — it is impossible to tell
whether the ACK answered the original or the retry, and including such samples
biases the estimate badly. One sample per ACK, so a cumulative acknowledgement
of many segments cannot skew the average. Smoothed the way TCP itself does
(RFC 6298, α = 1/8).
**Proof.** `./build/netscope -i lo` against local traffic shows sub-millisecond
RTT; the sample capture shows 18–30 ms for its synthetic WAN flows.

### M12 · pcap file output
**Goal.** Save what was captured, for later replay or inspection in Wireshark.
**Files.** `include/pcap_writer.hpp`, `src/pcap_writer.cpp`
**Key decisions.** The format is written directly rather than via `pcap_dump`,
for two reasons: the AF_PACKET backend has no `pcap_t` to dump through, and a
file written by your own code that Wireshark can open is a strong cross-check on
the decoder. Frames are written *before* analysis, so a crash in the decoder
still leaves the offending frame on disk to reproduce with.
**Proof.** `make test` — the round-trip test writes a file and reads it back
through libpcap. Also `tcpdump -r` the output.

### M13 · Unit test suite
**Goal.** Lock down the analysis logic that live traffic cannot exercise reliably.
**Files.** `tests/test_netscope.cpp`
**Key decisions.** No gtest, no catch2 — a dependency-free harness so
`make test` works on a fresh clone. The tests concentrate on what is hard to
reproduce on a real network and easy to get wrong: sequence wraparound,
reordered and overlapping segments, truncated and malformed headers, DNS
compression-pointer loops, and Karn's algorithm. One test decodes *every prefix*
of a valid frame to prove the parser cannot be walked off the end of its buffer.
**Proof.** `make test` → 171 checks, 0 failures.

---

## What is deliberately not built

Worth knowing so you can answer for it rather than being caught out:

- **No IP fragment reassembly.** Fragments are counted and later ones are
  attributed to a flow by address alone, since they carry no transport header.
- **No TLS decryption.** Only the unencrypted handshake is read. SNI is
  visible; everything after it is not.
- **No IPv6 flow-label handling** and no tunnelling (GRE, VXLAN, IP-in-IP).
- **AF_PACKET uses `recvfrom`, not a `TPACKET_V3` mmap ring.** The ring is the
  zero-copy path and would raise the ceiling on a saturated link; the socket
  buffer is enlarged instead, and kernel drops are reported so you can tell when
  it matters.

## Natural next milestones

- **M14 · TPACKET_V3 ring buffer** — zero-copy capture for multi-gigabit links.
- **M15 · IP fragment reassembly** — feeding reassembled datagrams to the decoder.
- **M16 · Prometheus metrics endpoint** — expose flow and error counters over HTTP.
- **M17 · Anomaly detection** — port-scan and SYN-flood signatures from the
  existing per-flow SYN/RST counters, which are already collected.
