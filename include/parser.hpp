// parser.hpp -- turns a raw captured frame into a DecodedPacket.
#pragma once

#include <cstdint>

#include "protocol.hpp"

namespace netscope {

// libpcap DLT_* values we handle. Declared here so the parser does not force
// every translation unit to include pcap.h.
enum class LinkType : int {
  Null = 0,       // BSD loopback, 4-byte family header
  Ethernet = 1,   // DLT_EN10MB
  Raw = 101,      // bare IP packet
  LinuxSll = 113, // "any" pseudo-device, 16-byte cooked header
  LinuxSll2 = 276,
};

// Decodes `data[0..caplen)` in place. Returns false if nothing useful could be
// extracted; `out.error` then explains why. Partial decodes (e.g. valid IPv4
// header but a snaplen-truncated TCP header) return true with out.truncated set,
// because the L3 information is still worth counting.
bool decode_packet(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                   const timeval& ts, int linktype, DecodedPacket& out);

// One-line tcpdump-ish rendering, used by --text mode.
std::string format_packet_line(const DecodedPacket& p);

// Standard internet checksum (RFC 1071). Returns 0 for a valid header.
uint16_t internet_checksum(const uint8_t* data, size_t len);

// Best-effort service name for a port, for display only.
const char* service_name(uint16_t port, L4Proto proto);

}  // namespace netscope
