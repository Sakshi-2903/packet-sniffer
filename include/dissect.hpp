// dissect.hpp -- M10: application-protocol identification.
//
// Ports are a hint, not an answer: HTTP runs on 8080, TLS runs on 8443, and an
// SSH daemon on 443 is a standard way through a restrictive firewall. So these
// dissectors identify protocols from the bytes themselves and use the port only
// to decide what to try first.
//
// TCP dissection reads the reassembled stream prefix (see reassembly.hpp), so a
// ClientHello split across reordered segments is still recognised. UDP is
// datagram-oriented and needs no reassembly.
#pragma once

#include <cstdint>
#include <string>

namespace netscope {

enum class AppProtocol : uint8_t {
  Unknown,
  HTTP,
  TLS,
  DNS,
  SSH,
  DHCP,
  NTP,
  Other,
};

const char* to_string(AppProtocol p);

struct AppInfo {
  AppProtocol proto = AppProtocol::Unknown;
  std::string summary;  // e.g. "TLS1.2 sni=example.com" or "GET example.com/"
  // Set when no further inspection can improve the result, letting the flow
  // release its reassembly buffers.
  bool conclusive = false;

  bool identified() const { return proto != AppProtocol::Unknown; }
};

// Inspects a reassembled TCP stream prefix. `sport`/`dport` are the ports of the
// direction the prefix belongs to. Returns true if `out` was updated.
bool dissect_tcp_stream(const std::string& prefix, uint16_t sport, uint16_t dport,
                        AppInfo& out);

// Inspects a single UDP datagram payload.
bool dissect_udp_payload(const uint8_t* data, size_t len, uint16_t sport,
                         uint16_t dport, AppInfo& out);

// --- individual dissectors, exposed for unit testing -----------------------

bool dissect_http(const std::string& data, AppInfo& out);
bool dissect_tls(const std::string& data, AppInfo& out);
bool dissect_ssh(const std::string& data, AppInfo& out);
bool dissect_dns(const uint8_t* data, size_t len, AppInfo& out);

// Decodes a DNS name in wire format (length-prefixed labels) starting at
// `offset`. Compression pointers are followed. Returns false on a malformed
// name; `consumed` receives the bytes used at `offset` (not inside pointers).
bool decode_dns_name(const uint8_t* msg, size_t msg_len, size_t offset,
                     std::string& name, size_t& consumed);

}  // namespace netscope
