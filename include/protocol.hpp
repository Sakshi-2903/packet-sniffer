// protocol.hpp -- wire-format header definitions and the decoded-packet struct.
//
// Every struct here mirrors the exact on-wire byte layout of a protocol header,
// so a captured frame can be decoded by bounds-checking and casting rather than
// by copying field-by-field. All multi-byte fields are network byte order
// (big-endian) and must be converted with ntohs/ntohl before use.
#pragma once

#include <arpa/inet.h>
#include <sys/time.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace netscope {

// ---------------------------------------------------------------- link layer

// EtherType values we care about.
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;
constexpr uint16_t ETHERTYPE_QINQ = 0x88A8;

//  0                   1                   2                   3
//  |      dst MAC (6 bytes)      |      src MAC (6 bytes)      | type |
struct EthernetHeader {
  uint8_t dst[6];
  uint8_t src[6];
  uint16_t ethertype;
} __attribute__((packed));
static_assert(sizeof(EthernetHeader) == 14, "bad EthernetHeader layout");

// 802.1Q tag: 4 bytes inserted after the MACs.
struct VlanTag {
  uint16_t tci;  // 3-bit PCP | 1-bit DEI | 12-bit VLAN id
  uint16_t inner_ethertype;
} __attribute__((packed));
static_assert(sizeof(VlanTag) == 4, "bad VlanTag layout");

// --------------------------------------------------------------- network layer

constexpr uint8_t IPPROTO_HOPOPTS_ = 0;
constexpr uint8_t IPPROTO_ICMP_ = 1;
constexpr uint8_t IPPROTO_TCP_ = 6;
constexpr uint8_t IPPROTO_UDP_ = 17;
constexpr uint8_t IPPROTO_IPV6_ROUTE_ = 43;
constexpr uint8_t IPPROTO_IPV6_FRAG_ = 44;
constexpr uint8_t IPPROTO_ICMPV6_ = 58;
constexpr uint8_t IPPROTO_NONXT_ = 59;
constexpr uint8_t IPPROTO_DSTOPTS_ = 60;

//  |ver|ihl| tos |    total length   |
//  |       id      | flags |  frag   |
//  | ttl | proto |     checksum      |
//  |            src address          |
//  |            dst address          |
struct Ipv4Header {
  uint8_t ver_ihl;  // high nibble = version, low nibble = header words
  uint8_t tos;      // DSCP (6 bits) + ECN (2 bits)
  uint16_t total_len;
  uint16_t id;
  uint16_t flags_frag;  // 3 flag bits + 13-bit fragment offset
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;

  uint8_t version() const { return ver_ihl >> 4; }
  uint8_t header_len() const { return static_cast<uint8_t>((ver_ihl & 0x0F) * 4); }
  bool dont_fragment() const { return (ntohs(flags_frag) & 0x4000) != 0; }
  bool more_fragments() const { return (ntohs(flags_frag) & 0x2000) != 0; }
  uint16_t frag_offset() const { return static_cast<uint16_t>((ntohs(flags_frag) & 0x1FFF) * 8); }
  uint8_t dscp() const { return static_cast<uint8_t>(tos >> 2); }
} __attribute__((packed));
static_assert(sizeof(Ipv4Header) == 20, "bad Ipv4Header layout");

struct Ipv6Header {
  uint32_t ver_tc_flow;
  uint16_t payload_len;
  uint8_t next_header;
  uint8_t hop_limit;
  uint8_t src[16];
  uint8_t dst[16];

  uint8_t version() const { return static_cast<uint8_t>(ntohl(ver_tc_flow) >> 28); }
} __attribute__((packed));
static_assert(sizeof(Ipv6Header) == 40, "bad Ipv6Header layout");

// -------------------------------------------------------------- transport layer

// TCP flag bits, in the order they appear in the 6th byte of the 13th octet.
constexpr uint8_t TH_FIN = 0x01;
constexpr uint8_t TH_SYN = 0x02;
constexpr uint8_t TH_RST = 0x04;
constexpr uint8_t TH_PSH = 0x08;
constexpr uint8_t TH_ACK = 0x10;
constexpr uint8_t TH_URG = 0x20;
constexpr uint8_t TH_ECE = 0x40;
constexpr uint8_t TH_CWR = 0x80;

struct TcpHeader {
  uint16_t sport;
  uint16_t dport;
  uint32_t seq;
  uint32_t ack;
  uint8_t offset_ns;  // high nibble = data offset in 32-bit words
  uint8_t flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urgent_ptr;

  uint8_t header_len() const { return static_cast<uint8_t>((offset_ns >> 4) * 4); }
} __attribute__((packed));
static_assert(sizeof(TcpHeader) == 20, "bad TcpHeader layout");

struct UdpHeader {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;  // header + payload
  uint16_t checksum;
} __attribute__((packed));
static_assert(sizeof(UdpHeader) == 8, "bad UdpHeader layout");

struct IcmpHeader {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;   // echo request/reply only
  uint16_t seq;  // echo request/reply only
} __attribute__((packed));
static_assert(sizeof(IcmpHeader) == 8, "bad IcmpHeader layout");

// ------------------------------------------------------------ decoded packet

enum class L3Proto : uint8_t { Unknown, IPv4, IPv6, ARP };
enum class L4Proto : uint8_t { Unknown, TCP, UDP, ICMP, ICMPv6, Other };

const char* to_string(L3Proto p);
const char* to_string(L4Proto p);

// Protocol-agnostic address holder so IPv4 and IPv6 flows share one code path.
struct IpAddress {
  bool is_v6 = false;
  std::array<uint8_t, 16> bytes{};

  static IpAddress from_v4(uint32_t net_order);
  static IpAddress from_v6(const uint8_t raw[16]);
  std::string str() const;

  bool operator==(const IpAddress& o) const {
    return is_v6 == o.is_v6 && bytes == o.bytes;
  }
  // Ordering is only used to canonicalise a flow key, not for anything
  // semantic, so a plain lexicographic compare is fine.
  bool operator<(const IpAddress& o) const {
    if (is_v6 != o.is_v6) return !is_v6;
    return bytes < o.bytes;
  }
};

// Result of decoding one captured frame. Points into the capture buffer, so it
// is only valid until the next packet is read.
struct DecodedPacket {
  timeval ts{};
  uint32_t caplen = 0;   // bytes actually captured
  uint32_t wirelen = 0;  // bytes on the wire (may exceed caplen)

  // L2
  bool has_l2 = false;
  uint8_t src_mac[6]{};
  uint8_t dst_mac[6]{};
  uint16_t ethertype = 0;
  bool has_vlan = false;
  uint16_t vlan_id = 0;

  // L3
  L3Proto l3 = L3Proto::Unknown;
  IpAddress src_ip;
  IpAddress dst_ip;
  uint8_t ttl = 0;
  uint8_t ip_proto = 0;
  uint16_t ip_id = 0;
  uint8_t dscp = 0;
  bool fragmented = false;
  bool first_fragment = true;
  bool bad_ip_checksum = false;

  // L4
  L4Proto l4 = L4Proto::Unknown;
  uint16_t sport = 0;
  uint16_t dport = 0;
  uint32_t seq = 0;
  uint32_t ack = 0;
  uint16_t window = 0;
  uint8_t tcp_flags = 0;
  uint8_t icmp_type = 0;
  uint8_t icmp_code = 0;

  // L7
  const uint8_t* payload = nullptr;
  uint32_t payload_len = 0;

  bool truncated = false;      // snaplen cut a header short
  const char* error = nullptr; // non-null when decoding gave up

  bool has_ports() const { return l4 == L4Proto::TCP || l4 == L4Proto::UDP; }
  std::string tcp_flag_string() const;
};

}  // namespace netscope
