// M13: unit tests.
//
// Deliberately dependency-free -- no gtest, no catch2 -- so `make test` works on
// a fresh clone with nothing installed beyond libpcap. The point of these tests
// is the analysis logic that live traffic cannot exercise reliably: sequence
// wraparound, reordered segments, malformed headers, truncated captures. Those
// are exactly the cases that are hard to reproduce on a real network and easy to
// get wrong.
#include <arpa/inet.h>

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "capture.hpp"
#include "dissect.hpp"
#include "flow.hpp"
#include "parser.hpp"
#include "pcap_writer.hpp"
#include "reassembly.hpp"
#include "stats.hpp"

using namespace netscope;

// ------------------------------------------------------------- test harness

namespace {

int g_checks = 0;
int g_failures = 0;
const char* g_current_test = "";

void report_failure(const char* file, int line, const std::string& detail) {
  ++g_failures;
  std::printf("  FAIL %s:%d  [%s]\n       %s\n", file, line, g_current_test,
              detail.c_str());
}

#define CHECK(cond)                                                    \
  do {                                                                 \
    ++g_checks;                                                        \
    if (!(cond)) report_failure(__FILE__, __LINE__, "expected: " #cond); \
  } while (0)

#define CHECK_EQ(actual, expected)                                            \
  do {                                                                        \
    ++g_checks;                                                               \
    auto a_ = (actual);                                                       \
    auto e_ = (expected);                                                     \
    if (!(a_ == e_)) {                                                        \
      std::string d = std::string(#actual) + " == " + std::to_string(a_) +     \
                      ", expected " + std::to_string(e_);                     \
      report_failure(__FILE__, __LINE__, d);                                  \
    }                                                                         \
  } while (0)

#define CHECK_STR_EQ(actual, expected)                                    \
  do {                                                                    \
    ++g_checks;                                                           \
    std::string a_ = (actual);                                            \
    std::string e_ = (expected);                                          \
    if (a_ != e_) {                                                       \
      report_failure(__FILE__, __LINE__,                                  \
                     std::string(#actual) + " == \"" + a_ +               \
                         "\", expected \"" + e_ + "\"");                  \
    }                                                                     \
  } while (0)

#define CHECK_NEAR(actual, expected, tol)                                     \
  do {                                                                        \
    ++g_checks;                                                               \
    double a_ = (actual), e_ = (expected);                                     \
    if (!(a_ >= e_ - (tol) && a_ <= e_ + (tol))) {                             \
      report_failure(__FILE__, __LINE__,                                      \
                     std::string(#actual) + " == " + std::to_string(a_) +      \
                         ", expected ~" + std::to_string(e_));                \
    }                                                                         \
  } while (0)

void run_test(const char* name, void (*fn)()) {
  g_current_test = name;
  const int before = g_failures;
  fn();
  std::printf("%s %s\n", (g_failures == before) ? "  ok  " : "  --  ", name);
}

// ---------------------------------------------------- packet builder helpers

uint16_t checksum16(const uint8_t* data, size_t len) {
  return internet_checksum(data, len);
}

void append16(std::vector<uint8_t>& v, uint16_t x) {
  v.push_back(static_cast<uint8_t>(x >> 8));
  v.push_back(static_cast<uint8_t>(x & 0xFF));
}

void append32(std::vector<uint8_t>& v, uint32_t x) {
  v.push_back(static_cast<uint8_t>(x >> 24));
  v.push_back(static_cast<uint8_t>((x >> 16) & 0xFF));
  v.push_back(static_cast<uint8_t>((x >> 8) & 0xFF));
  v.push_back(static_cast<uint8_t>(x & 0xFF));
}

std::vector<uint8_t> ethernet_header(uint16_t ethertype) {
  std::vector<uint8_t> v;
  for (int i = 0; i < 6; ++i) v.push_back(static_cast<uint8_t>(0x10 + i));  // dst
  for (int i = 0; i < 6; ++i) v.push_back(static_cast<uint8_t>(0x20 + i));  // src
  append16(v, ethertype);
  return v;
}

uint32_t ipv4_addr(const char* text) {
  in_addr a{};
  inet_pton(AF_INET, text, &a);
  return a.s_addr;  // network byte order
}

// Builds an Ethernet + IPv4 frame around `payload`.
std::vector<uint8_t> make_ipv4_frame(const char* src, const char* dst, uint8_t proto,
                                     const std::vector<uint8_t>& payload,
                                     bool corrupt_checksum = false,
                                     bool vlan = false, uint16_t vlan_id = 0,
                                     uint16_t frag_field = 0x4000) {
  std::vector<uint8_t> ip;
  ip.push_back(0x45);                                        // version 4, IHL 5
  ip.push_back(0x00);                                        // TOS
  append16(ip, static_cast<uint16_t>(20 + payload.size()));   // total length
  append16(ip, 0x1234);                                      // id
  append16(ip, frag_field);                                  // flags + offset
  ip.push_back(64);                                          // TTL
  ip.push_back(proto);
  append16(ip, 0);                                           // checksum placeholder
  const uint32_t s = ipv4_addr(src), d = ipv4_addr(dst);
  ip.insert(ip.end(), reinterpret_cast<const uint8_t*>(&s),
            reinterpret_cast<const uint8_t*>(&s) + 4);
  ip.insert(ip.end(), reinterpret_cast<const uint8_t*>(&d),
            reinterpret_cast<const uint8_t*>(&d) + 4);
  uint16_t csum = checksum16(ip.data(), ip.size());
  if (corrupt_checksum) csum = static_cast<uint16_t>(csum ^ 0xFFFF);
  ip[10] = static_cast<uint8_t>(csum >> 8);
  ip[11] = static_cast<uint8_t>(csum & 0xFF);
  ip.insert(ip.end(), payload.begin(), payload.end());

  std::vector<uint8_t> frame;
  if (vlan) {
    frame = ethernet_header(ETHERTYPE_VLAN);
    append16(frame, vlan_id);
    append16(frame, ETHERTYPE_IPV4);
  } else {
    frame = ethernet_header(ETHERTYPE_IPV4);
  }
  frame.insert(frame.end(), ip.begin(), ip.end());
  return frame;
}

std::vector<uint8_t> tcp_segment(uint16_t sport, uint16_t dport, uint32_t seq,
                                 uint32_t ack, uint8_t flags,
                                 const std::string& payload = "",
                                 uint16_t window = 64240) {
  std::vector<uint8_t> v;
  append16(v, sport);
  append16(v, dport);
  append32(v, seq);
  append32(v, ack);
  v.push_back(0x50);  // data offset 5 words, no options
  v.push_back(flags);
  append16(v, window);
  append16(v, 0);  // checksum (not verified by the decoder)
  append16(v, 0);  // urgent pointer
  v.insert(v.end(), payload.begin(), payload.end());
  return v;
}

std::vector<uint8_t> udp_datagram(uint16_t sport, uint16_t dport,
                                  const std::vector<uint8_t>& payload) {
  std::vector<uint8_t> v;
  append16(v, sport);
  append16(v, dport);
  append16(v, static_cast<uint16_t>(8 + payload.size()));
  append16(v, 0);
  v.insert(v.end(), payload.begin(), payload.end());
  return v;
}

timeval tv(long sec, long usec) {
  timeval t{};
  t.tv_sec = static_cast<decltype(t.tv_sec)>(sec);
  t.tv_usec = static_cast<decltype(t.tv_usec)>(usec);
  return t;
}

DecodedPacket decode(const std::vector<uint8_t>& frame, const timeval& ts = tv(1000, 0)) {
  DecodedPacket p;
  decode_packet(frame.data(), static_cast<uint32_t>(frame.size()),
                static_cast<uint32_t>(frame.size()), ts, 1 /* DLT_EN10MB */, p);
  return p;
}

// Feeds a TCP segment through a flow table and returns the resulting flow.
Flow* feed_tcp(FlowTable& table, const char* src, const char* dst, uint16_t sport,
               uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags,
               const std::string& payload, const timeval& ts) {
  const auto frame = make_ipv4_frame(src, dst, IPPROTO_TCP_,
                                     tcp_segment(sport, dport, seq, ack, flags, payload));
  DecodedPacket p = decode(frame, ts);
  return table.update(p);
}

// ------------------------------------------------------------------- M2 tests

void test_internet_checksum() {
  // A correct IPv4 header must checksum to zero.
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                     tcp_segment(1234, 80, 1, 0, TH_SYN));
  CHECK_EQ(internet_checksum(frame.data() + 14, 20), 0);
}

void test_decode_tcp_over_ipv4() {
  const auto frame = make_ipv4_frame("192.168.1.10", "93.184.216.34", IPPROTO_TCP_,
                                     tcp_segment(51000, 443, 1000, 2000,
                                                 TH_SYN | TH_ACK, "hello"));
  const DecodedPacket p = decode(frame);
  CHECK(p.error == nullptr);
  CHECK(p.l3 == L3Proto::IPv4);
  CHECK(p.l4 == L4Proto::TCP);
  CHECK_STR_EQ(p.src_ip.str(), "192.168.1.10");
  CHECK_STR_EQ(p.dst_ip.str(), "93.184.216.34");
  CHECK_EQ(p.sport, 51000);
  CHECK_EQ(p.dport, 443);
  CHECK_EQ(p.seq, 1000u);
  CHECK_EQ(p.ack, 2000u);
  CHECK_EQ(p.payload_len, 5u);
  CHECK_EQ(p.ttl, 64);
  CHECK_STR_EQ(p.tcp_flag_string(), "SA");
  CHECK(!p.bad_ip_checksum);
  CHECK(!p.truncated);
}

void test_decode_udp_and_icmp() {
  const auto udp = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_UDP_,
                                   udp_datagram(53535, 53, {1, 2, 3, 4}));
  const DecodedPacket p = decode(udp);
  CHECK(p.l4 == L4Proto::UDP);
  CHECK_EQ(p.sport, 53535);
  CHECK_EQ(p.payload_len, 4u);

  std::vector<uint8_t> icmp = {8, 0, 0, 0, 0x12, 0x34, 0, 1};  // echo request
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_ICMP_, icmp);
  const DecodedPacket q = decode(frame);
  CHECK(q.l4 == L4Proto::ICMP);
  CHECK_EQ(q.icmp_type, 8);
  CHECK_EQ(q.icmp_code, 0);
  CHECK(!q.has_ports());
}

void test_decode_vlan_tagged() {
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                     tcp_segment(1111, 2222, 1, 0, TH_SYN),
                                     false, true, 42);
  const DecodedPacket p = decode(frame);
  CHECK(p.has_vlan);
  CHECK_EQ(p.vlan_id, 42);
  CHECK(p.l4 == L4Proto::TCP);
  CHECK_EQ(p.sport, 1111);
}

void test_decode_null_linktype_loopback() {
  // DLT_NULL (BSD/macOS loopback): a 4-byte host-order address family instead of
  // an Ethernet header. AF_INET is 2; macOS uses 30 for AF_INET6.
  const auto eth_frame = make_ipv4_frame("127.0.0.1", "127.0.0.1", IPPROTO_UDP_,
                                         udp_datagram(9999, 53, {1, 2, 3}));
  std::vector<uint8_t> null_frame(4, 0);
  const uint32_t af_inet = 2;
  std::memcpy(null_frame.data(), &af_inet, 4);  // host byte order, by definition
  null_frame.insert(null_frame.end(), eth_frame.begin() + 14, eth_frame.end());

  DecodedPacket p;
  CHECK(decode_packet(null_frame.data(), static_cast<uint32_t>(null_frame.size()),
                      static_cast<uint32_t>(null_frame.size()), tv(1, 0),
                      0 /* DLT_NULL */, p));
  CHECK(p.l3 == L3Proto::IPv4);
  CHECK(p.l4 == L4Proto::UDP);
  CHECK_EQ(p.sport, 9999);
  CHECK(!p.has_l2);  // no MAC addresses on a loopback capture
}

void test_decode_bad_checksum_flagged() {
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_UDP_,
                                     udp_datagram(1, 2, {0}), true);
  const DecodedPacket p = decode(frame);
  CHECK(p.bad_ip_checksum);
  CHECK(p.error == nullptr);  // still decodable, just corrupt
}

void test_decode_truncation_is_safe() {
  // Every prefix of a valid frame must decode without reading out of bounds.
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                     tcp_segment(80, 90, 5, 6, TH_ACK, "payload"));
  for (size_t len = 0; len <= frame.size(); ++len) {
    DecodedPacket p;
    decode_packet(frame.data(), static_cast<uint32_t>(len),
                  static_cast<uint32_t>(frame.size()), tv(1, 0), 1, p);
    // No assertion on the result: the requirement is that it does not crash or
    // read past `len`, which ASan/valgrind would catch. Consistency is checked.
    if (p.error == nullptr && p.l4 == L4Proto::TCP && !p.truncated) {
      CHECK(len >= 14 + 20 + 20);
    }
  }
  // A frame cut inside the TCP header must be marked, not silently accepted.
  DecodedPacket p;
  decode_packet(frame.data(), 14 + 20 + 10, static_cast<uint32_t>(frame.size()),
                tv(1, 0), 1, p);
  CHECK(p.truncated);
  CHECK(p.l3 == L3Proto::IPv4);
}

void test_decode_non_initial_fragment_has_no_ports() {
  // Fragment offset 185 (in 8-byte units) with more-fragments clear.
  const auto frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                     tcp_segment(80, 90, 1, 0, TH_ACK, "x"),
                                     false, false, 0, 185);
  const DecodedPacket p = decode(frame);
  CHECK(p.fragmented);
  CHECK(!p.first_fragment);
  CHECK(!p.has_ports());  // no transport header in a later fragment
}

// ------------------------------------------------------------------- M4 tests

void test_sequence_wraparound_comparison() {
  // Numbers straddling the 2^32 boundary must compare by signed difference.
  CHECK(seq_lt(0xFFFFFF00u, 0x00000100u));
  CHECK(seq_gt(0x00000100u, 0xFFFFFF00u));
  CHECK(seq_le(42u, 42u));
  CHECK(!seq_lt(0x00000100u, 0xFFFFFF00u));
}

void test_flow_key_is_direction_agnostic() {
  const auto a = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                 tcp_segment(51000, 443, 1, 0, TH_SYN));
  const auto b = make_ipv4_frame("10.0.0.2", "10.0.0.1", IPPROTO_TCP_,
                                 tcp_segment(443, 51000, 5, 2, TH_SYN | TH_ACK));
  bool fwd_a = false, fwd_b = false;
  const FlowKey ka = make_flow_key(decode(a), fwd_a);
  const FlowKey kb = make_flow_key(decode(b), fwd_b);
  CHECK(ka == kb);              // one flow, not two
  CHECK(fwd_a != fwd_b);        // opposite directions
  CHECK_EQ(FlowKeyHash{}(ka), FlowKeyHash{}(kb));

  FlowTable table;
  table.update(decode(a));
  table.update(decode(b));
  CHECK_EQ(table.size(), 1u);
}

void test_tcp_state_machine_full_lifecycle() {
  FlowTable table;
  table.set_dissection_enabled(false);
  const char* c = "10.0.0.1";
  const char* s = "10.0.0.2";

  Flow* f = feed_tcp(table, c, s, 51000, 443, 100, 0, TH_SYN, "", tv(1, 0));
  CHECK(f->state == TcpState::SynSent);
  f = feed_tcp(table, s, c, 443, 51000, 500, 101, TH_SYN | TH_ACK, "", tv(1, 20000));
  CHECK(f->state == TcpState::SynReceived);
  f = feed_tcp(table, c, s, 51000, 443, 101, 501, TH_ACK, "", tv(1, 21000));
  CHECK(f->state == TcpState::Established);
  CHECK(f->handshake_complete);

  f = feed_tcp(table, c, s, 51000, 443, 101, 501, TH_ACK | TH_FIN, "", tv(2, 0));
  CHECK(f->state == TcpState::FinWait);
  f = feed_tcp(table, s, c, 443, 51000, 501, 102, TH_ACK | TH_FIN, "", tv(2, 10000));
  CHECK(f->state == TcpState::Closing);
  f = feed_tcp(table, c, s, 51000, 443, 102, 502, TH_ACK, "", tv(2, 11000));
  CHECK(f->state == TcpState::Closed);
}

void test_tcp_reset_and_midstream_join() {
  FlowTable table;
  table.set_dissection_enabled(false);
  Flow* f = feed_tcp(table, "10.0.0.1", "10.0.0.2", 51001, 8080, 1, 0, TH_SYN, "", tv(1, 0));
  f = feed_tcp(table, "10.0.0.2", "10.0.0.1", 8080, 51001, 0, 2, TH_RST | TH_ACK, "", tv(1, 5000));
  CHECK(f->state == TcpState::Reset);

  // A flow whose first observed packet is ordinary data is treated as already
  // established rather than discarded -- a sniffer often joins mid-connection.
  FlowTable other;
  other.set_dissection_enabled(false);
  Flow* g = feed_tcp(other, "10.0.0.3", "10.0.0.4", 40000, 80, 9000, 1, TH_ACK, "data", tv(1, 0));
  CHECK(g->state == TcpState::Established);
}

// ------------------------------------------------------------------- M5 tests

void test_retransmission_detection() {
  FlowTable table;
  table.set_dissection_enabled(false);
  const char* c = "10.0.0.1";
  const char* s = "10.0.0.2";
  const std::string data(200, 'A');

  feed_tcp(table, c, s, 51000, 443, 100, 0, TH_SYN, "", tv(1, 0));
  feed_tcp(table, s, c, 443, 51000, 500, 101, TH_SYN | TH_ACK, "", tv(1, 10000));
  feed_tcp(table, c, s, 51000, 443, 101, 501, TH_ACK, "", tv(1, 11000));

  Flow* f = feed_tcp(table, c, s, 51000, 443, 101, 501, TH_ACK | TH_PSH, data, tv(1, 12000));
  CHECK_EQ(f->retransmits(), 0u);
  // Exactly the same segment again: a retransmission.
  f = feed_tcp(table, c, s, 51000, 443, 101, 501, TH_ACK | TH_PSH, data, tv(1, 300000));
  CHECK_EQ(f->retransmits(), 1u);
  CHECK_EQ(table.total_retransmits(), 1u);
  // Data segments counted: two (the duplicate counts as a segment seen).
  CHECK_EQ(table.total_tcp_data_segments(), 2u);

  // A forward jump is a gap, not a retransmission.
  f = feed_tcp(table, c, s, 51000, 443, 101 + 200 + 500, 501, TH_ACK, data, tv(1, 320000));
  CHECK_EQ(f->out_of_order(), 1u);
  CHECK_EQ(f->retransmits(), 1u);

  // Pure ACKs are not data and must not inflate the denominator.
  const uint64_t before = table.total_tcp_data_segments();
  feed_tcp(table, s, c, 443, 51000, 501, 301, TH_ACK, "", tv(1, 330000));
  CHECK_EQ(table.total_tcp_data_segments(), before);
}

void test_late_segment_filling_a_hole_is_not_a_retransmission() {
  // The distinction that matters for the headline retransmission rate: a
  // segment arriving after a later one, filling the gap it left behind, is a
  // delayed original. Counting it as a retransmission overstates packet loss.
  FlowTable table;
  table.set_dissection_enabled(false);
  const char* c = "10.0.0.1";
  const char* s = "10.0.0.2";
  const std::string seg(500, 'X');

  feed_tcp(table, c, s, 51000, 443, 1000, 1, TH_ACK, seg, tv(1, 0));         // 1000-1500
  Flow* f = feed_tcp(table, c, s, 51000, 443, 2000, 1, TH_ACK, seg, tv(1, 1000));  // jump
  CHECK_EQ(f->out_of_order(), 1u);
  CHECK_EQ(f->retransmits(), 0u);

  // The missing middle finally arrives.
  f = feed_tcp(table, c, s, 51000, 443, 1500, 1, TH_ACK, seg, tv(1, 5000));
  CHECK_EQ(f->retransmits(), 0u);   // not a resend
  CHECK_EQ(f->out_of_order(), 2u);  // late delivery

  // But genuinely resending data that was never missing still counts.
  f = feed_tcp(table, c, s, 51000, 443, 1000, 1, TH_ACK, seg, tv(2, 0));
  CHECK_EQ(f->retransmits(), 1u);
}

// ------------------------------------------------------------------- M9 tests

void test_reassembly_in_order() {
  StreamReassembler r;
  r.push(1000, nullptr, 0, true);  // SYN anchors the ISN
  const std::string a = "hello ";
  const std::string b = "world";
  CHECK_EQ(r.push(1001, reinterpret_cast<const uint8_t*>(a.data()), a.size(), false), 6u);
  CHECK_EQ(r.push(1007, reinterpret_cast<const uint8_t*>(b.data()), b.size(), false), 5u);
  CHECK_STR_EQ(r.prefix(), "hello world");
  CHECK(!r.has_gap());
}

void test_reassembly_reordered() {
  StreamReassembler r;
  r.push(500, nullptr, 0, true);
  const std::string first = "AAA";
  const std::string second = "BBB";
  const std::string third = "CCC";

  // Third segment arrives before the second: it must be held, not appended.
  CHECK_EQ(r.push(501, reinterpret_cast<const uint8_t*>(first.data()), 3, false), 3u);
  CHECK_EQ(r.push(507, reinterpret_cast<const uint8_t*>(third.data()), 3, false), 0u);
  CHECK(r.has_gap());
  CHECK_STR_EQ(r.prefix(), "AAA");
  // Filling the gap releases both segments at once.
  CHECK_EQ(r.push(504, reinterpret_cast<const uint8_t*>(second.data()), 3, false), 6u);
  CHECK_STR_EQ(r.prefix(), "AAABBBCCC");
  CHECK(!r.has_gap());
}

void test_reassembly_overlap_and_duplicates() {
  StreamReassembler r;
  r.push(0, nullptr, 0, true);
  const std::string abcdef = "ABCDEF";
  CHECK_EQ(r.push(1, reinterpret_cast<const uint8_t*>(abcdef.data()), 6, false), 6u);
  // Exact duplicate: contributes nothing.
  CHECK_EQ(r.push(1, reinterpret_cast<const uint8_t*>(abcdef.data()), 6, false), 0u);
  // Partial overlap: only the tail beyond next_seq is new.
  const std::string efgh = "EFGH";
  CHECK_EQ(r.push(5, reinterpret_cast<const uint8_t*>(efgh.data()), 4, false), 2u);
  CHECK_STR_EQ(r.prefix(), "ABCDEFGH");
  CHECK(r.overlap_bytes() >= 6);
}

void test_reassembly_respects_prefix_cap() {
  StreamReassembler r(16, 64);  // tiny caps to make the boundary testable
  r.push(0, nullptr, 0, true);
  const std::string chunk(10, 'x');
  r.push(1, reinterpret_cast<const uint8_t*>(chunk.data()), 10, false);
  r.push(11, reinterpret_cast<const uint8_t*>(chunk.data()), 10, false);
  CHECK_EQ(r.prefix().size(), 16u);  // capped
  CHECK(r.saturated());
  CHECK_EQ(r.bytes_delivered(), 20u);  // still tracked accurately
}

// ------------------------------------------------------------------ M10 tests

std::string make_tls_client_hello(const std::string& sni, bool tls13) {
  std::vector<uint8_t> ext;
  // server_name extension
  std::vector<uint8_t> sni_ext;
  append16(sni_ext, static_cast<uint16_t>(sni.size() + 3));  // list length
  sni_ext.push_back(0x00);                                   // name type: host_name
  append16(sni_ext, static_cast<uint16_t>(sni.size()));
  sni_ext.insert(sni_ext.end(), sni.begin(), sni.end());
  append16(ext, 0x0000);
  append16(ext, static_cast<uint16_t>(sni_ext.size()));
  ext.insert(ext.end(), sni_ext.begin(), sni_ext.end());

  if (tls13) {
    append16(ext, 0x002B);  // supported_versions
    append16(ext, 3);
    ext.push_back(2);       // list length in bytes
    append16(ext, 0x0304);  // TLS 1.3
  }

  std::vector<uint8_t> body;
  append16(body, 0x0303);                       // legacy version
  for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(i));  // random
  body.push_back(0);                            // session id length
  append16(body, 2);                            // cipher suites length
  append16(body, 0x1301);                       // one cipher suite
  body.push_back(1);                            // compression methods length
  body.push_back(0);                            // null compression
  append16(body, static_cast<uint16_t>(ext.size()));
  body.insert(body.end(), ext.begin(), ext.end());

  std::vector<uint8_t> handshake;
  handshake.push_back(0x01);  // client hello
  handshake.push_back(0);     // 24-bit length
  append16(handshake, static_cast<uint16_t>(body.size()));
  handshake.insert(handshake.end(), body.begin(), body.end());

  std::vector<uint8_t> record;
  record.push_back(0x16);  // handshake
  append16(record, 0x0301);
  append16(record, static_cast<uint16_t>(handshake.size()));
  record.insert(record.end(), handshake.begin(), handshake.end());
  return std::string(record.begin(), record.end());
}

void test_dissect_tls_sni() {
  AppInfo info;
  CHECK(dissect_tls(make_tls_client_hello("example.com", false), info));
  CHECK(info.proto == AppProtocol::TLS);
  CHECK_STR_EQ(info.summary, "TLS1.2 sni=example.com");
  CHECK(info.conclusive);

  // TLS 1.3 hides its version in supported_versions; the legacy field lies.
  AppInfo v13;
  CHECK(dissect_tls(make_tls_client_hello("cdn.example.org", true), v13));
  CHECK_STR_EQ(v13.summary, "TLS1.3 sni=cdn.example.org");

  // A truncated hello must fail cleanly rather than read out of bounds.
  const std::string full = make_tls_client_hello("example.com", false);
  for (size_t n = 1; n < full.size(); ++n) {
    AppInfo partial;
    dissect_tls(full.substr(0, n), partial);  // must not crash
  }
  AppInfo not_tls;
  CHECK(!dissect_tls("GET / HTTP/1.1\r\n\r\n", not_tls));
}

void test_dissect_http() {
  AppInfo info;
  CHECK(dissect_http("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", info));
  CHECK(info.proto == AppProtocol::HTTP);
  CHECK_STR_EQ(info.summary, "GET example.com/index.html");
  CHECK(info.conclusive);

  AppInfo resp;
  CHECK(dissect_http("HTTP/1.1 404 Not Found\r\nServer: nginx\r\n\r\n", resp));
  CHECK_STR_EQ(resp.summary, "HTTP/1.1 404 Not Found");

  // Control characters from a hostile stream must not reach the terminal.
  AppInfo evil;
  CHECK(dissect_http("GET /\x1b[31mred HTTP/1.1\r\nHost: a.com\r\n\r\n", evil));
  CHECK(evil.summary.find('\x1b') == std::string::npos);

  AppInfo none;
  CHECK(!dissect_http("NOTHTTP data here", none));
}

void test_dissect_dns() {
  // Query for example.com, type A.
  std::vector<uint8_t> msg = {0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  const char* labels = "\7example\3com";
  msg.insert(msg.end(), labels, labels + 12);
  msg.push_back(0x00);
  append16(msg, 1);  // qtype A
  append16(msg, 1);  // qclass IN

  AppInfo info;
  CHECK(dissect_dns(msg.data(), msg.size(), info));
  CHECK(info.proto == AppProtocol::DNS);
  CHECK_STR_EQ(info.summary, "query A example.com");

  std::string name;
  size_t consumed = 0;
  CHECK(decode_dns_name(msg.data(), msg.size(), 12, name, consumed));
  CHECK_STR_EQ(name, "example.com");
  CHECK_EQ(consumed, 13u);

  // A compression pointer that loops must be rejected, not followed forever.
  std::vector<uint8_t> loop = {0xC0, 0x00};
  std::string bad;
  size_t used = 0;
  CHECK(!decode_dns_name(loop.data(), loop.size(), 0, bad, used));

  // Truncated messages must fail cleanly.
  for (size_t n = 0; n < msg.size(); ++n) {
    AppInfo partial;
    dissect_dns(msg.data(), n, partial);
  }
}

void test_dissect_ssh() {
  AppInfo info;
  CHECK(dissect_ssh("SSH-2.0-OpenSSH_9.6\r\n", info));
  CHECK(info.proto == AppProtocol::SSH);
  CHECK_STR_EQ(info.summary, "SSH-2.0-OpenSSH_9.6");
}

void test_dissection_across_reordered_segments() {
  // The point of M9: a ClientHello split across segments that arrive out of
  // order is still identified, because dissection reads the reassembled stream.
  FlowTable table;
  const std::string hello = make_tls_client_hello("split.example.com", false);
  const size_t cut = hello.size() / 2;
  const std::string part1 = hello.substr(0, cut);
  const std::string part2 = hello.substr(cut);

  feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443, 100, 0, TH_SYN, "", tv(1, 0));
  feed_tcp(table, "10.0.0.2", "10.0.0.1", 443, 51000, 500, 101, TH_SYN | TH_ACK, "", tv(1, 10000));
  feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443, 101, 501, TH_ACK, "", tv(1, 11000));

  // Second half first.
  Flow* f = feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443,
                     static_cast<uint32_t>(101 + cut), 501, TH_ACK, part2, tv(1, 12000));
  CHECK(!f->app.identified());  // nothing usable yet: the stream starts with a hole
  f = feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443, 101, 501, TH_ACK | TH_PSH,
               part1, tv(1, 13000));
  CHECK(f->app.identified());
  CHECK(f->app.proto == AppProtocol::TLS);
  CHECK_STR_EQ(f->app.summary, "TLS1.2 sni=split.example.com");

  const auto apps = table.app_protocols();
  CHECK_EQ(apps.size(), 1u);
  CHECK(apps[0].first == AppProtocol::TLS);
  CHECK_EQ(apps[0].second, 1u);
}

// ------------------------------------------------------------------ M11 tests

void test_rtt_from_handshake() {
  FlowTable table;
  table.set_dissection_enabled(false);
  feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443, 100, 0, TH_SYN, "", tv(10, 0));
  Flow* f = feed_tcp(table, "10.0.0.2", "10.0.0.1", 443, 51000, 500, 101,
                     TH_SYN | TH_ACK, "", tv(10, 25000));  // +25 ms
  CHECK_NEAR(f->handshake_rtt_ms, 25.0, 0.5);
  CHECK_NEAR(f->best_rtt_ms(), 25.0, 0.5);
}

void test_rtt_from_data_acks_ignores_retransmits() {
  FlowTable table;
  table.set_dissection_enabled(false);
  const char* c = "10.0.0.1";
  const char* s = "10.0.0.2";
  const std::string data(100, 'D');

  // Join mid-stream so no handshake sample exists and data ACKs are the source.
  Flow* f = feed_tcp(table, c, s, 51000, 443, 1000, 1, TH_ACK | TH_PSH, data, tv(20, 0));
  f = feed_tcp(table, s, c, 443, 51000, 1, 1100, TH_ACK, "", tv(20, 40000));  // +40 ms
  CHECK(f->best_rtt_ms() >= 0.0);
  CHECK_NEAR(f->best_rtt_ms(), 40.0, 1.0);
  CHECK_EQ(f->fwd.rtt.samples + f->rev.rtt.samples, 1u);

  // A retransmitted segment must produce no sample (Karn's algorithm): the ACK
  // could be answering either copy, so the measurement would be meaningless.
  const uint64_t before = f->fwd.rtt.samples + f->rev.rtt.samples;
  f = feed_tcp(table, c, s, 51000, 443, 1000, 1, TH_ACK | TH_PSH, data, tv(21, 0));
  CHECK_EQ(f->retransmits(), 1u);
  f = feed_tcp(table, s, c, 443, 51000, 1, 1100, TH_ACK, "", tv(21, 90000));
  CHECK_EQ(f->fwd.rtt.samples + f->rev.rtt.samples, before);
}

void test_rtt_smoothing_and_bounds() {
  RttStats r;
  r.add(100.0);
  r.add(20.0);
  CHECK_EQ(r.samples, 2u);
  CHECK_NEAR(r.min_ms, 20.0, 0.001);
  CHECK_NEAR(r.max_ms, 100.0, 0.001);
  CHECK_NEAR(r.srtt_ms, 0.875 * 100.0 + 0.125 * 20.0, 0.001);
  // Implausible samples (clock jumps, bad capture timestamps) are rejected.
  r.add(-5.0);
  r.add(999999.0);
  CHECK_EQ(r.samples, 2u);
}

// ------------------------------------------------------------------ M12 tests

void test_pcap_writer_roundtrip() {
  std::string tmpdir = "/tmp";
  if (const char* env_tmpdir = std::getenv("TMPDIR"); env_tmpdir && env_tmpdir[0] != '\0') {
    tmpdir = env_tmpdir;
  }
  if (!tmpdir.empty() && tmpdir.back() != '/') {
    tmpdir.push_back('/');
  }
  const std::string path = tmpdir + "netscope_test_out.pcap";
  std::remove(path.c_str());

  const std::vector<std::vector<uint8_t>> frames = {
      make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                      tcp_segment(51000, 443, 1, 0, TH_SYN)),
      make_ipv4_frame("10.0.0.2", "10.0.0.1", IPPROTO_TCP_,
                      tcp_segment(443, 51000, 9, 2, TH_SYN | TH_ACK)),
      make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_UDP_,
                      udp_datagram(5353, 5353, {0, 1, 2, 3, 4})),
  };

  {
    PcapWriter w;
    std::string err;
    CHECK(w.open(path, 1 /* DLT_EN10MB */, 65535, err));
    long sec = 1700000000;
    for (const auto& f : frames) {
      w.write(f.data(), static_cast<uint32_t>(f.size()),
              static_cast<uint32_t>(f.size()), tv(sec++, 500));
    }
    CHECK_EQ(w.packets_written(), 3u);
    w.close();
  }

  // Read it back through the real capture backend: if libpcap can parse it, so
  // can Wireshark and tcpdump.
  auto capture = make_pcap_capture();
  CaptureConfig cfg;
  cfg.pcap_file = path;
  std::string err;
  CHECK(capture->open(cfg, err));
  CHECK_EQ(capture->linktype(), 1);

  std::vector<uint32_t> lengths;
  std::vector<uint16_t> ports;
  std::atomic<bool> running{true};
  auto sink = [&](const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                  const timeval& ts) {
    lengths.push_back(wirelen);
    DecodedPacket p;
    if (decode_packet(data, caplen, wirelen, ts, 1, p) && p.has_ports()) {
      ports.push_back(p.sport);
    }
  };
  CHECK(capture->run(sink, running, 0, err));
  capture->close();

  CHECK_EQ(lengths.size(), 3u);
  if (lengths.size() == 3) {
    CHECK_EQ(lengths[0], static_cast<uint32_t>(frames[0].size()));
    CHECK_EQ(lengths[2], static_cast<uint32_t>(frames[2].size()));
  }
  CHECK_EQ(ports.size(), 3u);
  if (ports.size() == 3) {
    CHECK_EQ(ports[0], 51000);
    CHECK_EQ(ports[1], 443);
    CHECK_EQ(ports[2], 5353);
  }
  std::remove(path.c_str());
}

// ------------------------------------------------------------- M3 / M6 tests

void test_bpf_filter_validation() {
  std::string err;
  CHECK(validate_bpf_filter("tcp port 443", 1, err));
  CHECK(validate_bpf_filter("icmp or (udp and port 53)", 1, err));
  CHECK(!validate_bpf_filter("tcp porrt 443", 1, err));
  CHECK(!err.empty());
}

void test_statistics_and_throughput() {
  Statistics stats;
  const auto tcp_frame = make_ipv4_frame("10.0.0.1", "10.0.0.2", IPPROTO_TCP_,
                                         tcp_segment(51000, 443, 1, 0, TH_SYN));
  const auto udp_frame = make_ipv4_frame("10.0.0.1", "10.0.0.3", IPPROTO_UDP_,
                                         udp_datagram(5353, 53, {1, 2, 3}));

  for (int i = 0; i < 3; ++i) stats.add(decode(tcp_frame, tv(100, 0)));
  stats.add(decode(udp_frame, tv(101, 0)));

  CHECK_EQ(stats.packets(), 4u);
  CHECK_EQ(stats.tcp_syn(), 3u);
  const auto dist = stats.protocol_distribution();
  CHECK(dist[0].name == std::string("TCP"));
  CHECK_EQ(dist[0].packets, 3u);
  CHECK_NEAR(stats.elapsed_sec(), 1.0, 0.001);

  // Bytes must land in the bucket for their own second.
  const auto hist = stats.throughput_history();
  CHECK_EQ(hist.size(), kThroughputWindow);
  uint64_t total = 0;
  for (const auto& b : hist) total += b.bytes;
  CHECK_EQ(total, stats.bytes());
}

void test_formatting_helpers() {
  CHECK_STR_EQ(human_bytes(512), "512 B");
  CHECK_STR_EQ(human_bytes(1536), "1.5 KB");
  CHECK_STR_EQ(human_rate_bits(1500), "1.50 Kbps");
  CHECK_STR_EQ(human_count(1500), "1.5K");
  CHECK_STR_EQ(human_duration(3725), "1h02m05s");
  CHECK_STR_EQ(human_duration(65), "1m05s");
}

void test_flow_expiry_and_eviction() {
  FlowTable table;
  table.set_dissection_enabled(false);
  feed_tcp(table, "10.0.0.1", "10.0.0.2", 51000, 443, 1, 0, TH_SYN, "", tv(100, 0));
  feed_tcp(table, "10.0.0.1", "10.0.0.3", 51001, 443, 1, 0, TH_SYN, "", tv(100, 0));
  CHECK_EQ(table.size(), 2u);
  CHECK_EQ(table.expire(tv(150, 0), 120.0), 0u);  // still fresh
  CHECK_EQ(table.expire(tv(300, 0), 120.0), 2u);  // both idle out
  CHECK_EQ(table.size(), 0u);
  CHECK_EQ(table.total_flows_seen(), 2u);         // history is not forgotten

  // A reset flow is dropped after a short grace period rather than the full idle
  // timeout, because it can never carry traffic again.
  FlowTable t2;
  t2.set_dissection_enabled(false);
  feed_tcp(t2, "10.0.0.1", "10.0.0.2", 51000, 443, 1, 0, TH_SYN, "", tv(100, 0));
  feed_tcp(t2, "10.0.0.2", "10.0.0.1", 443, 51000, 0, 2, TH_RST | TH_ACK, "", tv(100, 1000));
  CHECK_EQ(t2.expire(tv(110, 0), 120.0), 1u);
}

void test_bounded_flow_table() {
  FlowTable table(4);  // deliberately tiny
  table.set_dissection_enabled(false);
  for (int i = 0; i < 20; ++i) {
    char dst[32];
    std::snprintf(dst, sizeof(dst), "10.1.%d.%d", i / 256, i % 256);
    feed_tcp(table, "10.0.0.1", dst, 51000, 443, 1, 0, TH_SYN, "", tv(100 + i, 0));
  }
  CHECK(table.size() <= 4);            // memory stays bounded under flooding
  CHECK_EQ(table.total_flows_seen(), 20u);
}

}  // namespace

int main() {
  std::printf("netscope unit tests\n\n");

  std::printf("M2  header decoding\n");
  run_test("internet checksum over a valid IPv4 header", test_internet_checksum);
  run_test("decode TCP over IPv4 over Ethernet", test_decode_tcp_over_ipv4);
  run_test("decode UDP and ICMP", test_decode_udp_and_icmp);
  run_test("decode 802.1Q VLAN tagged frame", test_decode_vlan_tagged);
  run_test("decode DLT_NULL loopback frame (macOS/BSD lo0)", test_decode_null_linktype_loopback);
  run_test("flag a corrupt IPv4 header checksum", test_decode_bad_checksum_flagged);
  run_test("every truncation of a frame decodes safely", test_decode_truncation_is_safe);
  run_test("non-initial fragment exposes no ports", test_decode_non_initial_fragment_has_no_ports);

  std::printf("\nM3  filtering\n");
  run_test("BPF expressions are validated before capture", test_bpf_filter_validation);

  std::printf("\nM4  flow tracking and TCP state\n");
  run_test("sequence numbers compare correctly across wraparound", test_sequence_wraparound_comparison);
  run_test("both directions map to one flow key", test_flow_key_is_direction_agnostic);
  run_test("state machine walks a full connection lifecycle", test_tcp_state_machine_full_lifecycle);
  run_test("RST and mid-stream join are handled", test_tcp_reset_and_midstream_join);
  run_test("idle and reset flows are expired", test_flow_expiry_and_eviction);
  run_test("flow table stays bounded under flooding", test_bounded_flow_table);

  std::printf("\nM5  retransmission heuristics\n");
  run_test("duplicates counted, gaps counted separately", test_retransmission_detection);
  run_test("late hole-filling segment is not a retransmission",
           test_late_segment_filling_a_hole_is_not_a_retransmission);

  std::printf("\nM6  statistics\n");
  run_test("counters, distribution and throughput buckets", test_statistics_and_throughput);
  run_test("human-readable formatting", test_formatting_helpers);

  std::printf("\nM9  stream reassembly\n");
  run_test("in-order segments", test_reassembly_in_order);
  run_test("reordered segments are held and released", test_reassembly_reordered);
  run_test("overlapping and duplicate segments are trimmed", test_reassembly_overlap_and_duplicates);
  run_test("prefix cap bounds memory", test_reassembly_respects_prefix_cap);

  std::printf("\nM10 application dissection\n");
  run_test("TLS ClientHello SNI and version", test_dissect_tls_sni);
  run_test("HTTP request line, Host header, sanitisation", test_dissect_http);
  run_test("DNS names, compression loops, truncation", test_dissect_dns);
  run_test("SSH version banner", test_dissect_ssh);
  run_test("ClientHello split across reordered segments", test_dissection_across_reordered_segments);

  std::printf("\nM11 round-trip time\n");
  run_test("handshake RTT", test_rtt_from_handshake);
  run_test("data-ACK RTT, retransmits excluded", test_rtt_from_data_acks_ignores_retransmits);
  run_test("smoothing and implausible-sample rejection", test_rtt_smoothing_and_bounds);

  std::printf("\nM12 pcap output\n");
  run_test("written file reads back through libpcap", test_pcap_writer_roundtrip);

  std::printf("\n%d checks, %d failure%s\n", g_checks, g_failures,
              g_failures == 1 ? "" : "s");
  return g_failures == 0 ? 0 : 1;
}
