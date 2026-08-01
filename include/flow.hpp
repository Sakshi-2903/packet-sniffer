// flow.hpp -- bidirectional flow tracking: TCP connection state, retransmission
// and out-of-order heuristics (M4/M5), stream reassembly and application
// identification (M9/M10), and round-trip time estimation (M11).
#pragma once

#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "dissect.hpp"
#include "protocol.hpp"
#include "reassembly.hpp"

namespace netscope {

// TCP sequence numbers wrap at 2^32, so they must be compared as signed
// differences rather than directly (RFC 1982 serial-number arithmetic).
inline bool seq_lt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) < 0; }
inline bool seq_le(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) <= 0; }
inline bool seq_gt(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b) > 0; }

// Canonical 5-tuple. Both directions of a conversation map to the same key: the
// numerically lower (address, port) pair is always stored as endpoint A, so
// A->B and B->A packets land in the same table entry.
struct FlowKey {
  IpAddress a;
  IpAddress b;
  uint16_t port_a = 0;
  uint16_t port_b = 0;
  uint8_t proto = 0;

  bool operator==(const FlowKey& o) const {
    return proto == o.proto && port_a == o.port_a && port_b == o.port_b &&
           a == o.a && b == o.b;
  }
};

struct FlowKeyHash {
  size_t operator()(const FlowKey& k) const noexcept;
};

// Builds the canonical key for a packet. `forward` is set to true when the
// packet travels A->B, false when it travels B->A.
FlowKey make_flow_key(const DecodedPacket& p, bool& forward);

enum class TcpState : uint8_t {
  None,        // not TCP, or nothing seen yet
  SynSent,     // client SYN observed
  SynReceived, // server SYN/ACK observed
  Established, // handshake completed
  FinWait,     // one side sent FIN
  Closing,     // both sides sent FIN
  Closed,      // final ACK after both FINs
  Reset,       // RST observed
};

const char* to_string(TcpState s);

// M11: round-trip time estimate for one direction of a flow.
//
// A sample is the delay between sending data and seeing the far side acknowledge
// it. Following Karn's algorithm, retransmitted segments produce no samples: it
// is impossible to tell whether the ACK answered the original or the retry, and
// including such samples biases the estimate badly. `srtt_ms` is smoothed the
// way TCP itself smooths RTT (RFC 6298, alpha = 1/8).
struct RttStats {
  uint64_t samples = 0;
  double min_ms = 0.0;
  double max_ms = 0.0;
  double last_ms = 0.0;
  double srtt_ms = 0.0;

  void add(double ms);
  bool valid() const { return samples > 0; }
};

// Counters for one direction of a flow.
struct DirectionStats {
  uint64_t packets = 0;
  uint64_t bytes = 0;         // wire bytes
  uint64_t payload_bytes = 0; // L4 payload only (goodput)
  uint64_t retransmits = 0;
  uint64_t out_of_order = 0;
  uint64_t syn = 0, fin = 0, rst = 0, pure_acks = 0;
  uint16_t last_window = 0;
  uint8_t last_ttl = 0;

  // TCP reassembly bookkeeping used for retransmission detection.
  bool seq_valid = false;
  uint32_t next_seq = 0;  // highest sequence number seen + payload length
  std::deque<uint64_t> recent_segments;  // packed (seq,len) fingerprints
  // Sequence ranges known to be missing, recorded when a forward jump is seen.
  // A later segment landing in one of these is a delayed delivery, not a resend.
  std::deque<std::pair<uint32_t, uint32_t>> holes;

  // M9: released once the application protocol is known, so long-lived
  // connections do not hold reassembly buffers for their whole lifetime.
  std::unique_ptr<StreamReassembler> stream;

  // M11: data segments sent but not yet acknowledged, as (end sequence, sent at).
  std::deque<std::pair<uint32_t, timeval>> awaiting_ack;
  RttStats rtt;
};

struct Flow {
  uint64_t id = 0;
  FlowKey key;
  L4Proto l4 = L4Proto::Unknown;
  TcpState state = TcpState::None;
  DirectionStats fwd;  // A -> B
  DirectionStats rev;  // B -> A
  timeval first_seen{};
  timeval last_seen{};
  bool handshake_complete = false;

  // M10: application protocol, identified from stream content.
  AppInfo app;

  // M11: SYN -> SYN/ACK delay, the cleanest RTT sample a connection offers.
  double handshake_rtt_ms = -1.0;
  timeval syn_ts{};
  bool syn_seen = false;

  uint64_t packets() const { return fwd.packets + rev.packets; }
  uint64_t bytes() const { return fwd.bytes + rev.bytes; }
  uint64_t retransmits() const { return fwd.retransmits + rev.retransmits; }
  uint64_t out_of_order() const { return fwd.out_of_order + rev.out_of_order; }
  double duration_sec() const;
  // Retransmitted share of this flow's TCP data segments, in percent.
  double retransmit_rate() const;
  // Best RTT estimate available: handshake timing if measured, otherwise the
  // smoothed data-ACK estimate from whichever direction has samples.
  double best_rtt_ms() const;
  std::string label() const;       // "1.2.3.4:443 <-> 5.6.7.8:51234"
  std::string app_summary() const; // "TLS1.3 sni=example.com", or empty
};

enum class FlowSort : uint8_t { Bytes, Packets, Retransmits, Recent, Rtt };
const char* to_string(FlowSort s);

class FlowTable {
 public:
  explicit FlowTable(size_t max_flows = 65536) : max_flows_(max_flows) {}

  // M9/M10 can be switched off to keep the per-packet path minimal.
  void set_dissection_enabled(bool on) { dissect_enabled_ = on; }
  bool dissection_enabled() const { return dissect_enabled_; }

  // Feeds one decoded packet into the table, creating the flow if needed.
  // Returns nullptr for packets with no flow identity (e.g. ARP).
  Flow* update(const DecodedPacket& p);

  // Drops flows idle for longer than `idle_sec` (and closed TCP flows after a
  // shorter grace period). Returns the number of flows removed.
  size_t expire(const timeval& now, double idle_sec = 120.0);

  std::vector<const Flow*> top(size_t n, FlowSort sort) const;

  size_t size() const { return flows_.size(); }
  uint64_t total_flows_seen() const { return next_id_; }
  uint64_t active_tcp() const;
  uint64_t total_retransmits() const { return total_retransmits_; }
  uint64_t total_out_of_order() const { return total_out_of_order_; }
  uint64_t total_tcp_data_segments() const { return total_data_segments_; }
  uint64_t total_reassembled_bytes() const { return total_reassembled_bytes_; }
  uint64_t total_rtt_samples() const { return total_rtt_samples_; }

  // Flows identified per application protocol, largest first.
  std::vector<std::pair<AppProtocol, uint64_t>> app_protocols() const;
  // Median-ish view of connection quality: mean smoothed RTT over flows that
  // have an estimate.
  double mean_rtt_ms() const;

  void clear();

 private:
  void advance_tcp_state(Flow& flow, const DecodedPacket& p, bool forward);
  // Returns true if the segment was judged a retransmission.
  bool track_sequence(DirectionStats& dir, const DecodedPacket& p, uint32_t seglen);
  void track_rtt(Flow& flow, const DecodedPacket& p, bool forward, bool retransmit);
  void reassemble_and_dissect(Flow& flow, DirectionStats& dir, const DecodedPacket& p);

  std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
  size_t max_flows_;
  bool dissect_enabled_ = true;
  uint64_t next_id_ = 0;
  uint64_t total_retransmits_ = 0;
  uint64_t total_out_of_order_ = 0;
  uint64_t total_data_segments_ = 0;
  uint64_t total_reassembled_bytes_ = 0;
  uint64_t total_rtt_samples_ = 0;
  std::unordered_map<uint8_t, uint64_t> app_counts_;  // AppProtocol -> flows
};

double timeval_diff(const timeval& later, const timeval& earlier);

}  // namespace netscope
