#include "flow.hpp"

#include <algorithm>
#include <cmath>
#include <sstream>

#include "dissect.hpp"

namespace netscope {

namespace {
constexpr size_t kRecentSegmentWindow = 64;  // segments remembered per direction
constexpr double kClosedFlowGraceSec = 5.0;
constexpr size_t kMaxAwaitingAck = 256;  // bounds per-direction RTT bookkeeping
constexpr size_t kMaxTrackedHoles = 16;

// Do the sequence ranges [a_lo, a_hi) and [b_lo, b_hi) overlap? Compared with
// serial arithmetic so the test survives sequence-number wraparound.
inline bool ranges_overlap(uint32_t a_lo, uint32_t a_hi, uint32_t b_lo, uint32_t b_hi) {
  return seq_lt(a_lo, b_hi) && seq_lt(b_lo, a_hi);
}

// Packs a (sequence number, length) pair into one 64-bit fingerprint so a
// repeated segment can be spotted with a cheap linear scan of a short deque.
inline uint64_t segment_fingerprint(uint32_t seq, uint32_t len) {
  return (static_cast<uint64_t>(seq) << 32) | len;
}
}  // namespace

double timeval_diff(const timeval& later, const timeval& earlier) {
  return static_cast<double>(later.tv_sec - earlier.tv_sec) +
         static_cast<double>(later.tv_usec - earlier.tv_usec) / 1e6;
}

size_t FlowKeyHash::operator()(const FlowKey& k) const noexcept {
  // FNV-1a over the address bytes plus the ports and protocol.
  uint64_t h = 1469598103934665603ULL;
  auto mix = [&h](uint8_t byte) {
    h ^= byte;
    h *= 1099511628211ULL;
  };
  size_t n = k.a.is_v6 ? 16u : 4u;
  for (size_t i = 0; i < n; ++i) mix(k.a.bytes[i]);
  for (size_t i = 0; i < n; ++i) mix(k.b.bytes[i]);
  mix(static_cast<uint8_t>(k.port_a & 0xFF));
  mix(static_cast<uint8_t>(k.port_a >> 8));
  mix(static_cast<uint8_t>(k.port_b & 0xFF));
  mix(static_cast<uint8_t>(k.port_b >> 8));
  mix(k.proto);
  return static_cast<size_t>(h);
}

FlowKey make_flow_key(const DecodedPacket& p, bool& forward) {
  FlowKey k;
  k.proto = p.ip_proto;
  uint16_t sp = p.has_ports() ? p.sport : 0;
  uint16_t dp = p.has_ports() ? p.dport : 0;

  // Canonicalise: endpoint A is the smaller (address, port).
  bool src_is_a = (p.src_ip < p.dst_ip) || (p.src_ip == p.dst_ip && sp <= dp);
  if (src_is_a) {
    k.a = p.src_ip;
    k.b = p.dst_ip;
    k.port_a = sp;
    k.port_b = dp;
    forward = true;
  } else {
    k.a = p.dst_ip;
    k.b = p.src_ip;
    k.port_a = dp;
    k.port_b = sp;
    forward = false;
  }
  return k;
}

const char* to_string(TcpState s) {
  switch (s) {
    case TcpState::SynSent:     return "SYN_SENT";
    case TcpState::SynReceived: return "SYN_RECV";
    case TcpState::Established: return "ESTABLISHED";
    case TcpState::FinWait:     return "FIN_WAIT";
    case TcpState::Closing:     return "CLOSING";
    case TcpState::Closed:      return "CLOSED";
    case TcpState::Reset:       return "RESET";
    default:                    return "-";
  }
}

const char* to_string(FlowSort s) {
  switch (s) {
    case FlowSort::Bytes:       return "bytes";
    case FlowSort::Packets:     return "packets";
    case FlowSort::Retransmits: return "retransmits";
    case FlowSort::Recent:      return "recent";
    case FlowSort::Rtt:         return "rtt";
  }
  return "bytes";
}

double Flow::duration_sec() const { return timeval_diff(last_seen, first_seen); }

double Flow::retransmit_rate() const {
  uint64_t data_segs = fwd.packets + rev.packets;
  if (data_segs == 0) return 0.0;
  return 100.0 * static_cast<double>(retransmits()) / static_cast<double>(data_segs);
}

void RttStats::add(double ms) {
  if (ms < 0.0 || ms > 60000.0) return;  // implausible: clock jump or bad capture
  if (samples == 0) {
    min_ms = max_ms = last_ms = srtt_ms = ms;
  } else {
    min_ms = std::min(min_ms, ms);
    max_ms = std::max(max_ms, ms);
    last_ms = ms;
    // RFC 6298 smoothing: srtt = (1 - alpha) * srtt + alpha * sample.
    srtt_ms = 0.875 * srtt_ms + 0.125 * ms;
  }
  ++samples;
}

double Flow::best_rtt_ms() const {
  if (handshake_rtt_ms >= 0.0) return handshake_rtt_ms;
  if (fwd.rtt.valid() && rev.rtt.valid()) {
    return std::min(fwd.rtt.srtt_ms, rev.rtt.srtt_ms);
  }
  if (fwd.rtt.valid()) return fwd.rtt.srtt_ms;
  if (rev.rtt.valid()) return rev.rtt.srtt_ms;
  return -1.0;
}

std::string Flow::app_summary() const {
  if (!app.identified()) return {};
  std::string s = to_string(app.proto);
  if (!app.summary.empty()) s += " " + app.summary;
  return s;
}

std::string Flow::label() const {
  std::ostringstream os;
  os << key.a.str();
  if (key.port_a || key.port_b) os << ':' << key.port_a;
  os << " <-> " << key.b.str();
  if (key.port_a || key.port_b) os << ':' << key.port_b;
  return os.str();
}

// Simplified TCP state machine. It is observational, not authoritative: a
// sniffer may join mid-connection or miss packets, so states advance on the
// evidence available and never block on a transition that was not observed.
void FlowTable::advance_tcp_state(Flow& flow, const DecodedPacket& p, bool forward) {
  const uint8_t f = p.tcp_flags;

  if (f & TH_RST) {
    flow.state = TcpState::Reset;
    return;
  }

  const bool syn = (f & TH_SYN) != 0;
  const bool ack = (f & TH_ACK) != 0;
  const bool fin = (f & TH_FIN) != 0;

  switch (flow.state) {
    case TcpState::None:
      if (syn && !ack) {
        flow.state = TcpState::SynSent;
      } else if (syn && ack) {
        flow.state = TcpState::SynReceived;
      } else {
        // Joined an existing conversation already in progress.
        flow.state = TcpState::Established;
      }
      break;
    case TcpState::SynSent:
      if (syn && ack) flow.state = TcpState::SynReceived;
      break;
    case TcpState::SynReceived:
      if (ack && !syn) {
        flow.state = TcpState::Established;
        flow.handshake_complete = true;
      }
      break;
    case TcpState::Established:
      if (fin) flow.state = TcpState::FinWait;
      break;
    case TcpState::FinWait:
      // The second FIN must come from the opposite direction to close the flow.
      if (fin) {
        bool other_side_finned = forward ? (flow.rev.fin > 0) : (flow.fwd.fin > 0);
        flow.state = other_side_finned ? TcpState::Closing : TcpState::FinWait;
      }
      break;
    case TcpState::Closing:
      if (ack && !fin) flow.state = TcpState::Closed;
      break;
    case TcpState::Closed:
    case TcpState::Reset:
      // Terminal; a new handshake on the same tuple restarts the state.
      if (syn && !ack) {
        flow.state = TcpState::SynSent;
        flow.handshake_complete = false;
      }
      break;
  }
}

// Retransmission detection, using two independent signals:
//   1. An exact (seq, len) fingerprint seen recently in the same direction --
//      a strong indicator of a genuine retransmission.
//   2. A data segment whose end falls at or below the highest sequence number
//      already seen -- old data being resent.
// Anything arriving ahead of next_seq is counted as out-of-order/gap instead.
bool FlowTable::track_sequence(DirectionStats& dir, const DecodedPacket& p,
                               uint32_t seglen) {
  if (seglen == 0) {
    // Pure ACK / control segment: advance past SYN and FIN, which each consume
    // one sequence number, but do not treat it as data.
    uint32_t consumed = 0;
    if (p.tcp_flags & TH_SYN) consumed = 1;
    if (p.tcp_flags & TH_FIN) consumed = 1;
    if (!dir.seq_valid) {
      dir.seq_valid = true;
      dir.next_seq = p.seq + consumed;
    } else if (seq_gt(p.seq + consumed, dir.next_seq)) {
      dir.next_seq = p.seq + consumed;
    }
    return false;
  }

  ++total_data_segments_;
  const uint64_t fp = segment_fingerprint(p.seq, seglen);
  const bool duplicate = std::find(dir.recent_segments.begin(),
                                   dir.recent_segments.end(), fp) !=
                         dir.recent_segments.end();
  const uint32_t seg_end = p.seq + seglen;

  // Does this segment land in a range already known to be missing? If so it is
  // a delayed original rather than a resend, and the hole is now (partly) filled.
  auto fills_known_hole = [&]() {
    for (auto it = dir.holes.begin(); it != dir.holes.end(); ++it) {
      if (ranges_overlap(p.seq, seg_end, it->first, it->second)) {
        if (seq_le(it->second, seg_end) && seq_le(p.seq, it->first)) {
          dir.holes.erase(it);  // hole fully covered
        } else if (seq_le(p.seq, it->first)) {
          it->first = seg_end;  // filled from the front
        } else {
          it->second = p.seq;   // filled from the back
        }
        return true;
      }
    }
    return false;
  };

  bool retransmit = false;
  if (!dir.seq_valid) {
    dir.seq_valid = true;
    dir.next_seq = seg_end;
  } else if (duplicate) {
    // Byte-for-byte the same segment seen twice: unambiguously a retransmission.
    ++dir.retransmits;
    ++total_retransmits_;
    retransmit = true;
  } else if (seq_le(seg_end, dir.next_seq)) {
    if (fills_known_hole()) {
      ++dir.out_of_order;
      ++total_out_of_order_;
    } else {
      ++dir.retransmits;
      ++total_retransmits_;
      retransmit = true;
    }
  } else if (seq_gt(p.seq, dir.next_seq)) {
    // A forward jump: everything between the old and new position is missing.
    dir.holes.emplace_back(dir.next_seq, p.seq);
    if (dir.holes.size() > kMaxTrackedHoles) dir.holes.pop_front();
    ++dir.out_of_order;
    ++total_out_of_order_;
    dir.next_seq = seg_end;
  } else {
    dir.next_seq = seg_end;
  }

  dir.recent_segments.push_back(fp);
  if (dir.recent_segments.size() > kRecentSegmentWindow) {
    dir.recent_segments.pop_front();
  }
  return retransmit;
}

// M11: turns "sent at T1, acknowledged at T2" into an RTT sample.
//
// Each direction records the end sequence number of every data segment it sends
// along with the send time. When the opposite direction acknowledges past that
// point, the delay is a round-trip measurement. Retransmitted segments are never
// recorded (Karn's algorithm), and only one sample is taken per ACK so a single
// cumulative acknowledgement of many segments cannot skew the average.
void FlowTable::track_rtt(Flow& flow, const DecodedPacket& p, bool forward,
                          bool retransmit) {
  DirectionStats& sender = forward ? flow.fwd : flow.rev;
  DirectionStats& peer = forward ? flow.rev : flow.fwd;

  // Handshake RTT: the SYN -> SYN/ACK delay, unambiguous by construction.
  const bool syn = (p.tcp_flags & TH_SYN) != 0;
  const bool ack = (p.tcp_flags & TH_ACK) != 0;
  if (syn && !ack) {
    flow.syn_ts = p.ts;
    flow.syn_seen = true;
  } else if (syn && ack && flow.syn_seen && flow.handshake_rtt_ms < 0.0) {
    flow.handshake_rtt_ms = timeval_diff(p.ts, flow.syn_ts) * 1000.0;
    ++total_rtt_samples_;
  }

  // Remember this segment so the peer's ACK can be timed against it.
  if (p.payload_len > 0 && !retransmit) {
    sender.awaiting_ack.emplace_back(p.seq + p.payload_len, p.ts);
    if (sender.awaiting_ack.size() > kMaxAwaitingAck) sender.awaiting_ack.pop_front();
  }

  // This packet's ACK number retires data the peer sent.
  if (ack && !peer.awaiting_ack.empty()) {
    bool sampled = false;
    while (!peer.awaiting_ack.empty() &&
           seq_le(peer.awaiting_ack.front().first, p.ack)) {
      if (!sampled) {
        const double ms = timeval_diff(p.ts, peer.awaiting_ack.front().second) * 1000.0;
        peer.rtt.add(ms);
        ++total_rtt_samples_;
        sampled = true;
      }
      peer.awaiting_ack.pop_front();
    }
  }
}

// M9/M10: feed the payload through reassembly, then try to name the protocol.
void FlowTable::reassemble_and_dissect(Flow& flow, DirectionStats& dir,
                                       const DecodedPacket& p) {
  if (!dissect_enabled_ || flow.app.conclusive) return;

  if (p.l4 == L4Proto::UDP) {
    // Datagram protocols need no reassembly: each packet stands alone.
    AppInfo info;
    if (dissect_udp_payload(p.payload, p.payload_len, p.sport, p.dport, info)) {
      const bool first = !flow.app.identified();
      flow.app = info;
      if (first) ++app_counts_[static_cast<uint8_t>(info.proto)];
    }
    return;
  }
  if (p.l4 != L4Proto::TCP) return;

  const bool syn = (p.tcp_flags & TH_SYN) != 0;
  if (p.payload_len == 0 && !syn) return;

  if (!dir.stream) dir.stream = std::make_unique<StreamReassembler>();
  const size_t added = dir.stream->push(p.seq, p.payload, p.payload_len, syn);
  total_reassembled_bytes_ += added;

  if (added > 0) {
    AppInfo info;
    if (dissect_tcp_stream(dir.stream->prefix(), p.sport, p.dport, info)) {
      // A later, more definite reading replaces an earlier tentative one -- for
      // example "TLS1.2 client-hello" upgrading to "TLS1.3 sni=example.com".
      if (!flow.app.identified() || (info.conclusive && !flow.app.conclusive)) {
        const bool first = !flow.app.identified();
        flow.app = info;
        if (first) ++app_counts_[static_cast<uint8_t>(info.proto)];
      }
    }
  }

  // Release the buffers as soon as they cannot tell us anything more.
  if (flow.app.conclusive || dir.stream->saturated()) {
    dir.stream.reset();
  }
}

Flow* FlowTable::update(const DecodedPacket& p) {
  if (p.l3 != L3Proto::IPv4 && p.l3 != L3Proto::IPv6) return nullptr;
  if (p.error != nullptr) return nullptr;

  bool forward = true;
  FlowKey key = make_flow_key(p, forward);

  auto it = flows_.find(key);
  if (it == flows_.end()) {
    if (flows_.size() >= max_flows_) {
      // Table is full: make room by dropping the least recently active flow.
      auto oldest = flows_.begin();
      for (auto i = flows_.begin(); i != flows_.end(); ++i) {
        if (timeval_diff(i->second.last_seen, oldest->second.last_seen) < 0) oldest = i;
      }
      flows_.erase(oldest);
    }
    Flow flow;
    flow.id = ++next_id_;
    flow.key = key;
    flow.l4 = p.l4;
    flow.first_seen = p.ts;
    it = flows_.emplace(key, std::move(flow)).first;
  }

  Flow& flow = it->second;
  flow.last_seen = p.ts;
  DirectionStats& dir = forward ? flow.fwd : flow.rev;

  ++dir.packets;
  dir.bytes += p.wirelen;
  dir.payload_bytes += p.payload_len;
  dir.last_ttl = p.ttl;

  if (p.l4 == L4Proto::TCP) {
    dir.last_window = p.window;
    if (p.tcp_flags & TH_SYN) ++dir.syn;
    if (p.tcp_flags & TH_FIN) ++dir.fin;
    if (p.tcp_flags & TH_RST) ++dir.rst;
    if (p.payload_len == 0 && (p.tcp_flags & TH_ACK) &&
        !(p.tcp_flags & (TH_SYN | TH_FIN | TH_RST))) {
      ++dir.pure_acks;
    }
    const bool retransmit = track_sequence(dir, p, p.payload_len);
    advance_tcp_state(flow, p, forward);
    track_rtt(flow, p, forward, retransmit);
  }

  reassemble_and_dissect(flow, dir, p);
  return &flow;
}

size_t FlowTable::expire(const timeval& now, double idle_sec) {
  size_t removed = 0;
  for (auto it = flows_.begin(); it != flows_.end();) {
    const double idle = timeval_diff(now, it->second.last_seen);
    const bool terminal = it->second.state == TcpState::Closed ||
                          it->second.state == TcpState::Reset;
    if (idle > idle_sec || (terminal && idle > kClosedFlowGraceSec)) {
      it = flows_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }
  return removed;
}

uint64_t FlowTable::active_tcp() const {
  uint64_t n = 0;
  for (const auto& [key, flow] : flows_) {
    if (flow.l4 == L4Proto::TCP && flow.state == TcpState::Established) ++n;
  }
  return n;
}

std::vector<const Flow*> FlowTable::top(size_t n, FlowSort sort) const {
  std::vector<const Flow*> all;
  all.reserve(flows_.size());
  for (const auto& [key, flow] : flows_) all.push_back(&flow);

  auto cmp = [sort](const Flow* x, const Flow* y) {
    switch (sort) {
      case FlowSort::Packets: return x->packets() > y->packets();
      case FlowSort::Retransmits:
        if (x->retransmits() != y->retransmits()) return x->retransmits() > y->retransmits();
        return x->bytes() > y->bytes();
      case FlowSort::Recent: return timeval_diff(x->last_seen, y->last_seen) > 0;
      case FlowSort::Rtt: {
        // Flows without an estimate sort last rather than appearing fastest.
        const double a = x->best_rtt_ms(), b = y->best_rtt_ms();
        if (a < 0.0) return false;
        if (b < 0.0) return true;
        return a > b;
      }
      case FlowSort::Bytes:
      default: return x->bytes() > y->bytes();
    }
  };

  if (all.size() > n) {
    std::partial_sort(all.begin(), all.begin() + static_cast<long>(n), all.end(), cmp);
    all.resize(n);
  } else {
    std::sort(all.begin(), all.end(), cmp);
  }
  return all;
}

std::vector<std::pair<AppProtocol, uint64_t>> FlowTable::app_protocols() const {
  std::vector<std::pair<AppProtocol, uint64_t>> v;
  v.reserve(app_counts_.size());
  for (const auto& [proto, count] : app_counts_) {
    v.emplace_back(static_cast<AppProtocol>(proto), count);
  }
  std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
  return v;
}

double FlowTable::mean_rtt_ms() const {
  double total = 0.0;
  uint64_t n = 0;
  for (const auto& [key, flow] : flows_) {
    const double rtt = flow.best_rtt_ms();
    if (rtt >= 0.0) {
      total += rtt;
      ++n;
    }
  }
  return n ? total / static_cast<double>(n) : -1.0;
}

void FlowTable::clear() {
  flows_.clear();
  app_counts_.clear();
}

}  // namespace netscope
