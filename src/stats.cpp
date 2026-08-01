#include "stats.hpp"

#include <algorithm>
#include <cstdio>
#include <sstream>

#include "flow.hpp"  // timeval_diff
#include "parser.hpp"

namespace netscope {

Statistics::Statistics() { ring_sec_.fill(0); }

void Statistics::reset() {
  *this = Statistics();
}

ThroughputBucket& Statistics::bucket_for(time_t sec) {
  const size_t idx = static_cast<size_t>(sec) % kThroughputWindow;
  if (ring_sec_[idx] != sec) {
    ring_sec_[idx] = sec;
    ring_[idx] = ThroughputBucket{};
  }
  if (sec > newest_sec_) newest_sec_ = sec;
  return ring_[idx];
}

void Statistics::add(const DecodedPacket& p) {
  if (!started_) {
    start_ = p.ts;
    started_ = true;
  }
  last_ = p.ts;

  ++packets_;
  bytes_ += p.wirelen;

  ThroughputBucket& b = bucket_for(p.ts.tv_sec);
  b.bytes += p.wirelen;
  b.packets += 1;

  if (p.truncated) ++truncated_;
  if (p.bad_ip_checksum) ++bad_checksums_;
  if (p.fragmented) ++fragments_;
  if (p.error != nullptr) {
    ++decode_errors_;
    return;
  }

  if (p.l3 == L3Proto::IPv4) ++ipv4_packets_;
  if (p.l3 == L3Proto::IPv6) ++ipv6_packets_;

  if (p.l3 == L3Proto::ARP) {
    ++arp_packets_;
    arp_bytes_ += p.wirelen;
    return;
  }

  switch (p.l4) {
    case L4Proto::TCP:
      ++tcp_packets_;
      tcp_bytes_ += p.wirelen;
      if (p.tcp_flags & TH_SYN) ++tcp_syn_;
      if (p.tcp_flags & TH_FIN) ++tcp_fin_;
      if (p.tcp_flags & TH_RST) ++tcp_rst_;
      break;
    case L4Proto::UDP:
      ++udp_packets_;
      udp_bytes_ += p.wirelen;
      break;
    case L4Proto::ICMP:
    case L4Proto::ICMPv6:
      ++icmp_packets_;
      icmp_bytes_ += p.wirelen;
      break;
    default:
      ++other_packets_;
      other_bytes_ += p.wirelen;
      break;
  }

  // Attribute bytes to the well-known side of the conversation: the lower port
  // number is almost always the service.
  if (p.has_ports()) {
    const uint16_t service = std::min(p.sport, p.dport);
    port_bytes_[service] += p.wirelen;
  }
  if (p.l3 == L3Proto::IPv4 || p.l3 == L3Proto::IPv6) {
    talker_bytes_[p.src_ip.str()] += p.wirelen;
  }
}

void Statistics::set_kernel_stats(uint64_t received, uint64_t dropped,
                                  uint64_t if_dropped) {
  kernel_received_ = received;
  kernel_dropped_ = dropped;
  if_dropped_ = if_dropped;
}

double Statistics::elapsed_sec() const {
  if (!started_) return 0.0;
  const double d = timeval_diff(last_, start_);
  return d > 0.0 ? d : 0.0;
}

double Statistics::avg_bps() const {
  const double secs = elapsed_sec();
  if (secs <= 0.001) return 0.0;
  return static_cast<double>(bytes_) * 8.0 / secs;
}

double Statistics::avg_pps() const {
  const double secs = elapsed_sec();
  if (secs <= 0.001) return 0.0;
  return static_cast<double>(packets_) / secs;
}

double Statistics::recent_bps(size_t seconds) const {
  if (seconds == 0 || newest_sec_ == 0) return 0.0;
  seconds = std::min(seconds, kThroughputWindow);
  uint64_t total = 0;
  // The newest bucket is still filling, so measure the completed ones behind it.
  for (size_t i = 1; i <= seconds; ++i) {
    const time_t sec = newest_sec_ - static_cast<time_t>(i);
    const size_t idx = static_cast<size_t>(sec) % kThroughputWindow;
    if (ring_sec_[idx] == sec) total += ring_[idx].bytes;
  }
  return static_cast<double>(total) * 8.0 / static_cast<double>(seconds);
}

double Statistics::recent_pps(size_t seconds) const {
  if (seconds == 0 || newest_sec_ == 0) return 0.0;
  seconds = std::min(seconds, kThroughputWindow);
  uint64_t total = 0;
  for (size_t i = 1; i <= seconds; ++i) {
    const time_t sec = newest_sec_ - static_cast<time_t>(i);
    const size_t idx = static_cast<size_t>(sec) % kThroughputWindow;
    if (ring_sec_[idx] == sec) total += ring_[idx].packets;
  }
  return static_cast<double>(total) / static_cast<double>(seconds);
}

std::vector<ThroughputBucket> Statistics::throughput_history() const {
  std::vector<ThroughputBucket> out;
  out.reserve(kThroughputWindow);
  if (newest_sec_ == 0) return out;
  for (size_t i = 0; i < kThroughputWindow; ++i) {
    const time_t sec = newest_sec_ - static_cast<time_t>(kThroughputWindow - 1 - i);
    const size_t idx = static_cast<size_t>(sec) % kThroughputWindow;
    out.push_back(ring_sec_[idx] == sec ? ring_[idx] : ThroughputBucket{});
  }
  return out;
}

uint64_t Statistics::peak_bucket_bytes() const {
  uint64_t peak = 0;
  for (size_t i = 0; i < kThroughputWindow; ++i) {
    if (ring_sec_[i] != 0) peak = std::max(peak, ring_[i].bytes);
  }
  return peak;
}

std::vector<ProtocolCount> Statistics::protocol_distribution() const {
  std::vector<ProtocolCount> v{
      {"TCP", tcp_packets_, tcp_bytes_},
      {"UDP", udp_packets_, udp_bytes_},
      {"ICMP", icmp_packets_, icmp_bytes_},
      {"ARP", arp_packets_, arp_bytes_},
      {"OTHER", other_packets_, other_bytes_},
  };
  std::sort(v.begin(), v.end(), [](const ProtocolCount& a, const ProtocolCount& b) {
    return a.packets > b.packets;
  });
  return v;
}

std::vector<std::pair<uint16_t, uint64_t>> Statistics::top_ports(size_t n) const {
  std::vector<std::pair<uint16_t, uint64_t>> v(port_bytes_.begin(), port_bytes_.end());
  std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
  if (v.size() > n) v.resize(n);
  return v;
}

std::vector<std::pair<std::string, uint64_t>> Statistics::top_talkers(size_t n) const {
  std::vector<std::pair<std::string, uint64_t>> v(talker_bytes_.begin(),
                                                  talker_bytes_.end());
  std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
  if (v.size() > n) v.resize(n);
  return v;
}

// ------------------------------------------------------------ formatting

std::string human_bytes(double bytes) {
  static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
  int u = 0;
  while (bytes >= 1024.0 && u < 4) {
    bytes /= 1024.0;
    ++u;
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), (u == 0) ? "%.0f %s" : "%.1f %s", bytes, units[u]);
  return buf;
}

std::string human_rate_bits(double bits_per_sec) {
  static const char* units[] = {"bps", "Kbps", "Mbps", "Gbps"};
  int u = 0;
  while (bits_per_sec >= 1000.0 && u < 3) {
    bits_per_sec /= 1000.0;
    ++u;
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), (u == 0) ? "%.0f %s" : "%.2f %s", bits_per_sec, units[u]);
  return buf;
}

std::string human_count(uint64_t n) {
  char buf[32];
  if (n < 1000) {
    std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(n));
  } else if (n < 1000000) {
    std::snprintf(buf, sizeof(buf), "%.1fK", static_cast<double>(n) / 1e3);
  } else {
    std::snprintf(buf, sizeof(buf), "%.2fM", static_cast<double>(n) / 1e6);
  }
  return buf;
}

std::string human_duration(double seconds) {
  const int total = static_cast<int>(seconds);
  const int h = total / 3600;
  const int m = (total % 3600) / 60;
  const int s = total % 60;
  char buf[32];
  if (h > 0) {
    std::snprintf(buf, sizeof(buf), "%dh%02dm%02ds", h, m, s);
  } else if (m > 0) {
    std::snprintf(buf, sizeof(buf), "%dm%02ds", m, s);
  } else {
    std::snprintf(buf, sizeof(buf), "%ds", s);
  }
  return buf;
}

}  // namespace netscope
