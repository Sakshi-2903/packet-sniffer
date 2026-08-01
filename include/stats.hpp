// stats.hpp -- aggregate counters over the whole capture: protocol mix,
// throughput history, TCP flag tallies and top ports/talkers.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "protocol.hpp"

namespace netscope {

// Number of one-second buckets kept for the throughput sparkline.
constexpr size_t kThroughputWindow = 90;

struct ThroughputBucket {
  uint64_t bytes = 0;
  uint64_t packets = 0;
};

struct ProtocolCount {
  const char* name;
  uint64_t packets;
  uint64_t bytes;
};

class Statistics {
 public:
  Statistics();

  void add(const DecodedPacket& p);
  void set_kernel_stats(uint64_t received, uint64_t dropped, uint64_t if_dropped);

  // --- totals ---
  uint64_t packets() const { return packets_; }
  uint64_t bytes() const { return bytes_; }
  uint64_t kernel_dropped() const { return kernel_dropped_; }
  uint64_t if_dropped() const { return if_dropped_; }
  uint64_t decode_errors() const { return decode_errors_; }
  uint64_t truncated() const { return truncated_; }
  uint64_t bad_checksums() const { return bad_checksums_; }
  uint64_t fragments() const { return fragments_; }

  double elapsed_sec() const;
  double avg_bps() const;           // bits/sec since start
  double avg_pps() const;           // packets/sec since start
  double recent_bps(size_t seconds = 5) const;  // bits/sec over last N buckets
  double recent_pps(size_t seconds = 5) const;
  uint64_t peak_bucket_bytes() const;

  // Protocol distribution over L4 (plus ARP and other L3), largest first.
  std::vector<ProtocolCount> protocol_distribution() const;
  std::vector<ThroughputBucket> throughput_history() const;

  // TCP flag tallies.
  uint64_t tcp_syn() const { return tcp_syn_; }
  uint64_t tcp_fin() const { return tcp_fin_; }
  uint64_t tcp_rst() const { return tcp_rst_; }

  std::vector<std::pair<uint16_t, uint64_t>> top_ports(size_t n) const;
  std::vector<std::pair<std::string, uint64_t>> top_talkers(size_t n) const;

  void reset();

 private:
  ThroughputBucket& bucket_for(time_t sec);

  uint64_t packets_ = 0, bytes_ = 0;
  uint64_t kernel_received_ = 0, kernel_dropped_ = 0, if_dropped_ = 0;
  uint64_t decode_errors_ = 0, truncated_ = 0, bad_checksums_ = 0, fragments_ = 0;

  uint64_t tcp_packets_ = 0, tcp_bytes_ = 0;
  uint64_t udp_packets_ = 0, udp_bytes_ = 0;
  uint64_t icmp_packets_ = 0, icmp_bytes_ = 0;
  uint64_t arp_packets_ = 0, arp_bytes_ = 0;
  uint64_t other_packets_ = 0, other_bytes_ = 0;
  uint64_t ipv4_packets_ = 0, ipv6_packets_ = 0;
  uint64_t tcp_syn_ = 0, tcp_fin_ = 0, tcp_rst_ = 0;

  // Ring of one-second buckets, indexed by (epoch second % window).
  std::array<ThroughputBucket, kThroughputWindow> ring_{};
  std::array<time_t, kThroughputWindow> ring_sec_{};
  time_t newest_sec_ = 0;

  std::unordered_map<uint16_t, uint64_t> port_bytes_;
  std::unordered_map<std::string, uint64_t> talker_bytes_;

  timeval start_{};
  timeval last_{};
  bool started_ = false;
};

// Formatting helpers shared by the dashboard and the text reporter.
std::string human_bytes(double bytes);
std::string human_rate_bits(double bits_per_sec);
std::string human_count(uint64_t n);
std::string human_duration(double seconds);

}  // namespace netscope
