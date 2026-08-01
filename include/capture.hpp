// capture.hpp -- packet sources. Two interchangeable backends are provided:
//   * libpcap  -- portable live capture plus offline .pcap replay
//   * AF_PACKET raw socket -- Linux-native capture with a kernel-attached BPF
//                             program, showing what libpcap does underneath
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <sys/time.h>
#include <vector>

namespace netscope {

struct CaptureConfig {
  std::string interface;   // NIC to capture from; empty selects a default
  std::string pcap_file;   // if non-empty, replay this file instead
  std::string filter;      // BPF expression, e.g. "tcp port 443"
  int snaplen = 262144;    // bytes captured per frame
  bool promiscuous = true;
  int timeout_ms = 200;    // how long a read may block before we re-check flags
};

struct CaptureCounters {
  uint64_t received = 0;    // packets seen by the capture mechanism
  uint64_t dropped = 0;     // dropped by the kernel buffer
  uint64_t if_dropped = 0;  // dropped by the interface/driver
};

struct InterfaceInfo {
  std::string name;
  std::string description;
  std::string address;
  bool is_up = false;
  bool is_loopback = false;
};

// Called once per captured frame. The buffer is only valid for the duration of
// the call.
using PacketSink = std::function<void(const uint8_t* data, uint32_t caplen,
                                      uint32_t wirelen, const timeval& ts)>;

class Capture {
 public:
  virtual ~Capture() = default;

  virtual bool open(const CaptureConfig& cfg, std::string& err) = 0;
  virtual void close() = 0;

  // Reads packets until `running` goes false, `max_packets` have been delivered
  // (0 = unlimited), or the input ends. Returns false only on a hard error.
  virtual bool run(const PacketSink& sink, std::atomic<bool>& running,
                   uint64_t max_packets, std::string& err) = 0;

  virtual CaptureCounters counters() const = 0;
  virtual int linktype() const = 0;  // libpcap DLT_* value
  virtual const char* backend_name() const = 0;
  virtual bool is_offline() const { return false; }
};

std::unique_ptr<Capture> make_pcap_capture();
std::unique_ptr<Capture> make_raw_socket_capture();

std::vector<InterfaceInfo> list_interfaces(std::string& err);
std::string pick_default_interface(std::string& err);

// Compiles a BPF expression against a link type without opening a device, so
// bad filters can be reported before capture starts.
bool validate_bpf_filter(const std::string& filter, int linktype, std::string& err);

}  // namespace netscope
