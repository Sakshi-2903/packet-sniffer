// pcap_writer.hpp -- M12: writes captured frames to a .pcap file.
//
// The format is deliberately implemented directly rather than through
// pcap_dump(), for two reasons: the AF_PACKET backend has no pcap_t to dump
// through, and a file written here can be opened by Wireshark or tcpdump, which
// makes it a useful cross-check on the decoder ("does Wireshark agree with what
// netscope reported?").
//
// Layout: a 24-byte global header, then per packet a 16-byte record header
// followed by the raw bytes.
#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <sys/time.h>

namespace netscope {

class PcapWriter {
 public:
  ~PcapWriter();

  bool open(const std::string& path, int linktype, int snaplen, std::string& err);
  // Only ever called from the capture thread, so no locking is needed.
  void write(const uint8_t* data, uint32_t caplen, uint32_t wirelen, const timeval& ts);
  void close();

  bool is_open() const { return file_ != nullptr; }
  uint64_t packets_written() const { return packets_; }
  uint64_t bytes_written() const { return bytes_; }
  const std::string& path() const { return path_; }

 private:
  std::FILE* file_ = nullptr;
  std::string path_;
  uint32_t snaplen_ = 262144;
  uint64_t packets_ = 0;
  uint64_t bytes_ = 0;
};

}  // namespace netscope
