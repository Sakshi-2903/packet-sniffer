// reassembly.hpp -- M9: in-order reconstruction of one direction of a TCP stream.
//
// TCP is a byte stream, but capture delivers segments: they arrive out of order,
// overlap after a retransmission, and repeat. Anything that reads the stream
// content (an HTTP request line, a TLS ClientHello) must see the bytes in the
// order the receiving application would, not the order the wire delivered them.
//
// Only a bounded prefix of each direction is retained. Application protocols
// announce themselves in their first few kilobytes, so once that much has been
// delivered the reassembler stops buffering and the flow releases it. Memory is
// therefore capped per direction regardless of how long the connection lives.
#pragma once

#include <cstdint>
#include <map>
#include <string>

namespace netscope {

class StreamReassembler {
 public:
  StreamReassembler(size_t max_prefix = 8192, size_t max_buffered = 32768)
      : max_prefix_(max_prefix), max_buffered_(max_buffered) {}

  // Feeds one segment. `syn` must be set for a SYN segment so the initial
  // sequence number is anchored correctly (the SYN itself consumes one number
  // without carrying data). Returns how many new in-order bytes reached the
  // prefix as a result -- which may exceed `len` when this segment filled a gap
  // and released buffered successors.
  size_t push(uint32_t seq, const uint8_t* data, size_t len, bool syn);

  // Contiguous stream bytes from the start of the connection.
  const std::string& prefix() const { return prefix_; }

  bool initialized() const { return initialized_; }
  bool has_gap() const { return !pending_.empty(); }
  // True once the prefix is full: further content is of no interest.
  bool saturated() const { return prefix_.size() >= max_prefix_; }

  uint64_t bytes_delivered() const { return delivered_; }
  uint64_t segments_buffered() const { return buffered_segments_; }
  uint64_t overlap_bytes() const { return overlap_bytes_; }
  uint64_t discarded_bytes() const { return discarded_bytes_; }
  uint32_t next_seq() const { return next_seq_; }

  void reset();

 private:
  // Moves buffered segments into the prefix while they are contiguous.
  size_t drain();
  void append(const uint8_t* data, size_t len);

  bool initialized_ = false;
  uint32_t next_seq_ = 0;   // next sequence number expected in the prefix
  std::string prefix_;
  std::map<uint32_t, std::string> pending_;  // seq -> bytes waiting on a gap
  size_t buffered_bytes_ = 0;
  size_t max_prefix_;
  size_t max_buffered_;

  uint64_t delivered_ = 0;
  uint64_t buffered_segments_ = 0;
  uint64_t overlap_bytes_ = 0;
  uint64_t discarded_bytes_ = 0;
};

}  // namespace netscope
