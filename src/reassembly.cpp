#include "reassembly.hpp"

#include <algorithm>

#include "flow.hpp"  // seq_lt / seq_le / seq_gt

namespace netscope {

void StreamReassembler::reset() {
  initialized_ = false;
  next_seq_ = 0;
  prefix_.clear();
  pending_.clear();
  buffered_bytes_ = 0;
}

void StreamReassembler::append(const uint8_t* data, size_t len) {
  if (prefix_.size() >= max_prefix_) return;
  const size_t room = max_prefix_ - prefix_.size();
  const size_t take = std::min(room, len);
  prefix_.append(reinterpret_cast<const char*>(data), take);
  if (take < len) discarded_bytes_ += len - take;
}

size_t StreamReassembler::push(uint32_t seq, const uint8_t* data, size_t len,
                               bool syn) {
  if (!initialized_) {
    // A SYN carries the initial sequence number and consumes it, so the first
    // data byte is at seq+1. Joining mid-stream, the first segment seen defines
    // the origin instead.
    next_seq_ = syn ? seq + 1 : seq;
    initialized_ = true;
  }
  if (len == 0 || data == nullptr) return 0;

  // Already-delivered bytes at the front of the segment are trimmed. This is
  // what a retransmission or a partially overlapping segment looks like.
  if (seq_lt(seq, next_seq_)) {
    const uint32_t already = next_seq_ - seq;
    overlap_bytes_ += std::min<uint64_t>(already, len);
    if (already >= len) return 0;  // entirely old data
    data += already;
    len -= already;
    seq = next_seq_;
  }

  size_t new_bytes = 0;

  if (seq == next_seq_) {
    append(data, len);
    next_seq_ += static_cast<uint32_t>(len);
    delivered_ += len;
    new_bytes = len;
    new_bytes += drain();
    return new_bytes;
  }

  // Ahead of what is expected: hold it until the gap is filled. Once the prefix
  // is full there is nothing left to reconstruct, so buffering stops.
  if (saturated() || buffered_bytes_ + len > max_buffered_) {
    discarded_bytes_ += len;
    return 0;
  }
  auto [it, inserted] = pending_.emplace(seq, std::string(reinterpret_cast<const char*>(data), len));
  if (inserted) {
    buffered_bytes_ += len;
    ++buffered_segments_;
  } else if (it->second.size() < len) {
    // A longer copy of a segment already held: keep the longer one.
    buffered_bytes_ += len - it->second.size();
    it->second.assign(reinterpret_cast<const char*>(data), len);
  }
  return 0;
}

size_t StreamReassembler::drain() {
  size_t delivered_now = 0;
  while (!pending_.empty()) {
    auto it = pending_.begin();
    const uint32_t seq = it->first;
    if (seq_gt(seq, next_seq_)) break;  // still a hole before this segment

    std::string bytes = std::move(it->second);
    buffered_bytes_ -= bytes.size();
    pending_.erase(it);

    // Trim any part that the prefix already covers.
    const uint32_t already = next_seq_ - seq;
    if (already >= bytes.size()) {
      overlap_bytes_ += bytes.size();
      continue;
    }
    const uint8_t* start = reinterpret_cast<const uint8_t*>(bytes.data()) + already;
    const size_t len = bytes.size() - already;
    overlap_bytes_ += already;

    append(start, len);
    next_seq_ += static_cast<uint32_t>(len);
    delivered_ += len;
    delivered_now += len;
  }
  return delivered_now;
}

}  // namespace netscope
