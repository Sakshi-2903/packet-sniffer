// analyzer.hpp -- owns the decode -> flow-tracking -> statistics pipeline and
// serialises access to it.
//
// The capture backend runs on its own thread and calls consume(); the UI thread
// reads the results through read(). One mutex guards both the flow table and the
// counters, which is ample: the critical section is a few hundred nanoseconds of
// integer work per packet.
#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>

#include "capture.hpp"
#include "flow.hpp"
#include "parser.hpp"
#include "stats.hpp"

namespace netscope {

class Analyzer {
 public:
  explicit Analyzer(int linktype) : linktype_(linktype) {}

  // Optional per-packet hook, used by --text mode to print a line per packet.
  // Invoked with the decoded packet and the flow it belongs to (may be null).
  using Observer = std::function<void(const DecodedPacket&, const Flow*)>;
  void set_observer(Observer obs) { observer_ = std::move(obs); }

  // M9/M10 can be disabled to keep the per-packet path minimal.
  void set_dissection_enabled(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    flows_.set_dissection_enabled(on);
  }

  void consume(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
               const timeval& ts) {
    DecodedPacket pkt;
    const bool ok = decode_packet(data, caplen, wirelen, ts, linktype_, pkt);

    std::lock_guard<std::mutex> lock(mu_);
    stats_.add(pkt);
    Flow* flow = ok ? flows_.update(pkt) : nullptr;
    last_ts_ = ts;
    if (observer_) observer_(pkt, flow);
  }

  void update_capture_counters(const CaptureCounters& c) {
    std::lock_guard<std::mutex> lock(mu_);
    stats_.set_kernel_stats(c.received, c.dropped, c.if_dropped);
  }

  // Runs `fn(stats, flows)` while holding the lock. Rendering directly from the
  // live structures avoids copying the whole flow table every frame.
  template <typename Fn>
  void read(Fn&& fn) const {
    std::lock_guard<std::mutex> lock(mu_);
    fn(stats_, flows_);
  }

  size_t expire_idle_flows(double idle_sec) {
    std::lock_guard<std::mutex> lock(mu_);
    if (last_ts_.tv_sec == 0) return 0;
    return flows_.expire(last_ts_, idle_sec);
  }

  void reset() {
    std::lock_guard<std::mutex> lock(mu_);
    stats_.reset();
    flows_.clear();
  }

  int linktype() const { return linktype_; }

 private:
  mutable std::mutex mu_;
  Statistics stats_;
  FlowTable flows_;
  Observer observer_;
  timeval last_ts_{};
  int linktype_;
};

}  // namespace netscope
