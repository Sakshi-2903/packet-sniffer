// dashboard.hpp -- live terminal UI built on raw ANSI escape sequences (no
// ncurses dependency) plus a plain-text summary reporter.
#pragma once

#include <string>

#include "analyzer.hpp"
#include "flow.hpp"
#include "stats.hpp"

namespace netscope {

// Everything the header bar needs to know about the running capture.
struct SessionInfo {
  std::string source;   // interface name or file path
  std::string filter;   // BPF expression, empty if none
  std::string backend;  // "libpcap" / "AF_PACKET" / "pcap-file"
  int snaplen = 0;
  bool offline = false;
};

enum class DashboardKey { None, Quit, Pause, CycleSort, Reset };

class Dashboard {
 public:
  ~Dashboard();

  // Switches to the alternate screen buffer and puts the terminal in raw mode
  // so single keypresses arrive without Enter. Returns false if stdout is not a
  // terminal, in which case the caller should fall back to --text mode.
  bool begin();
  void end();

  DashboardKey poll_key();
  void render(const Analyzer& analyzer, const SessionInfo& info);

  void toggle_pause() { paused_ = !paused_; }
  bool paused() const { return paused_; }
  void cycle_sort();
  FlowSort sort() const { return sort_; }

 private:
  void query_size();

  int rows_ = 24;
  int cols_ = 100;
  bool active_ = false;
  bool paused_ = false;
  FlowSort sort_ = FlowSort::Bytes;
  std::string frame_;  // reused draw buffer to keep the render allocation-free
};

// Final report printed when the capture stops, in both TUI and text modes.
void print_summary(const Analyzer& analyzer, const SessionInfo& info);

}  // namespace netscope
