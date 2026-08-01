#include "dashboard.hpp"

#include <cerrno>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace netscope {

namespace {

// ---- ANSI helpers -------------------------------------------------------
constexpr const char* kReset = "\x1b[0m";
constexpr const char* kBold = "\x1b[1m";
constexpr const char* kDim = "\x1b[2m";
constexpr const char* kReverse = "\x1b[7m";
constexpr const char* kRed = "\x1b[31m";
constexpr const char* kGreen = "\x1b[32m";
constexpr const char* kYellow = "\x1b[33m";
constexpr const char* kBlue = "\x1b[34m";
constexpr const char* kMagenta = "\x1b[35m";
constexpr const char* kCyan = "\x1b[36m";
constexpr const char* kGrey = "\x1b[90m";

constexpr const char* kAltScreenOn = "\x1b[?1049h";
constexpr const char* kAltScreenOff = "\x1b[?1049l";
constexpr const char* kHideCursor = "\x1b[?25l";
constexpr const char* kShowCursor = "\x1b[?25h";
constexpr const char* kHome = "\x1b[H";
constexpr const char* kClearScreen = "\x1b[2J";
constexpr const char* kClearToEol = "\x1b[K";

termios g_saved_termios{};
bool g_termios_saved = false;

// Eight levels of vertical bar, used for the throughput sparkline.
const char* kSparkLevels[9] = {" ", "\u2581", "\u2582", "\u2583", "\u2584",
                               "\u2585", "\u2586", "\u2587", "\u2588"};

// Pads or clips an ASCII string to exactly `width` columns.
std::string fit(std::string s, size_t width) {
  if (s.size() > width) {
    if (width <= 2) return s.substr(0, width);
    return s.substr(0, width - 2) + "..";
  }
  s.append(width - s.size(), ' ');
  return s;
}

std::string right(std::string s, size_t width) {
  if (s.size() >= width) return s.substr(0, width);
  return std::string(width - s.size(), ' ') + s;
}

const char* color_for_protocol(const char* name) {
  if (std::strcmp(name, "TCP") == 0) return kCyan;
  if (std::strcmp(name, "UDP") == 0) return kGreen;
  if (std::strcmp(name, "ICMP") == 0) return kYellow;
  if (std::strcmp(name, "ARP") == 0) return kMagenta;
  return kGrey;
}

const char* color_for_state(TcpState s) {
  switch (s) {
    case TcpState::Established: return kGreen;
    case TcpState::SynSent:
    case TcpState::SynReceived:  return kYellow;
    case TcpState::Reset:        return kRed;
    case TcpState::Closed:
    case TcpState::Closing:
    case TcpState::FinWait:      return kGrey;
    default:                     return kReset;
  }
}

std::string bar(double fraction, size_t width) {
  if (fraction < 0) fraction = 0;
  if (fraction > 1) fraction = 1;
  const size_t filled = static_cast<size_t>(fraction * static_cast<double>(width) + 0.5);
  std::string s;
  for (size_t i = 0; i < width; ++i) s += (i < filled) ? "\u2588" : "\u2591";
  return s;
}

}  // namespace

Dashboard::~Dashboard() { end(); }

void Dashboard::query_size() {
  winsize ws{};
  if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
    cols_ = ws.ws_col;
    rows_ = ws.ws_row;
  }
  cols_ = std::clamp(cols_, 60, 220);
  rows_ = std::clamp(rows_, 16, 80);
}

bool Dashboard::begin() {
  if (!isatty(STDOUT_FILENO) || !isatty(STDIN_FILENO)) return false;

  if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
    g_termios_saved = true;
    termios raw = g_saved_termios;
    // Turn off line buffering and echo so keys are read as they are pressed,
    // and make read() non-blocking by requiring zero characters.
    raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO));
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &raw);
  }

  query_size();
  std::fputs(kAltScreenOn, stdout);
  std::fputs(kHideCursor, stdout);
  std::fputs(kClearScreen, stdout);
  std::fflush(stdout);
  active_ = true;
  return true;
}

void Dashboard::end() {
  if (!active_) return;
  std::fputs(kShowCursor, stdout);
  std::fputs(kAltScreenOff, stdout);
  std::fputs(kReset, stdout);
  std::fflush(stdout);
  if (g_termios_saved) {
    tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
    g_termios_saved = false;
  }
  active_ = false;
}

DashboardKey Dashboard::poll_key() {
  if (!active_) return DashboardKey::None;
  char c = 0;
  const ssize_t n = ::read(STDIN_FILENO, &c, 1);
  if (n != 1) return DashboardKey::None;
  switch (c) {
    case 'q': case 'Q': case 3 /* Ctrl-C */: return DashboardKey::Quit;
    case 'p': case 'P': case ' ':           return DashboardKey::Pause;
    case 's': case 'S':                     return DashboardKey::CycleSort;
    case 'r': case 'R':                     return DashboardKey::Reset;
    default:                                return DashboardKey::None;
  }
}

void Dashboard::cycle_sort() {
  switch (sort_) {
    case FlowSort::Bytes:       sort_ = FlowSort::Packets; break;
    case FlowSort::Packets:     sort_ = FlowSort::Retransmits; break;
    case FlowSort::Retransmits: sort_ = FlowSort::Rtt; break;
    case FlowSort::Rtt:         sort_ = FlowSort::Recent; break;
    case FlowSort::Recent:      sort_ = FlowSort::Bytes; break;
  }
}

void Dashboard::render(const Analyzer& analyzer, const SessionInfo& info) {
  if (!active_) return;
  query_size();

  const size_t W = static_cast<size_t>(cols_);
  frame_.clear();
  frame_ += kHome;

  int line_budget = rows_;
  auto push = [&](const std::string& text) {
    frame_ += text;
    frame_ += kClearToEol;
    frame_ += "\r\n";
    --line_budget;
  };

  analyzer.read([&](const Statistics& stats, const FlowTable& flows) {
    // ---------------------------------------------------------- title bar
    {
      std::ostringstream os;
      os << " netscope  " << (info.offline ? "file=" : "iface=") << info.source
         << "  backend=" << info.backend;
      if (!info.filter.empty()) os << "  bpf=\"" << info.filter << '"';
      os << "  up " << human_duration(stats.elapsed_sec());
      if (paused_) os << "  [PAUSED]";
      push(std::string(kReverse) + kBold + fit(os.str(), W) + kReset);
    }

    // ------------------------------------------------------ headline totals
    {
      std::ostringstream os;
      os << " " << kBold << "pkts" << kReset << " " << human_count(stats.packets())
         << "   " << kBold << "vol" << kReset << " " << human_bytes(static_cast<double>(stats.bytes()))
         << "   " << kBold << "now" << kReset << " " << human_rate_bits(stats.recent_bps(5))
         << " / " << static_cast<uint64_t>(stats.recent_pps(5)) << " pps"
         << "   " << kBold << "avg" << kReset << " " << human_rate_bits(stats.avg_bps())
         << "   " << kBold << "flows" << kReset << " " << flows.size() << "/"
         << flows.total_flows_seen();
      // Colouring makes the width calculation unreliable, so this line is not
      // padded -- the escape sequences add no visible columns.
      push(os.str());
    }
    {
      std::ostringstream os;
      const uint64_t drops = stats.kernel_dropped() + stats.if_dropped();
      os << " " << kDim << "drops" << kReset << " "
         << (drops ? kRed : kGrey) << drops << kReset
         << "   " << kDim << "decode-err" << kReset << " " << stats.decode_errors()
         << "   " << kDim << "trunc" << kReset << " " << stats.truncated()
         << "   " << kDim << "bad-cksum" << kReset << " " << stats.bad_checksums()
         << "   " << kDim << "frags" << kReset << " " << stats.fragments()
         << "   " << kDim << "snaplen" << kReset << " " << info.snaplen;
      push(os.str());
    }
    push("");

    // ------------------------------------------------ protocol distribution
    push(std::string(kBold) + " PROTOCOL DISTRIBUTION" + kReset);
    {
      const auto dist = stats.protocol_distribution();
      const double total = static_cast<double>(std::max<uint64_t>(stats.packets(), 1));
      const size_t bar_w = std::min<size_t>(40, W > 55 ? W - 46 : 12);
      for (const auto& p : dist) {
        if (p.packets == 0) continue;
        const double frac = static_cast<double>(p.packets) / total;
        std::ostringstream os;
        os << "  " << color_for_protocol(p.name) << fit(p.name, 6) << kReset
           << color_for_protocol(p.name) << bar(frac, bar_w) << kReset << ' '
           << right(std::to_string(static_cast<int>(frac * 100.0 + 0.5)) + "%", 4) << "  "
           << right(human_count(p.packets), 7) << " pkts  "
           << right(human_bytes(static_cast<double>(p.bytes)), 9);
        push(os.str());
      }
      if (stats.packets() == 0) push(std::string(kGrey) + "  waiting for packets..." + kReset);
    }
    push("");

    // ------------------------------------------------------------ throughput
    {
      const auto hist = stats.throughput_history();
      const uint64_t peak = std::max<uint64_t>(stats.peak_bucket_bytes(), 1);
      std::ostringstream head;
      head << kBold << " THROUGHPUT" << kReset << kDim << "  (last "
           << hist.size() << "s, peak " << human_rate_bits(static_cast<double>(peak) * 8.0)
           << ")" << kReset;
      push(head.str());

      std::string spark = "  ";
      const size_t avail = W > 6 ? W - 6 : 20;
      const size_t start = hist.size() > avail ? hist.size() - avail : 0;
      for (size_t i = start; i < hist.size(); ++i) {
        const double frac = static_cast<double>(hist[i].bytes) / static_cast<double>(peak);
        size_t level = static_cast<size_t>(frac * 8.0 + 0.5);
        if (hist[i].bytes > 0 && level == 0) level = 1;
        spark += kSparkLevels[std::min<size_t>(level, 8)];
      }
      push(std::string(kCyan) + spark + kReset);
    }
    push("");

    // ----------------------------------------------------------- tcp health
    {
      const uint64_t segs = flows.total_tcp_data_segments();
      const uint64_t retx = flows.total_retransmits();
      const double rate = segs ? 100.0 * static_cast<double>(retx) / static_cast<double>(segs) : 0.0;
      const char* rate_color = rate >= 5.0 ? kRed : (rate >= 1.0 ? kYellow : kGreen);

      std::ostringstream os;
      os << kBold << " TCP HEALTH" << kReset
         << "  established " << kGreen << flows.active_tcp() << kReset
         << "   syn " << stats.tcp_syn()
         << "   fin " << stats.tcp_fin()
         << "   rst " << (stats.tcp_rst() ? kRed : kReset) << stats.tcp_rst() << kReset
         << "   retrans " << rate_color << retx << " / " << segs << " ("
         << std::fixed << std::setprecision(2) << rate << "%)" << kReset
         << "   ooo " << flows.total_out_of_order();
      const double mean_rtt = flows.mean_rtt_ms();
      if (mean_rtt >= 0.0) {
        os << "   rtt " << std::fixed << std::setprecision(1) << mean_rtt << " ms";
      }
      push(os.str());

      // M10: which application protocols the flows were identified as.
      const auto apps = flows.app_protocols();
      if (!apps.empty()) {
        std::ostringstream a;
        a << kBold << " APPLICATION" << kReset << " ";
        for (const auto& [proto, count] : apps) {
          a << ' ' << kBlue << to_string(proto) << kReset << ' ' << count;
        }
        push(a.str());
      }
    }
    push("");

    // ------------------------------------------------------------ flow table
    {
      std::ostringstream head;
      head << kBold << " TOP FLOWS" << kReset << kDim << "  sorted by " << to_string(sort_)
           << kReset;
      push(head.str());

      // Fixed-width columns; whatever is left is split between the endpoint
      // pair and the application detail, with detail dropped on narrow terminals.
      const size_t fixed = 2 + 6 + 11 + 7 + 9 + 5 + 7 + 6 + 1;
      const size_t flexible = W > fixed + 24 ? W - fixed : 24;
      const size_t ep_w = std::min<size_t>(42, std::max<size_t>(24, flexible * 55 / 100));
      const size_t detail_w = flexible > ep_w + 8 ? flexible - ep_w : 0;

      std::ostringstream hdr;
      hdr << "  " << fit("PROTO", 6) << fit("ENDPOINTS", ep_w) << ' '
          << fit("STATE", 11) << right("PKTS", 7) << right("BYTES", 9)
          << right("RETX", 5) << right("RTT", 7) << right("AGE", 6);
      if (detail_w) hdr << "  " << fit("APPLICATION", detail_w - 2);
      push(std::string(kDim) + fit(hdr.str(), W) + kReset);

      const int reserved = 2;  // footer + blank
      const size_t max_rows = static_cast<size_t>(std::max(1, line_budget - reserved));
      const auto top = flows.top(max_rows, sort_);
      for (const Flow* f : top) {
        const double rtt = f->best_rtt_ms();
        char rtt_buf[16];
        if (rtt >= 0.0) {
          std::snprintf(rtt_buf, sizeof(rtt_buf), "%.1fms", rtt);
        } else {
          std::snprintf(rtt_buf, sizeof(rtt_buf), "-");
        }

        std::ostringstream os;
        os << "  " << fit(to_string(f->l4), 6) << fit(f->label(), ep_w) << ' '
           << color_for_state(f->state) << fit(to_string(f->state), 11) << kReset
           << right(human_count(f->packets()), 7)
           << right(human_bytes(static_cast<double>(f->bytes())), 9)
           << (f->retransmits() ? kYellow : kReset)
           << right(std::to_string(f->retransmits()), 5) << kReset
           << right(rtt_buf, 7)
           << right(human_duration(f->duration_sec()), 6);
        if (detail_w) {
          os << "  " << kBlue << fit(f->app_summary(), detail_w - 2) << kReset;
        }
        push(os.str());
      }
      if (top.empty()) push(std::string(kGrey) + "  no flows yet" + kReset);
    }

    // ---------------------------------------------------------------- footer
    while (line_budget > 1) push("");
    {
      std::ostringstream os;
      os << " q quit   p pause   s sort   r reset ";
      push(std::string(kReverse) + fit(os.str(), W) + kReset);
    }
  });

  // One write per frame keeps the redraw atomic and flicker-free. write() may
  // still return short on a slow terminal, so the remainder is pushed out rather
  // than dropped -- a truncated frame would leave the display corrupted.
  size_t written = 0;
  while (written < frame_.size()) {
    const ssize_t n = ::write(STDOUT_FILENO, frame_.data() + written,
                              frame_.size() - written);
    if (n > 0) {
      written += static_cast<size_t>(n);
    } else if (n < 0 && errno == EINTR) {
      continue;  // interrupted by a signal: retry
    } else {
      break;     // terminal closed or unwritable; nothing useful left to do
    }
  }
}

// ---------------------------------------------------------------- summary

void print_summary(const Analyzer& analyzer, const SessionInfo& info) {
  analyzer.read([&](const Statistics& stats, const FlowTable& flows) {
    std::ostringstream os;
    os << "\n==================== capture summary ====================\n";
    os << "source              : " << info.source << " (" << info.backend << ")\n";
    if (!info.filter.empty()) os << "bpf filter          : " << info.filter << "\n";
    os << "duration            : " << human_duration(stats.elapsed_sec()) << "\n";
    os << "packets captured    : " << stats.packets() << "\n";
    os << "bytes captured      : " << human_bytes(static_cast<double>(stats.bytes()))
       << " (" << stats.bytes() << " B)\n";
    os << "average throughput  : " << human_rate_bits(stats.avg_bps()) << "  ("
       << static_cast<uint64_t>(stats.avg_pps()) << " pps)\n";
    if (stats.kernel_dropped() || stats.if_dropped()) {
      os << "dropped             : " << stats.kernel_dropped() << " kernel, "
         << stats.if_dropped() << " interface\n";
    }
    if (stats.decode_errors() || stats.truncated() || stats.bad_checksums()) {
      os << "anomalies           : " << stats.decode_errors() << " undecoded, "
         << stats.truncated() << " truncated, " << stats.bad_checksums()
         << " bad IPv4 checksums, " << stats.fragments() << " fragments\n";
    }

    os << "\nprotocol distribution\n";
    const double total = static_cast<double>(std::max<uint64_t>(stats.packets(), 1));
    for (const auto& p : stats.protocol_distribution()) {
      if (p.packets == 0) continue;
      char buf[128];
      std::snprintf(buf, sizeof(buf), "  %-6s %8llu pkts  %6.2f%%  %10s\n", p.name,
                    static_cast<unsigned long long>(p.packets),
                    100.0 * static_cast<double>(p.packets) / total,
                    human_bytes(static_cast<double>(p.bytes)).c_str());
      os << buf;
    }

    const uint64_t segs = flows.total_tcp_data_segments();
    const uint64_t retx = flows.total_retransmits();
    os << "\ntcp\n";
    os << "  flows tracked     : " << flows.total_flows_seen() << " (" << flows.size()
       << " still active)\n";
    os << "  established now   : " << flows.active_tcp() << "\n";
    os << "  syn/fin/rst       : " << stats.tcp_syn() << " / " << stats.tcp_fin()
       << " / " << stats.tcp_rst() << "\n";
    char rbuf[128];
    std::snprintf(rbuf, sizeof(rbuf), "  retransmissions   : %llu of %llu data segments (%.2f%%)\n",
                  static_cast<unsigned long long>(retx),
                  static_cast<unsigned long long>(segs),
                  segs ? 100.0 * static_cast<double>(retx) / static_cast<double>(segs) : 0.0);
    os << rbuf;
    os << "  out-of-order      : " << flows.total_out_of_order() << " segments\n";
    if (flows.total_reassembled_bytes() > 0) {
      os << "  stream reassembly : "
         << human_bytes(static_cast<double>(flows.total_reassembled_bytes()))
         << " delivered in order\n";
    }

    const double mean_rtt = flows.mean_rtt_ms();
    if (mean_rtt >= 0.0) {
      std::snprintf(rbuf, sizeof(rbuf), "  round-trip time   : %.2f ms mean over %llu samples\n",
                    mean_rtt, static_cast<unsigned long long>(flows.total_rtt_samples()));
      os << rbuf;
    }

    const auto apps = flows.app_protocols();
    if (!apps.empty()) {
      os << "\napplication protocols identified\n";
      for (const auto& [proto, count] : apps) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "  %-8s %6llu flows\n", to_string(proto),
                      static_cast<unsigned long long>(count));
        os << buf;
      }
    }

    const auto ports = stats.top_ports(5);
    if (!ports.empty()) {
      os << "\ntop service ports by volume\n";
      for (const auto& [port, bytes] : ports) {
        const char* svc = service_name(port, L4Proto::TCP);
        if (svc == nullptr) svc = service_name(port, L4Proto::UDP);
        char buf[96];
        std::snprintf(buf, sizeof(buf), "  %-6u %-12s %10s\n", port, svc ? svc : "-",
                      human_bytes(static_cast<double>(bytes)).c_str());
        os << buf;
      }
    }

    const auto talkers = stats.top_talkers(5);
    if (!talkers.empty()) {
      os << "\ntop talkers by bytes sent\n";
      for (const auto& [addr, bytes] : talkers) {
        char buf[128];
        std::snprintf(buf, sizeof(buf), "  %-42s %10s\n", addr.c_str(),
                      human_bytes(static_cast<double>(bytes)).c_str());
        os << buf;
      }
    }

    const auto top_flows = flows.top(10, FlowSort::Bytes);
    if (!top_flows.empty()) {
      os << "\ntop flows by bytes\n";
      for (const Flow* f : top_flows) {
        const double rtt = f->best_rtt_ms();
        char rtt_buf[16];
        if (rtt >= 0.0) {
          std::snprintf(rtt_buf, sizeof(rtt_buf), "%.1fms", rtt);
        } else {
          std::snprintf(rtt_buf, sizeof(rtt_buf), "-");
        }
        char buf[288];
        std::snprintf(buf, sizeof(buf),
                      "  %-5s %-46s %-12s %7llu pkts %9s retx=%-4llu rtt=%-8s %s\n",
                      to_string(f->l4), f->label().c_str(), to_string(f->state),
                      static_cast<unsigned long long>(f->packets()),
                      human_bytes(static_cast<double>(f->bytes())).c_str(),
                      static_cast<unsigned long long>(f->retransmits()), rtt_buf,
                      f->app_summary().c_str());
        os << buf;
      }
    }
    os << "=========================================================\n";
    std::cout << os.str() << std::flush;
  });
}

}  // namespace netscope
