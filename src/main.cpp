// netscope -- live packet capture and protocol analyser.
//
// Structure: a capture backend feeds raw frames to Analyzer on a dedicated
// thread; the main thread drives the terminal dashboard and reads the shared
// state under a mutex. Ctrl-C (or 'q') flips one atomic flag, both loops
// unwind, and the summary is printed on the way out.
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>

#include "analyzer.hpp"
#include "capture.hpp"
#include "dashboard.hpp"
#include "parser.hpp"
#include "pcap_writer.hpp"

namespace {

std::atomic<bool> g_running{true};

void handle_signal(int) { g_running.store(false, std::memory_order_relaxed); }

void print_usage(const char* argv0) {
  std::printf(
      "netscope -- packet capture and protocol analyser\n"
      "\n"
      "usage: %s [options]\n"
      "\n"
      "capture source\n"
      "  -i, --interface <name>   interface to capture from (default: first active NIC)\n"
      "  -r, --read <file.pcap>   replay a capture file instead of a live interface\n"
      "  -L, --list               list available interfaces and exit\n"
      "\n"
      "filtering and limits\n"
      "  -f, --filter <bpf>       BPF expression, e.g. \"tcp port 443 or icmp\"\n"
      "  -c, --count <n>          stop after n packets\n"
      "  -s, --snaplen <n>        bytes to capture per frame (default 262144)\n"
      "  -P, --no-promisc         do not put the interface in promiscuous mode\n"
      "\n"
      "backend and output\n"
      "  -b, --backend <pcap|raw> capture backend (default pcap; raw = AF_PACKET socket, Linux only)\n"
      "  -w, --write <file.pcap>  save captured frames to a pcap file (readable by Wireshark)\n"
      "  -t, --text               print one line per packet instead of the dashboard\n"
      "  -q, --quiet              with --text, suppress packet lines and print only the summary\n"
      "  -e, --expire <sec>       idle timeout before a flow is evicted (default 120)\n"
      "  -D, --no-dissect         skip stream reassembly and application decoding\n"
      "  -h, --help               this message\n"
      "\n"
      "examples\n"
      "  sudo %s -i eth0\n"
      "  sudo %s -i eth0 -f \"tcp and not port 22\"\n"
      "  sudo %s -i eth0 -b raw -t -c 200   (Linux only)\n"
      "  %s -r captures/sample.pcap -t\n"
      "  sudo %s -i eth0 -f \"tcp port 443\" -w captures/tls.pcap\n"
      "\n"
#if defined(__linux__)
      "live capture needs CAP_NET_RAW; see the README for the setcap alternative to sudo.\n",
#else
      "live capture needs access to /dev/bpf*; run with sudo, or see the README.\n",
#endif
      argv0, argv0, argv0, argv0, argv0, argv0);
}

struct Options {
  netscope::CaptureConfig capture;
  std::string backend = "pcap";
  uint64_t max_packets = 0;
  double expire_sec = 120.0;
  bool text_mode = false;
  bool quiet = false;
  bool list_interfaces = false;
  bool dissect = true;
  std::string write_path;
};

// Returns false when the program should exit; `exit_code` says with what.
bool parse_options(int argc, char** argv, Options& opt, int& exit_code) {
  exit_code = 0;
  auto need_value = [&](int& i, const char* flag) -> const char* {
    if (i + 1 >= argc) {
      std::fprintf(stderr, "error: %s needs a value\n", flag);
      exit_code = 2;
      return nullptr;
    }
    return argv[++i];
  };

  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto is = [&](const char* s, const char* l) {
      return arg == s || arg == l;
    };

    if (is("-h", "--help")) {
      print_usage(argv[0]);
      return false;
    } else if (is("-L", "--list")) {
      opt.list_interfaces = true;
    } else if (is("-i", "--interface")) {
      const char* v = need_value(i, "--interface");
      if (!v) return false;
      opt.capture.interface = v;
    } else if (is("-r", "--read")) {
      const char* v = need_value(i, "--read");
      if (!v) return false;
      opt.capture.pcap_file = v;
    } else if (is("-f", "--filter")) {
      const char* v = need_value(i, "--filter");
      if (!v) return false;
      opt.capture.filter = v;
    } else if (is("-c", "--count")) {
      const char* v = need_value(i, "--count");
      if (!v) return false;
      opt.max_packets = std::strtoull(v, nullptr, 10);
    } else if (is("-s", "--snaplen")) {
      const char* v = need_value(i, "--snaplen");
      if (!v) return false;
      opt.capture.snaplen = std::atoi(v);
      if (opt.capture.snaplen < 64) {
        std::fprintf(stderr, "error: snaplen must be at least 64\n");
        exit_code = 2;
        return false;
      }
    } else if (is("-b", "--backend")) {
      const char* v = need_value(i, "--backend");
      if (!v) return false;
      opt.backend = v;
      if (opt.backend != "pcap" && opt.backend != "raw") {
        std::fprintf(stderr, "error: backend must be 'pcap' or 'raw'\n");
        exit_code = 2;
        return false;
      }
    } else if (is("-e", "--expire")) {
      const char* v = need_value(i, "--expire");
      if (!v) return false;
      opt.expire_sec = std::strtod(v, nullptr);
    } else if (is("-w", "--write")) {
      const char* v = need_value(i, "--write");
      if (!v) return false;
      opt.write_path = v;
    } else if (is("-D", "--no-dissect")) {
      opt.dissect = false;
    } else if (is("-P", "--no-promisc")) {
      opt.capture.promiscuous = false;
    } else if (is("-t", "--text")) {
      opt.text_mode = true;
    } else if (is("-q", "--quiet")) {
      opt.quiet = true;
      opt.text_mode = true;
    } else {
      std::fprintf(stderr, "error: unknown option '%s' (try --help)\n", arg.c_str());
      exit_code = 2;
      return false;
    }
  }
  return true;
}

int do_list_interfaces() {
  std::string err;
  const auto ifaces = netscope::list_interfaces(err);
  if (ifaces.empty()) {
    std::fprintf(stderr, "no interfaces found%s%s\n", err.empty() ? "" : ": ", err.c_str());
    return 1;
  }
  std::printf("%-16s %-18s %-8s %s\n", "INTERFACE", "IPV4", "STATE", "NOTES");
  for (const auto& i : ifaces) {
    std::printf("%-16s %-18s %-8s %s%s\n", i.name.c_str(),
                i.address.empty() ? "-" : i.address.c_str(), i.is_up ? "up" : "down",
                i.is_loopback ? "loopback " : "", i.description.c_str());
  }
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  int exit_code = 0;
  if (!parse_options(argc, argv, opt, exit_code)) return exit_code;
  if (opt.list_interfaces) return do_list_interfaces();

  // Resolve the interface before opening anything so the error message is clear.
  if (opt.capture.pcap_file.empty() && opt.capture.interface.empty()) {
    std::string err;
    opt.capture.interface = netscope::pick_default_interface(err);
    if (opt.capture.interface.empty()) {
      std::fprintf(stderr, "error: %s (try --list)\n", err.c_str());
      return 1;
    }
  }

  // Syntax-check the filter early: a typo should not cost the user a sudo prompt.
  if (!opt.capture.filter.empty()) {
    std::string err;
    if (!netscope::validate_bpf_filter(opt.capture.filter, 1 /* DLT_EN10MB */, err)) {
      std::fprintf(stderr, "error: %s\n", err.c_str());
      return 2;
    }
  }

#if !defined(__linux__)
  if (opt.backend == "raw") {
    std::fprintf(stderr,
                 "error: the raw AF_PACKET backend is Linux-only.\n"
                 "  This platform captures through libpcap, which is the same\n"
                 "  mechanism underneath -- run without --backend raw.\n");
    return 2;
  }
#endif

  auto capture = (opt.backend == "raw") ? netscope::make_raw_socket_capture()
                                        : netscope::make_pcap_capture();
  std::string err;
  if (!capture->open(opt.capture, err)) {
    std::fprintf(stderr, "error: %s\n", err.c_str());
    return 1;
  }

  netscope::SessionInfo info;
  info.source = opt.capture.pcap_file.empty() ? opt.capture.interface : opt.capture.pcap_file;
  info.filter = opt.capture.filter;
  info.backend = capture->backend_name();
  info.snaplen = opt.capture.snaplen;
  info.offline = capture->is_offline();

  netscope::Analyzer analyzer(capture->linktype());
  analyzer.set_dissection_enabled(opt.dissect);

  // M12: optional pcap output. Opened after the capture so the link type in the
  // file header matches what the frames actually are.
  netscope::PcapWriter writer;
  if (!opt.write_path.empty()) {
    if (!writer.open(opt.write_path, capture->linktype(), opt.capture.snaplen, err)) {
      std::fprintf(stderr, "error: %s\n", err.c_str());
      return 1;
    }
  }

  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);

  netscope::Dashboard dashboard;
  const bool use_tui = !opt.text_mode && dashboard.begin();

  if (!use_tui && !opt.quiet) {
    // Packet lines are only printed in text mode; doing it from the observer
    // keeps the capture path free of any output branching.
    analyzer.set_observer([](const netscope::DecodedPacket& p, const netscope::Flow* flow) {
      std::string line = netscope::format_packet_line(p);
      if (flow != nullptr && flow->l4 == netscope::L4Proto::TCP) {
        line += std::string(" state=") + netscope::to_string(flow->state);
      }
      if (flow != nullptr && flow->app.identified()) {
        line += " [" + flow->app_summary() + "]";
      }
      std::puts(line.c_str());
    });
    std::printf("capturing on %s (%s), snaplen %d%s%s\n", info.source.c_str(),
                info.backend.c_str(), info.snaplen,
                info.filter.empty() ? "" : ", filter: ", info.filter.c_str());
  }

  std::atomic<bool> capture_done{false};
  std::string capture_error;

  std::thread capture_thread([&] {
    auto sink = [&](const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                    const timeval& ts) {
      // Written before analysis so a crash in the decoder still leaves the
      // offending frame on disk to reproduce with.
      if (writer.is_open()) writer.write(data, caplen, wirelen, ts);
      analyzer.consume(data, caplen, wirelen, ts);
    };
    if (!capture->run(sink, g_running, opt.max_packets, capture_error)) {
      g_running.store(false, std::memory_order_relaxed);
    }
    capture_done.store(true, std::memory_order_relaxed);
    g_running.store(false, std::memory_order_relaxed);
  });

  if (use_tui) {
    // ~10 fps is smooth enough to read and cheap enough to be invisible in a
    // profile; the flow table is swept for idle entries once per second.
    int ticks = 0;
    while (g_running.load(std::memory_order_relaxed)) {
      switch (dashboard.poll_key()) {
        case netscope::DashboardKey::Quit:
          g_running.store(false, std::memory_order_relaxed);
          break;
        case netscope::DashboardKey::Pause:
          dashboard.toggle_pause();
          break;
        case netscope::DashboardKey::CycleSort:
          dashboard.cycle_sort();
          break;
        case netscope::DashboardKey::Reset:
          analyzer.reset();
          break;
        case netscope::DashboardKey::None:
          break;
      }
      if (!dashboard.paused()) {
        analyzer.update_capture_counters(capture->counters());
        dashboard.render(analyzer, info);
        if (++ticks % 10 == 0) analyzer.expire_idle_flows(opt.expire_sec);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // On a finished capture file, hold the last frame briefly so it is readable.
    if (capture_done.load(std::memory_order_relaxed) && info.offline) {
      dashboard.render(analyzer, info);
      std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }
  }

  capture_thread.join();
  dashboard.end();
  analyzer.update_capture_counters(capture->counters());
  capture->close();

  if (writer.is_open()) {
    std::printf("wrote %llu packets (%s) to %s\n",
                static_cast<unsigned long long>(writer.packets_written()),
                netscope::human_bytes(static_cast<double>(writer.bytes_written())).c_str(),
                writer.path().c_str());
    writer.close();
  }
  if (!capture_error.empty()) {
    std::fprintf(stderr, "capture error: %s\n", capture_error.c_str());
  }
  netscope::print_summary(analyzer, info);
  return capture_error.empty() ? 0 : 1;
}
