#include <pcap.h>

#include <cstring>

#include "capture.hpp"

namespace netscope {

namespace {

class PcapCapture final : public Capture {
 public:
  ~PcapCapture() override { close(); }

  bool open(const CaptureConfig& cfg, std::string& err) override {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    if (!cfg.pcap_file.empty()) {
      offline_ = true;
      handle_ = pcap_open_offline(cfg.pcap_file.c_str(), errbuf);
      if (handle_ == nullptr) {
        err = std::string("cannot open capture file: ") + errbuf;
        return false;
      }
    } else {
      // pcap_create/activate is used rather than pcap_open_live so immediate
      // mode can be requested: without it the kernel batches packets and the
      // live dashboard updates in bursts.
      handle_ = pcap_create(cfg.interface.c_str(), errbuf);
      if (handle_ == nullptr) {
        err = std::string("pcap_create failed: ") + errbuf;
        return false;
      }
      pcap_set_snaplen(handle_, cfg.snaplen);
      pcap_set_promisc(handle_, cfg.promiscuous ? 1 : 0);
      pcap_set_timeout(handle_, cfg.timeout_ms);
      pcap_set_immediate_mode(handle_, 1);
      pcap_set_buffer_size(handle_, 4 * 1024 * 1024);

      const int rc = pcap_activate(handle_);
      if (rc < 0) {
        err = std::string("cannot activate capture on '") + cfg.interface + "': " +
              pcap_geterr(handle_);
        if (rc == PCAP_ERROR_PERM_DENIED) {
          err += "\n  (capturing needs root or CAP_NET_RAW -- see README)";
        }
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
      }
      if (rc > 0) {
        // Warnings such as PCAP_WARNING_PROMISC_NOTSUP are not fatal.
        warning_ = pcap_geterr(handle_);
      }
    }

    linktype_ = pcap_datalink(handle_);

    if (!cfg.filter.empty()) {
      bpf_program program{};
      if (pcap_compile(handle_, &program, cfg.filter.c_str(), 1,
                       PCAP_NETMASK_UNKNOWN) < 0) {
        err = std::string("bad BPF filter: ") + pcap_geterr(handle_);
        close();
        return false;
      }
      if (pcap_setfilter(handle_, &program) < 0) {
        err = std::string("cannot install filter: ") + pcap_geterr(handle_);
        pcap_freecode(&program);
        close();
        return false;
      }
      pcap_freecode(&program);
    }
    return true;
  }

  void close() override {
    if (handle_ != nullptr) {
      refresh_counters();
      pcap_close(handle_);
      handle_ = nullptr;
    }
  }

  bool run(const PacketSink& sink, std::atomic<bool>& running,
           uint64_t max_packets, std::string& err) override {
    if (handle_ == nullptr) {
      err = "capture not open";
      return false;
    }
    uint64_t delivered = 0;

    while (running.load(std::memory_order_relaxed)) {
      pcap_pkthdr* header = nullptr;
      const uint8_t* data = nullptr;
      // pcap_next_ex is used instead of pcap_loop so the `running` flag is
      // checked on every timeout tick and Ctrl-C exits promptly.
      const int rc = pcap_next_ex(handle_, &header, &data);

      if (rc == 1) {
        sink(data, header->caplen, header->len, header->ts);
        if (++delivered % 256 == 0) refresh_counters();
        if (max_packets != 0 && delivered >= max_packets) break;
      } else if (rc == 0) {
        continue;  // live capture read timeout
      } else if (rc == PCAP_ERROR_BREAK) {
        break;     // end of a capture file
      } else {
        err = std::string("read error: ") + pcap_geterr(handle_);
        return false;
      }
    }
    refresh_counters();
    return true;
  }

  CaptureCounters counters() const override { return counters_; }
  int linktype() const override { return linktype_; }
  const char* backend_name() const override { return offline_ ? "pcap-file" : "libpcap"; }
  bool is_offline() const override { return offline_; }

 private:
  void refresh_counters() {
    if (handle_ == nullptr || offline_) return;
    pcap_stat ps{};
    if (pcap_stats(handle_, &ps) == 0) {
      counters_.received = ps.ps_recv;
      counters_.dropped = ps.ps_drop;
      counters_.if_dropped = ps.ps_ifdrop;
    }
  }

  pcap_t* handle_ = nullptr;
  int linktype_ = 1;
  bool offline_ = false;
  std::string warning_;
  CaptureCounters counters_{};
};

}  // namespace

std::unique_ptr<Capture> make_pcap_capture() {
  return std::make_unique<PcapCapture>();
}

std::vector<InterfaceInfo> list_interfaces(std::string& err) {
  std::vector<InterfaceInfo> out;
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_if_t* devices = nullptr;
  if (pcap_findalldevs(&devices, errbuf) != 0) {
    err = errbuf;
    return out;
  }
  for (pcap_if_t* d = devices; d != nullptr; d = d->next) {
    InterfaceInfo info;
    info.name = d->name ? d->name : "";
    info.description = d->description ? d->description : "";
    info.is_up = (d->flags & PCAP_IF_UP) != 0;
    info.is_loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
    for (pcap_addr_t* a = d->addresses; a != nullptr; a = a->next) {
      if (a->addr != nullptr && a->addr->sa_family == AF_INET) {
        char buf[INET_ADDRSTRLEN] = {0};
        auto* sin = reinterpret_cast<sockaddr_in*>(a->addr);
        inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
        info.address = buf;
        break;
      }
    }
    out.push_back(std::move(info));
  }
  pcap_freealldevs(devices);
  return out;
}

std::string pick_default_interface(std::string& err) {
  // Prefer the first non-loopback interface that is up and has an IPv4 address.
  // Pseudo-devices are skipped explicitly: libpcap lists things like "any",
  // "bluetooth-monitor" and macOS's "pktap"/"awdl" ahead of real NICs, and most
  // of them either cannot be opened or carry no useful traffic.
  static const char* kPseudoPrefixes[] = {"any", "nf", "usbmon", "bluetooth",
                                          "dbus", "nflog", "nfqueue", "pktap",
                                          "awdl", "llw", "utun", "gif", "stf",
                                          "ap", "vmnet", "bridge"};
  auto is_pseudo = [](const std::string& name) {
    for (const char* prefix : kPseudoPrefixes) {
      const size_t n = std::strlen(prefix);
      if (name.compare(0, n, prefix) == 0) return true;
    }
    return false;
  };

  auto ifaces = list_interfaces(err);
  const InterfaceInfo* fallback = nullptr;
  for (const auto& i : ifaces) {
    if (i.is_loopback || i.name.empty() || is_pseudo(i.name)) continue;
    if (i.is_up && !i.address.empty()) return i.name;
    if (fallback == nullptr) fallback = &i;
  }
  if (fallback != nullptr) return fallback->name;
  if (err.empty()) err = "no capture interface found";
  return {};
}

bool validate_bpf_filter(const std::string& filter, int linktype, std::string& err) {
  if (filter.empty()) return true;
  // pcap_open_dead builds a handle with no device attached, which is enough to
  // compile (and therefore syntax-check) a filter program.
  pcap_t* dead = pcap_open_dead(linktype, 65535);
  if (dead == nullptr) {
    err = "pcap_open_dead failed";
    return false;
  }
  bpf_program program{};
  bool ok = true;
  if (pcap_compile(dead, &program, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
    err = pcap_geterr(dead);
    ok = false;
  } else {
    pcap_freecode(&program);
  }
  pcap_close(dead);
  return ok;
}

}  // namespace netscope
