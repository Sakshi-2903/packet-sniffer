// AF_PACKET raw-socket capture backend. LINUX ONLY.
//
// AF_PACKET, SO_ATTACH_FILTER and <linux/filter.h> are Linux kernel interfaces
// with no portable equivalent. macOS and the BSDs expose raw capture through
// /dev/bpf instead, which is precisely what libpcap wraps -- so on those
// platforms the libpcap backend already *is* the raw-socket backend, and
// reimplementing it would duplicate libpcap rather than reveal anything.
// This file therefore compiles to a stub off Linux, and `-b raw` reports that
// clearly instead of failing to build.
//
// This is the layer libpcap sits on top of on Linux: a PF_PACKET/SOCK_RAW
// socket bound to one interface receives complete link-layer frames. A BPF
// program compiled by libpcap is attached to the socket with SO_ATTACH_FILTER,
// so filtering happens in the kernel and unwanted frames are never copied to
// user space.
#if defined(__linux__)

#include <arpa/inet.h>
#include <errno.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <pcap.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstring>
#include <vector>

#include "capture.hpp"
#include "parser.hpp"  // LinkType

// Recent glibc renamed the ioctl that fetches a packet's kernel timestamp.
#if !defined(SIOCGSTAMP) && defined(SIOCGSTAMP_OLD)
#define SIOCGSTAMP SIOCGSTAMP_OLD
#endif

namespace netscope {

namespace {

constexpr int kDltEthernet = 1;
constexpr int kDltRaw = 101;

class RawSocketCapture final : public Capture {
 public:
  ~RawSocketCapture() override { close(); }

  bool open(const CaptureConfig& cfg, std::string& err) override {
    if (!cfg.pcap_file.empty()) {
      err = "the raw-socket backend cannot replay capture files; use --backend pcap";
      return false;
    }
    if (cfg.interface.empty()) {
      err = "the raw-socket backend needs an explicit interface";
      return false;
    }

    // ETH_P_ALL asks for every protocol; the socket still only sees frames on
    // the interface it is bound to.
    fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd_ < 0) {
      err = std::string("socket(AF_PACKET) failed: ") + std::strerror(errno);
      if (errno == EPERM) err += " (needs root or CAP_NET_RAW)";
      return false;
    }

    ifindex_ = static_cast<int>(if_nametoindex(cfg.interface.c_str()));
    if (ifindex_ == 0) {
      err = std::string("unknown interface '") + cfg.interface + "'";
      close();
      return false;
    }

    if (!detect_linktype(cfg.interface, err)) {
      close();
      return false;
    }

    // Attaching the filter before bind() closes the window where unfiltered
    // frames could already be queued on the socket.
    if (!cfg.filter.empty() && !attach_filter(cfg.filter, err)) {
      close();
      return false;
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifindex_;
    if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
      err = std::string("bind to interface failed: ") + std::strerror(errno);
      close();
      return false;
    }

    if (cfg.promiscuous && !enable_promisc(err)) {
      close();
      return false;
    }

    // A larger socket receive buffer reduces kernel drops during bursts.
    int rcvbuf = 4 * 1024 * 1024;
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    snaplen_ = cfg.snaplen > 0 ? static_cast<uint32_t>(cfg.snaplen) : 65536;
    buffer_.resize(snaplen_ < 65536 ? 65536 : snaplen_);
    timeout_ms_ = cfg.timeout_ms;
    return true;
  }

  void close() override {
    if (fd_ >= 0) {
      refresh_counters();
      if (promisc_on_) {
        packet_mreq mreq{};
        mreq.mr_ifindex = ifindex_;
        mreq.mr_type = PACKET_MR_PROMISC;
        ::setsockopt(fd_, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
        promisc_on_ = false;
      }
      ::close(fd_);
      fd_ = -1;
    }
  }

  bool run(const PacketSink& sink, std::atomic<bool>& running,
           uint64_t max_packets, std::string& err) override {
    if (fd_ < 0) {
      err = "capture not open";
      return false;
    }
    uint64_t delivered = 0;

    while (running.load(std::memory_order_relaxed)) {
      pollfd pfd{fd_, POLLIN, 0};
      const int ready = ::poll(&pfd, 1, timeout_ms_);
      if (ready < 0) {
        if (errno == EINTR) continue;
        err = std::string("poll failed: ") + std::strerror(errno);
        return false;
      }
      if (ready == 0) continue;  // timeout: loop back and re-check `running`

      sockaddr_ll from{};
      socklen_t fromlen = sizeof(from);
      const ssize_t n = ::recvfrom(fd_, buffer_.data(), buffer_.size(), 0,
                                   reinterpret_cast<sockaddr*>(&from), &fromlen);
      if (n < 0) {
        if (errno == EINTR || errno == EAGAIN) continue;
        err = std::string("recvfrom failed: ") + std::strerror(errno);
        return false;
      }

      // PACKET_OUTGOING frames are our own transmissions looped back; libpcap
      // reports them too, so they are kept for symmetry between backends.
      const uint32_t wirelen = static_cast<uint32_t>(n);
      const uint32_t caplen = wirelen < snaplen_ ? wirelen : snaplen_;

      timeval ts{};
      // SIOCGSTAMP gives the kernel's receive timestamp for the last packet,
      // which is closer to the true arrival time than a userspace clock read.
      if (::ioctl(fd_, SIOCGSTAMP, &ts) < 0) {
        gettimeofday(&ts, nullptr);
      }

      ++software_received_;
      sink(buffer_.data(), caplen, wirelen, ts);
      if (++delivered % 256 == 0) refresh_counters();
      if (max_packets != 0 && delivered >= max_packets) break;
    }
    refresh_counters();
    return true;
  }

  CaptureCounters counters() const override { return counters_; }
  int linktype() const override { return linktype_; }
  const char* backend_name() const override { return "AF_PACKET"; }

 private:
  // Uses libpcap only as a BPF compiler: pcap_open_dead needs no device, and the
  // resulting instructions are handed straight to the kernel. bpf_insn and
  // sock_filter have identical layouts, which is what makes this work.
  bool attach_filter(const std::string& filter, std::string& err) {
    pcap_t* dead = pcap_open_dead(linktype_, static_cast<int>(snaplen_ ? snaplen_ : 65535));
    if (dead == nullptr) {
      err = "pcap_open_dead failed";
      return false;
    }
    bpf_program program{};
    if (pcap_compile(dead, &program, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
      err = std::string("bad BPF filter: ") + pcap_geterr(dead);
      pcap_close(dead);
      return false;
    }

    sock_fprog fprog{};
    fprog.len = static_cast<unsigned short>(program.bf_len);
    fprog.filter = reinterpret_cast<sock_filter*>(program.bf_insns);

    const bool ok = ::setsockopt(fd_, SOL_SOCKET, SO_ATTACH_FILTER, &fprog,
                                 sizeof(fprog)) == 0;
    if (!ok) err = std::string("SO_ATTACH_FILTER failed: ") + std::strerror(errno);

    pcap_freecode(&program);
    pcap_close(dead);
    return ok;
  }

  bool enable_promisc(std::string& err) {
    packet_mreq mreq{};
    mreq.mr_ifindex = ifindex_;
    mreq.mr_type = PACKET_MR_PROMISC;
    if (::setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
      err = std::string("cannot enable promiscuous mode: ") + std::strerror(errno);
      return false;
    }
    promisc_on_ = true;
    return true;
  }

  bool detect_linktype(const std::string& iface, std::string& err) {
    ifreq ifr{};
    std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd_, SIOCGIFHWADDR, &ifr) < 0) {
      err = std::string("SIOCGIFHWADDR failed: ") + std::strerror(errno);
      return false;
    }
    switch (ifr.ifr_hwaddr.sa_family) {
      case ARPHRD_ETHER:
      case ARPHRD_LOOPBACK:
        linktype_ = kDltEthernet;
        return true;
      case ARPHRD_NONE:
        linktype_ = kDltRaw;  // tun devices carry bare IP packets
        return true;
      default:
        // Anything else is decoded as Ethernet; unknown framing shows up as
        // decode errors rather than crashing.
        linktype_ = kDltEthernet;
        return true;
    }
  }

  void refresh_counters() {
    if (fd_ < 0) return;
    tpacket_stats stats{};
    socklen_t len = sizeof(stats);
    // PACKET_STATISTICS is read-and-reset, so the values accumulate here.
    if (::getsockopt(fd_, SOL_PACKET, PACKET_STATISTICS, &stats, &len) == 0) {
      kernel_seen_ += stats.tp_packets;
      kernel_dropped_ += stats.tp_drops;
    }
    counters_.received = kernel_seen_ ? kernel_seen_ : software_received_;
    counters_.dropped = kernel_dropped_;
    counters_.if_dropped = 0;  // not exposed by AF_PACKET
  }

  int fd_ = -1;
  int ifindex_ = 0;
  int linktype_ = kDltEthernet;
  int timeout_ms_ = 200;
  uint32_t snaplen_ = 65536;
  bool promisc_on_ = false;
  std::vector<uint8_t> buffer_;
  uint64_t software_received_ = 0;
  uint64_t kernel_seen_ = 0;
  uint64_t kernel_dropped_ = 0;
  CaptureCounters counters_{};
};

}  // namespace

std::unique_ptr<Capture> make_raw_socket_capture() {
  return std::make_unique<RawSocketCapture>();
}

}  // namespace netscope

#else  // !__linux__

#include "capture.hpp"

namespace netscope {
namespace {

// Stub so the CLI keeps one code path on every platform: the backend exists but
// declines to open, with an explanation rather than a link error.
class UnsupportedRawCapture final : public Capture {
 public:
  bool open(const CaptureConfig&, std::string& err) override {
    err = "the raw-socket backend needs Linux (AF_PACKET); "
          "this platform captures through libpcap -- use --backend pcap";
    return false;
  }
  void close() override {}
  bool run(const PacketSink&, std::atomic<bool>&, uint64_t, std::string& err) override {
    err = "raw-socket backend unavailable on this platform";
    return false;
  }
  CaptureCounters counters() const override { return {}; }
  int linktype() const override { return 1; }
  const char* backend_name() const override { return "AF_PACKET (unavailable)"; }
};

}  // namespace

std::unique_ptr<Capture> make_raw_socket_capture() {
  return std::make_unique<UnsupportedRawCapture>();
}

}  // namespace netscope

#endif  // __linux__
