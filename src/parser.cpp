#include "parser.hpp"

#include <cstdio>
#include <sstream>

namespace netscope {

const char* to_string(L3Proto p) {
  switch (p) {
    case L3Proto::IPv4: return "IPv4";
    case L3Proto::IPv6: return "IPv6";
    case L3Proto::ARP:  return "ARP";
    default:            return "?";
  }
}

const char* to_string(L4Proto p) {
  switch (p) {
    case L4Proto::TCP:    return "TCP";
    case L4Proto::UDP:    return "UDP";
    case L4Proto::ICMP:   return "ICMP";
    case L4Proto::ICMPv6: return "ICMPv6";
    case L4Proto::Other:  return "OTHER";
    default:              return "?";
  }
}

IpAddress IpAddress::from_v4(uint32_t net_order) {
  IpAddress a;
  a.is_v6 = false;
  std::memcpy(a.bytes.data(), &net_order, 4);
  return a;
}

IpAddress IpAddress::from_v6(const uint8_t raw[16]) {
  IpAddress a;
  a.is_v6 = true;
  std::memcpy(a.bytes.data(), raw, 16);
  return a;
}

std::string IpAddress::str() const {
  char buf[INET6_ADDRSTRLEN] = {0};
  if (is_v6) {
    inet_ntop(AF_INET6, bytes.data(), buf, sizeof(buf));
  } else {
    inet_ntop(AF_INET, bytes.data(), buf, sizeof(buf));
  }
  return std::string(buf);
}

std::string DecodedPacket::tcp_flag_string() const {
  if (l4 != L4Proto::TCP) return "";
  std::string s;
  if (tcp_flags & TH_SYN) s += 'S';
  if (tcp_flags & TH_ACK) s += 'A';
  if (tcp_flags & TH_PSH) s += 'P';
  if (tcp_flags & TH_FIN) s += 'F';
  if (tcp_flags & TH_RST) s += 'R';
  if (tcp_flags & TH_URG) s += 'U';
  if (tcp_flags & TH_ECE) s += 'E';
  if (tcp_flags & TH_CWR) s += 'C';
  return s.empty() ? "." : s;
}

uint16_t internet_checksum(const uint8_t* data, size_t len) {
  uint32_t sum = 0;
  while (len > 1) {
    sum += static_cast<uint32_t>((data[0] << 8) | data[1]);
    data += 2;
    len -= 2;
  }
  if (len == 1) sum += static_cast<uint32_t>(data[0] << 8);
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

const char* service_name(uint16_t port, L4Proto proto) {
  if (proto == L4Proto::TCP) {
    switch (port) {
      case 20: case 21: return "ftp";
      case 22: return "ssh";
      case 23: return "telnet";
      case 25: return "smtp";
      case 80: return "http";
      case 110: return "pop3";
      case 143: return "imap";
      case 443: return "https";
      case 445: return "smb";
      case 587: return "submission";
      case 993: return "imaps";
      case 3306: return "mysql";
      case 5432: return "postgres";
      case 6379: return "redis";
      case 8080: return "http-alt";
      case 8443: return "https-alt";
      case 27017: return "mongo";
      default: break;
    }
  } else if (proto == L4Proto::UDP) {
    switch (port) {
      case 53: return "dns";
      case 67: case 68: return "dhcp";
      case 123: return "ntp";
      case 161: return "snmp";
      case 443: return "quic";
      case 500: return "isakmp";
      case 1900: return "ssdp";
      case 5353: return "mdns";
      default: break;
    }
  }
  return nullptr;
}

namespace {

// Cursor over the capture buffer that refuses to hand out more bytes than were
// actually captured. Every header read goes through take(), so a malformed or
// snaplen-truncated frame can never walk off the end of the buffer.
struct Cursor {
  const uint8_t* p;
  uint32_t left;

  const uint8_t* take(uint32_t n) {
    if (left < n) return nullptr;
    const uint8_t* r = p;
    p += n;
    left -= n;
    return r;
  }
  bool skip(uint32_t n) { return take(n) != nullptr; }
};

// Walks past IPv6 extension headers to find the real upper-layer protocol.
uint8_t resolve_ipv6_next(Cursor& cur, uint8_t next, bool& fragmented,
                          bool& first_fragment, bool& truncated) {
  for (int hops = 0; hops < 8; ++hops) {
    switch (next) {
      case IPPROTO_HOPOPTS_:
      case IPPROTO_IPV6_ROUTE_:
      case IPPROTO_DSTOPTS_: {
        const uint8_t* h = cur.take(2);
        if (!h) { truncated = true; return IPPROTO_NONXT_; }
        next = h[0];
        // Length is in 8-octet units, not counting the first 8 octets.
        uint32_t ext_len = static_cast<uint32_t>(h[1]) * 8 + 6;
        if (!cur.skip(ext_len)) { truncated = true; return IPPROTO_NONXT_; }
        break;
      }
      case IPPROTO_IPV6_FRAG_: {
        const uint8_t* h = cur.take(8);
        if (!h) { truncated = true; return IPPROTO_NONXT_; }
        fragmented = true;
        uint16_t off = static_cast<uint16_t>(((h[2] << 8) | h[3]) & 0xFFF8);
        first_fragment = (off == 0);
        next = h[0];
        break;
      }
      default:
        return next;
    }
  }
  return IPPROTO_NONXT_;
}

bool decode_l4(Cursor& cur, DecodedPacket& out) {
  switch (out.ip_proto) {
    case IPPROTO_TCP_: {
      out.l4 = L4Proto::TCP;
      const uint8_t* raw = cur.take(sizeof(TcpHeader));
      if (!raw) { out.truncated = true; return true; }
      const auto* tcp = reinterpret_cast<const TcpHeader*>(raw);
      out.sport = ntohs(tcp->sport);
      out.dport = ntohs(tcp->dport);
      out.seq = ntohl(tcp->seq);
      out.ack = ntohl(tcp->ack);
      out.window = ntohs(tcp->window);
      out.tcp_flags = tcp->flags;

      uint8_t hlen = tcp->header_len();
      if (hlen < sizeof(TcpHeader)) { out.error = "bad TCP data offset"; return true; }
      // Skip options (SACK, timestamps, MSS, window scale...).
      if (!cur.skip(hlen - sizeof(TcpHeader))) { out.truncated = true; return true; }
      out.payload = cur.p;
      out.payload_len = cur.left;
      return true;
    }
    case IPPROTO_UDP_: {
      out.l4 = L4Proto::UDP;
      const uint8_t* raw = cur.take(sizeof(UdpHeader));
      if (!raw) { out.truncated = true; return true; }
      const auto* udp = reinterpret_cast<const UdpHeader*>(raw);
      out.sport = ntohs(udp->sport);
      out.dport = ntohs(udp->dport);
      out.payload = cur.p;
      uint16_t dlen = ntohs(udp->len);
      uint32_t declared = dlen >= sizeof(UdpHeader) ? dlen - sizeof(UdpHeader) : 0;
      out.payload_len = declared < cur.left ? declared : cur.left;
      return true;
    }
    case IPPROTO_ICMP_:
    case IPPROTO_ICMPV6_: {
      out.l4 = (out.ip_proto == IPPROTO_ICMP_) ? L4Proto::ICMP : L4Proto::ICMPv6;
      const uint8_t* raw = cur.take(4);  // type/code/checksum are always present
      if (!raw) { out.truncated = true; return true; }
      out.icmp_type = raw[0];
      out.icmp_code = raw[1];
      out.payload = cur.p;
      out.payload_len = cur.left;
      return true;
    }
    default:
      out.l4 = L4Proto::Other;
      out.payload = cur.p;
      out.payload_len = cur.left;
      return true;
  }
}

bool decode_l3(Cursor& cur, uint16_t ethertype, DecodedPacket& out) {
  if (ethertype == ETHERTYPE_ARP) {
    out.l3 = L3Proto::ARP;
    out.l4 = L4Proto::Unknown;
    return true;
  }
  if (ethertype == ETHERTYPE_IPV4) {
    const uint8_t* raw = cur.take(sizeof(Ipv4Header));
    if (!raw) { out.error = "truncated IPv4 header"; return false; }
    const auto* ip = reinterpret_cast<const Ipv4Header*>(raw);
    if (ip->version() != 4) { out.error = "IPv4 version mismatch"; return false; }
    uint8_t hlen = ip->header_len();
    if (hlen < sizeof(Ipv4Header)) { out.error = "bad IPv4 IHL"; return false; }

    out.l3 = L3Proto::IPv4;
    out.src_ip = IpAddress::from_v4(ip->src);
    out.dst_ip = IpAddress::from_v4(ip->dst);
    out.ttl = ip->ttl;
    out.ip_proto = ip->proto;
    out.ip_id = ntohs(ip->id);
    out.dscp = ip->dscp();
    out.fragmented = ip->more_fragments() || ip->frag_offset() > 0;
    out.first_fragment = (ip->frag_offset() == 0);

    // The header checksum covers the header only, so it can be verified even on
    // a heavily truncated capture.
    if (cur.left + sizeof(Ipv4Header) >= hlen) {
      out.bad_ip_checksum = internet_checksum(raw, hlen) != 0;
    }

    if (!cur.skip(hlen - sizeof(Ipv4Header))) { out.truncated = true; return true; }
    // A non-initial fragment has no transport header to read.
    if (!out.first_fragment) {
      out.l4 = L4Proto::Other;
      out.payload = cur.p;
      out.payload_len = cur.left;
      return true;
    }
    return decode_l4(cur, out);
  }
  if (ethertype == ETHERTYPE_IPV6) {
    const uint8_t* raw = cur.take(sizeof(Ipv6Header));
    if (!raw) { out.error = "truncated IPv6 header"; return false; }
    const auto* ip6 = reinterpret_cast<const Ipv6Header*>(raw);
    if (ip6->version() != 6) { out.error = "IPv6 version mismatch"; return false; }

    out.l3 = L3Proto::IPv6;
    out.src_ip = IpAddress::from_v6(ip6->src);
    out.dst_ip = IpAddress::from_v6(ip6->dst);
    out.ttl = ip6->hop_limit;

    uint8_t next = resolve_ipv6_next(cur, ip6->next_header, out.fragmented,
                                    out.first_fragment, out.truncated);
    out.ip_proto = next;
    if (out.truncated) return true;
    if (!out.first_fragment) {
      out.l4 = L4Proto::Other;
      return true;
    }
    return decode_l4(cur, out);
  }

  out.l3 = L3Proto::Unknown;
  out.error = "unsupported ethertype";
  return false;
}

}  // namespace

bool decode_packet(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                   const timeval& ts, int linktype, DecodedPacket& out) {
  out = DecodedPacket{};
  out.ts = ts;
  out.caplen = caplen;
  out.wirelen = wirelen;
  if (data == nullptr || caplen == 0) {
    out.error = "empty frame";
    return false;
  }

  Cursor cur{data, caplen};
  uint16_t ethertype = 0;

  switch (static_cast<LinkType>(linktype)) {
    case LinkType::Ethernet: {
      const uint8_t* raw = cur.take(sizeof(EthernetHeader));
      if (!raw) { out.error = "truncated Ethernet header"; return false; }
      const auto* eth = reinterpret_cast<const EthernetHeader*>(raw);
      out.has_l2 = true;
      std::memcpy(out.dst_mac, eth->dst, 6);
      std::memcpy(out.src_mac, eth->src, 6);
      ethertype = ntohs(eth->ethertype);

      // Unwrap up to two levels of VLAN tagging (Q-in-Q).
      for (int i = 0; i < 2 && (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ); ++i) {
        const uint8_t* vraw = cur.take(sizeof(VlanTag));
        if (!vraw) { out.error = "truncated VLAN tag"; return false; }
        const auto* vlan = reinterpret_cast<const VlanTag*>(vraw);
        out.has_vlan = true;
        out.vlan_id = static_cast<uint16_t>(ntohs(vlan->tci) & 0x0FFF);
        ethertype = ntohs(vlan->inner_ethertype);
      }
      out.ethertype = ethertype;
      break;
    }
    case LinkType::LinuxSll: {
      // 16-byte cooked header; the protocol field sits in the last 2 bytes.
      const uint8_t* raw = cur.take(16);
      if (!raw) { out.error = "truncated SLL header"; return false; }
      ethertype = static_cast<uint16_t>((raw[14] << 8) | raw[15]);
      out.ethertype = ethertype;
      break;
    }
    case LinkType::LinuxSll2: {
      const uint8_t* raw = cur.take(20);
      if (!raw) { out.error = "truncated SLL2 header"; return false; }
      ethertype = static_cast<uint16_t>((raw[0] << 8) | raw[1]);
      out.ethertype = ethertype;
      break;
    }
    case LinkType::Null: {
      const uint8_t* raw = cur.take(4);
      if (!raw) { out.error = "truncated loopback header"; return false; }
      uint32_t family = *reinterpret_cast<const uint32_t*>(raw);  // host order
      ethertype = (family == 2) ? ETHERTYPE_IPV4 : ETHERTYPE_IPV6;
      out.ethertype = ethertype;
      break;
    }
    case LinkType::Raw: {
      if (cur.left < 1) { out.error = "empty raw frame"; return false; }
      ethertype = ((cur.p[0] >> 4) == 6) ? ETHERTYPE_IPV6 : ETHERTYPE_IPV4;
      out.ethertype = ethertype;
      break;
    }
    default:
      out.error = "unsupported link type";
      return false;
  }

  return decode_l3(cur, ethertype, out);
}

std::string format_packet_line(const DecodedPacket& p) {
  char tbuf[32];
  struct tm tm_local{};
  time_t secs = p.ts.tv_sec;
  localtime_r(&secs, &tm_local);
  std::snprintf(tbuf, sizeof(tbuf), "%02d:%02d:%02d.%06ld", tm_local.tm_hour,
                tm_local.tm_min, tm_local.tm_sec, static_cast<long>(p.ts.tv_usec));

  std::ostringstream os;
  os << tbuf << ' ';

  if (p.error) {
    os << "[undecoded: " << p.error << "] " << p.wirelen << "B";
    return os.str();
  }
  if (p.l3 == L3Proto::ARP) {
    os << "ARP " << p.wirelen << "B";
    return os.str();
  }

  os << to_string(p.l4) << ' ' << p.src_ip.str();
  if (p.has_ports()) os << ':' << p.sport;
  os << " > " << p.dst_ip.str();
  if (p.has_ports()) os << ':' << p.dport;

  if (p.l4 == L4Proto::TCP) {
    os << " [" << p.tcp_flag_string() << "] seq=" << p.seq << " win=" << p.window;
  } else if (p.l4 == L4Proto::ICMP || p.l4 == L4Proto::ICMPv6) {
    os << " type=" << static_cast<int>(p.icmp_type)
       << " code=" << static_cast<int>(p.icmp_code);
  }

  os << " len=" << p.payload_len << " ttl=" << static_cast<int>(p.ttl);
  if (p.has_vlan) os << " vlan=" << p.vlan_id;
  if (p.fragmented) os << " [frag]";
  if (p.bad_ip_checksum) os << " [bad-cksum]";
  if (p.truncated) os << " [trunc]";
  return os.str();
}

}  // namespace netscope
