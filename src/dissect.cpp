#include "dissect.hpp"

#include <algorithm>
#include <cstring>

namespace netscope {

const char* to_string(AppProtocol p) {
  switch (p) {
    case AppProtocol::HTTP: return "HTTP";
    case AppProtocol::TLS:  return "TLS";
    case AppProtocol::DNS:  return "DNS";
    case AppProtocol::SSH:  return "SSH";
    case AppProtocol::DHCP: return "DHCP";
    case AppProtocol::NTP:  return "NTP";
    case AppProtocol::Other: return "other";
    default: return "-";
  }
}

namespace {

// Reads big-endian integers out of a buffer while refusing to read past its end.
// Application headers are attacker-controlled data, so every field width and
// offset in them has to be treated as untrusted.
struct ByteReader {
  const uint8_t* p;
  size_t left;

  bool u8(uint8_t& v) {
    if (left < 1) return false;
    v = *p++;
    --left;
    return true;
  }
  bool u16(uint16_t& v) {
    if (left < 2) return false;
    v = static_cast<uint16_t>((p[0] << 8) | p[1]);
    p += 2;
    left -= 2;
    return true;
  }
  bool skip(size_t n) {
    if (left < n) return false;
    p += n;
    left -= n;
    return true;
  }
  bool read(std::string& out, size_t n) {
    if (left < n) return false;
    out.assign(reinterpret_cast<const char*>(p), n);
    p += n;
    left -= n;
    return true;
  }
};

std::string tls_version_name(uint16_t version) {
  switch (version) {
    case 0x0300: return "SSL3.0";
    case 0x0301: return "TLS1.0";
    case 0x0302: return "TLS1.1";
    case 0x0303: return "TLS1.2";
    case 0x0304: return "TLS1.3";
    default:     return "TLS?";
  }
}

const char* dns_type_name(uint16_t type) {
  switch (type) {
    case 1: return "A";
    case 2: return "NS";
    case 5: return "CNAME";
    case 6: return "SOA";
    case 12: return "PTR";
    case 15: return "MX";
    case 16: return "TXT";
    case 28: return "AAAA";
    case 33: return "SRV";
    case 65: return "HTTPS";
    default: return "?";
  }
}

const char* dns_rcode_name(uint8_t rcode) {
  switch (rcode) {
    case 0: return "NOERROR";
    case 1: return "FORMERR";
    case 2: return "SERVFAIL";
    case 3: return "NXDOMAIN";
    case 4: return "NOTIMP";
    case 5: return "REFUSED";
    default: return "RCODE?";
  }
}

bool starts_with(const std::string& s, const char* prefix) {
  const size_t n = std::strlen(prefix);
  return s.size() >= n && s.compare(0, n, prefix) == 0;
}

// Case-insensitive search for an HTTP header, returning its trimmed value.
bool find_header(const std::string& headers, const char* name, std::string& value) {
  const size_t name_len = std::strlen(name);
  size_t pos = 0;
  while (pos < headers.size()) {
    const size_t eol = headers.find("\r\n", pos);
    const size_t line_end = (eol == std::string::npos) ? headers.size() : eol;
    if (line_end - pos > name_len &&
        strncasecmp(headers.data() + pos, name, name_len) == 0 &&
        headers[pos + name_len] == ':') {
      size_t v = pos + name_len + 1;
      while (v < line_end && (headers[v] == ' ' || headers[v] == '\t')) ++v;
      value.assign(headers, v, line_end - v);
      return !value.empty();
    }
    if (eol == std::string::npos) break;
    pos = eol + 2;
  }
  return false;
}

// Keeps a summary line printable and bounded: control characters from a hostile
// stream must never reach the terminal, where escape sequences would be executed.
std::string sanitize(const std::string& in, size_t max_len = 72) {
  std::string out;
  out.reserve(std::min(in.size(), max_len));
  for (char c : in) {
    if (out.size() >= max_len) {
      out += "..";
      break;
    }
    const unsigned char u = static_cast<unsigned char>(c);
    out += (u >= 0x20 && u < 0x7F) ? c : '.';
  }
  return out;
}

}  // namespace

// --------------------------------------------------------------------- HTTP

bool dissect_http(const std::string& data, AppInfo& out) {
  static const char* kMethods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                                   "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};
  const bool is_response = starts_with(data, "HTTP/1.");
  bool is_request = false;
  for (const char* m : kMethods) {
    if (starts_with(data, m)) {
      is_request = true;
      break;
    }
  }
  if (!is_request && !is_response) return false;

  const size_t line_end = data.find("\r\n");
  if (line_end == std::string::npos) {
    // Headers are still arriving; identify the protocol but keep looking.
    out.proto = AppProtocol::HTTP;
    out.summary = "HTTP";
    out.conclusive = false;
    return true;
  }
  const std::string first_line = data.substr(0, line_end);

  out.proto = AppProtocol::HTTP;
  if (is_response) {
    out.summary = sanitize(first_line);
    out.conclusive = true;
    return true;
  }

  // Request: "METHOD path HTTP/1.1". Combining the Host header with the path
  // gives the effective URL, which is what is actually useful in a flow list.
  const size_t sp1 = first_line.find(' ');
  const size_t sp2 = (sp1 == std::string::npos) ? std::string::npos
                                                : first_line.find(' ', sp1 + 1);
  const std::string method = (sp1 == std::string::npos) ? first_line
                                                        : first_line.substr(0, sp1);
  std::string path = "/";
  if (sp1 != std::string::npos) {
    path = first_line.substr(sp1 + 1, (sp2 == std::string::npos)
                                          ? std::string::npos
                                          : sp2 - sp1 - 1);
  }

  std::string host;
  const bool headers_complete = data.find("\r\n\r\n") != std::string::npos;
  find_header(data.substr(line_end + 2), "Host", host);

  out.summary = sanitize(method + " " + host + path);
  out.conclusive = headers_complete || !host.empty();
  return true;
}

// ---------------------------------------------------------------------- TLS

bool dissect_tls(const std::string& data, AppInfo& out) {
  ByteReader r{reinterpret_cast<const uint8_t*>(data.data()), data.size()};

  uint8_t content_type = 0;
  uint16_t record_version = 0, record_len = 0;
  if (!r.u8(content_type) || !r.u16(record_version) || !r.u16(record_len)) return false;
  if (content_type != 0x16) return false;  // 0x16 = handshake
  if ((record_version >> 8) != 0x03) return false;  // all TLS/SSL3 versions

  uint8_t handshake_type = 0;
  if (!r.u8(handshake_type)) return false;
  if (handshake_type != 0x01 && handshake_type != 0x02) {
    // A handshake record that is not a Hello: identified, but nothing to name.
    out.proto = AppProtocol::TLS;
    out.summary = tls_version_name(record_version);
    out.conclusive = false;
    return true;
  }

  uint8_t len_hi = 0;
  uint16_t len_lo = 0;
  if (!r.u8(len_hi) || !r.u16(len_lo)) return false;  // 24-bit handshake length

  uint16_t hello_version = 0;
  if (!r.u16(hello_version)) return false;
  if (!r.skip(32)) return false;  // random

  uint8_t session_id_len = 0;
  if (!r.u8(session_id_len) || !r.skip(session_id_len)) return false;

  const bool is_client_hello = (handshake_type == 0x01);
  if (is_client_hello) {
    uint16_t cipher_suites_len = 0;
    if (!r.u16(cipher_suites_len) || !r.skip(cipher_suites_len)) return false;
    uint8_t compression_len = 0;
    if (!r.u8(compression_len) || !r.skip(compression_len)) return false;
  } else {
    if (!r.skip(2)) return false;  // chosen cipher suite
    if (!r.skip(1)) return false;  // chosen compression
  }

  out.proto = AppProtocol::TLS;
  out.summary = tls_version_name(hello_version);

  uint16_t extensions_len = 0;
  if (!r.u16(extensions_len)) {
    out.conclusive = false;  // no extensions block captured yet
    return true;
  }

  std::string sni;
  uint16_t supported_max = 0;
  size_t remaining = std::min<size_t>(extensions_len, r.left);
  while (remaining >= 4) {
    uint16_t ext_type = 0, ext_len = 0;
    if (!r.u16(ext_type) || !r.u16(ext_len)) break;
    remaining -= 4;
    if (ext_len > remaining) break;
    remaining -= ext_len;

    if (ext_type == 0x0000 && sni.empty()) {
      // server_name: list length, then (type, length, name) entries.
      ByteReader sub{r.p, ext_len};
      uint16_t list_len = 0;
      uint8_t name_type = 0;
      uint16_t name_len = 0;
      if (sub.u16(list_len) && sub.u8(name_type) && sub.u16(name_len) &&
          name_type == 0x00) {
        sub.read(sni, name_len);
      }
    } else if (ext_type == 0x002B) {
      // supported_versions: TLS 1.3 advertises its real version here, because
      // the legacy version field has to stay 0x0303 for middlebox compatibility.
      ByteReader sub{r.p, ext_len};
      uint8_t list_len = 0;
      if (sub.u8(list_len)) {
        for (int i = 0; i < list_len / 2; ++i) {
          uint16_t v = 0;
          if (!sub.u16(v)) break;
          if (v > supported_max && v <= 0x0304) supported_max = v;
        }
      }
    }
    if (!r.skip(ext_len)) break;
  }

  if (supported_max != 0) out.summary = tls_version_name(supported_max);
  if (!sni.empty()) {
    out.summary += " sni=" + sanitize(sni, 48);
    out.conclusive = true;
  } else {
    out.summary += is_client_hello ? " client-hello" : " server-hello";
    out.conclusive = !is_client_hello;
  }
  return true;
}

// ---------------------------------------------------------------------- SSH

bool dissect_ssh(const std::string& data, AppInfo& out) {
  if (!starts_with(data, "SSH-")) return false;
  const size_t eol = data.find_first_of("\r\n");
  out.proto = AppProtocol::SSH;
  out.summary = sanitize(data.substr(0, eol == std::string::npos ? data.size() : eol), 48);
  out.conclusive = (eol != std::string::npos);
  return true;
}

// ---------------------------------------------------------------------- DNS

bool decode_dns_name(const uint8_t* msg, size_t msg_len, size_t offset,
                     std::string& name, size_t& consumed) {
  name.clear();
  consumed = 0;
  size_t pos = offset;
  bool followed_pointer = false;
  int jumps = 0;

  while (pos < msg_len) {
    const uint8_t len = msg[pos];

    if ((len & 0xC0) == 0xC0) {
      // Compression pointer: a 14-bit offset to a name earlier in the message.
      if (pos + 1 >= msg_len) return false;
      const size_t target = static_cast<size_t>(((len & 0x3F) << 8) | msg[pos + 1]);
      if (!followed_pointer) consumed = pos + 2 - offset;
      followed_pointer = true;
      if (target >= msg_len || ++jumps > 8) return false;  // guard against loops
      pos = target;
      continue;
    }
    if ((len & 0xC0) != 0) return false;  // reserved label type

    if (len == 0) {
      if (!followed_pointer) consumed = pos + 1 - offset;
      if (name.empty()) name = ".";
      return true;
    }
    if (pos + 1 + len > msg_len) return false;
    if (!name.empty()) name += '.';
    name.append(reinterpret_cast<const char*>(msg + pos + 1), len);
    if (name.size() > 253) return false;  // maximum legal DNS name length
    pos += 1 + len;
  }
  return false;
}

bool dissect_dns(const uint8_t* data, size_t len, AppInfo& out) {
  if (data == nullptr || len < 12) return false;

  const uint16_t flags = static_cast<uint16_t>((data[2] << 8) | data[3]);
  const uint16_t qdcount = static_cast<uint16_t>((data[4] << 8) | data[5]);
  const uint16_t ancount = static_cast<uint16_t>((data[6] << 8) | data[7]);
  const bool is_response = (flags & 0x8000) != 0;
  const uint8_t opcode = static_cast<uint8_t>((flags >> 11) & 0x0F);
  const uint8_t rcode = static_cast<uint8_t>(flags & 0x0F);

  if (opcode > 5 || qdcount == 0 || qdcount > 16) return false;

  std::string qname;
  size_t consumed = 0;
  if (!decode_dns_name(data, len, 12, qname, consumed)) return false;

  uint16_t qtype = 0;
  const size_t type_at = 12 + consumed;
  if (type_at + 2 <= len) qtype = static_cast<uint16_t>((data[type_at] << 8) | data[type_at + 1]);

  out.proto = AppProtocol::DNS;
  out.summary = std::string(is_response ? "response " : "query ") +
                dns_type_name(qtype) + " " + sanitize(qname, 48);
  if (is_response) {
    out.summary += " -> " + std::string(dns_rcode_name(rcode)) + " (" +
                   std::to_string(ancount) + " ans)";
  }
  out.conclusive = true;
  return true;
}

// ------------------------------------------------------------- entry points

bool dissect_tcp_stream(const std::string& prefix, uint16_t sport, uint16_t dport,
                        AppInfo& out) {
  if (prefix.size() < 4) return false;

  // The port only chooses the order of attempts; every dissector still validates
  // its own magic bytes, so a protocol on an unexpected port is still found.
  const uint16_t service = std::min(sport, dport);
  const bool tls_first = (service == 443 || service == 8443 || service == 993 ||
                          service == 995 || service == 465);

  if (tls_first && dissect_tls(prefix, out)) return true;
  if (dissect_http(prefix, out)) return true;
  if (!tls_first && dissect_tls(prefix, out)) return true;
  if (dissect_ssh(prefix, out)) return true;

  // DNS over TCP is length-prefixed with a two-byte count.
  if (service == 53 && prefix.size() > 2) {
    const size_t declared = static_cast<size_t>((static_cast<uint8_t>(prefix[0]) << 8) |
                                                static_cast<uint8_t>(prefix[1]));
    if (declared >= 12 && declared <= prefix.size() - 2) {
      return dissect_dns(reinterpret_cast<const uint8_t*>(prefix.data()) + 2, declared, out);
    }
  }
  return false;
}

bool dissect_udp_payload(const uint8_t* data, size_t len, uint16_t sport,
                         uint16_t dport, AppInfo& out) {
  if (data == nullptr || len == 0) return false;
  const uint16_t service = std::min(sport, dport);

  if (service == 53 || sport == 5353 || dport == 5353) {
    if (dissect_dns(data, len, out)) return true;
  }
  if (service == 67 || service == 68) {
    // DHCP: the magic cookie sits at a fixed offset in the BOOTP header.
    if (len > 240 && data[236] == 0x63 && data[237] == 0x82 && data[238] == 0x53 &&
        data[239] == 0x63) {
      out.proto = AppProtocol::DHCP;
      out.summary = (data[0] == 1) ? "request" : "reply";
      out.conclusive = true;
      return true;
    }
  }
  if (service == 123 && len >= 48) {
    const uint8_t mode = data[0] & 0x07;
    const uint8_t version = (data[0] >> 3) & 0x07;
    if (version >= 1 && version <= 4) {
      out.proto = AppProtocol::NTP;
      out.summary = "v" + std::to_string(version) + " mode=" + std::to_string(mode);
      out.conclusive = true;
      return true;
    }
  }
  if ((service == 443 || service == 80) && len > 0 && (data[0] & 0x40)) {
    // QUIC long-header packets have the fixed bit set; a full parse needs
    // version negotiation, so this only records the family.
    out.proto = AppProtocol::Other;
    out.summary = "QUIC?";
    out.conclusive = true;
    return true;
  }
  // Fall back to a port-independent attempt: DNS is common on odd ports.
  return dissect_dns(data, len, out);
}

}  // namespace netscope
