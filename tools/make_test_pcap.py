#!/usr/bin/env python3
"""Builds a small synthetic pcap so netscope can be tested without root.

The generated capture deliberately contains the situations the analyser is
supposed to notice:

  * a complete TCP handshake, data transfer and FIN teardown
  * a retransmitted data segment (same seq and length sent twice)
  * an out-of-order segment (a sequence gap)
  * a connection refused with RST
  * a UDP DNS query and response
  * an ICMP echo request and reply
  * an IPv4 packet with a deliberately corrupted header checksum
  * an HTTP request and response (application dissection)
  * a TLS ClientHello split across two segments that arrive OUT OF ORDER, so
    the SNI is only recoverable after stream reassembly
  * an SSH version banner exchange

Usage:  python3 tools/make_test_pcap.py captures/sample.pcap
"""

import struct
import sys
import os

LINKTYPE_ETHERNET = 1


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def ip(text: str) -> bytes:
    return bytes(int(part) for part in text.split("."))


def ethernet(src: str, dst: str, ethertype: int = 0x0800) -> bytes:
    return mac(dst) + mac(src) + struct.pack("!H", ethertype)


def ipv4(src: str, dst: str, payload: bytes, proto: int, ident: int = 0,
         ttl: int = 64, corrupt_checksum: bool = False) -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, ident, 0x4000,
                         ttl, proto, 0, ip(src), ip(dst))
    csum = checksum(header)
    if corrupt_checksum:
        csum ^= 0xFFFF
    header = header[:10] + struct.pack("!H", csum) + header[12:]
    return header + payload


def tcp(src_ip: str, dst_ip: str, sport: int, dport: int, seq: int, ack: int,
        flags: int, payload: bytes = b"", window: int = 64240) -> bytes:
    offset_flags = (5 << 12) | flags  # 5 words = 20-byte header, no options
    header = struct.pack("!HHIIHHHH", sport, dport, seq, ack, offset_flags,
                         window, 0, 0)
    pseudo = ip(src_ip) + ip(dst_ip) + struct.pack("!BBH", 0, 6,
                                                   len(header) + len(payload))
    csum = checksum(pseudo + header + payload)
    header = header[:16] + struct.pack("!H", csum) + header[18:]
    return header + payload


def udp(src_ip: str, dst_ip: str, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    header = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = ip(src_ip) + ip(dst_ip) + struct.pack("!BBH", 0, 17, length)
    csum = checksum(pseudo + header + payload) or 0xFFFF
    header = struct.pack("!HHHH", sport, dport, length, csum)
    return header + payload


def icmp(icmp_type: int, code: int, ident: int, seq: int, payload: bytes) -> bytes:
    header = struct.pack("!BBHHH", icmp_type, code, 0, ident, seq)
    csum = checksum(header + payload)
    header = struct.pack("!BBHHH", icmp_type, code, csum, ident, seq)
    return header + payload


def tls_client_hello(sni: str) -> bytes:
    """Builds a minimal but structurally valid TLS 1.3 ClientHello."""
    sni_bytes = sni.encode()
    server_name = struct.pack("!HBH", len(sni_bytes) + 3, 0, len(sni_bytes)) + sni_bytes
    extensions = struct.pack("!HH", 0x0000, len(server_name)) + server_name
    # supported_versions: TLS 1.3 announces its real version here
    extensions += struct.pack("!HHBH", 0x002B, 3, 2, 0x0304)

    body = struct.pack("!H", 0x0303)          # legacy version
    body += bytes(range(32))                  # random
    body += b"\x00"                           # session id length
    body += struct.pack("!HH", 2, 0x1301)     # one cipher suite
    body += b"\x01\x00"                       # null compression
    body += struct.pack("!H", len(extensions)) + extensions

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

CLIENT_MAC = "aa:bb:cc:00:00:01"
SERVER_MAC = "aa:bb:cc:00:00:02"
ROUTER_MAC = "aa:bb:cc:00:00:03"
CLIENT = "192.168.1.50"
SERVER = "93.184.216.34"
DNS = "192.168.1.1"
PEER = "10.0.0.7"


def build_packets():
    """Returns a list of (timestamp_seconds, frame_bytes) tuples."""
    out = []
    t = 1721990400.000000  # fixed base time so runs are reproducible

    def add(dt, frame):
        nonlocal t
        t += dt
        out.append((t, frame))

    # --- flow 1: HTTPS session, client 192.168.1.50:51000 -> server:443 -----
    sp = 51000
    c_seq, s_seq = 1000, 5000

    add(0.000, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, 0, SYN), 6, 1))
    add(0.030, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq, c_seq + 1, SYN | ACK), 6, 2))
    c_seq += 1
    s_seq += 1
    add(0.001, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, s_seq, ACK), 6, 3))

    # Client sends a TLS-ish record.
    req = b"\x16\x03\x01" + b"A" * 200
    add(0.002, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, s_seq, PSH | ACK, req), 6, 4))

    # RETRANSMISSION: the same segment (identical seq and length) sent again.
    add(0.250, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, s_seq, PSH | ACK, req), 6, 5))
    c_seq += len(req)

    add(0.040, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq, c_seq, ACK), 6, 6))

    # Server response split into three segments, the middle one arriving late
    # (an out-of-order gap followed by the missing piece, itself a retransmit).
    seg = b"B" * 500
    add(0.010, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq, c_seq, ACK, seg), 6, 7))
    add(0.005, ethernet(ROUTER_MAC, CLIENT_MAC) +   # jumps ahead: gap
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq + 1000, c_seq, ACK, seg), 6, 8))
    add(0.030, ethernet(ROUTER_MAC, CLIENT_MAC) +   # the missing middle segment
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq + 500, c_seq, ACK, seg), 6, 9))
    s_seq += 1500

    add(0.002, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, s_seq, ACK), 6, 10))

    # Graceful teardown.
    add(0.500, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq, s_seq, FIN | ACK), 6, 11))
    add(0.030, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, sp, s_seq, c_seq + 1, FIN | ACK), 6, 12))
    add(0.001, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, sp, 443, c_seq + 1, s_seq + 1, ACK), 6, 13))

    # --- flow 2: connection refused -----------------------------------------
    add(0.100, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, PEER, tcp(CLIENT, PEER, 51001, 8080, 22000, 0, SYN), 6, 20))
    add(0.005, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(PEER, CLIENT, tcp(PEER, CLIENT, 8080, 51001, 0, 22001, RST | ACK), 6, 21))

    # --- flow 3: DNS lookup over UDP ----------------------------------------
    query = (b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
    answer = query[:2] + b"\x81\x80" + query[4:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + ip(SERVER)
    add(0.050, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, DNS, udp(CLIENT, DNS, 53535, 53, query), 17, 30))
    add(0.012, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(DNS, CLIENT, udp(DNS, CLIENT, 53, 53535, answer), 17, 31))

    # --- flow 4: ICMP echo request and reply --------------------------------
    ping_payload = bytes(range(56))
    for i in range(3):
        add(0.200, ethernet(CLIENT_MAC, ROUTER_MAC) +
            ipv4(CLIENT, SERVER, icmp(8, 0, 0x1234, i + 1, ping_payload), 1, 40 + i))
        add(0.025, ethernet(ROUTER_MAC, CLIENT_MAC) +
            ipv4(SERVER, CLIENT, icmp(0, 0, 0x1234, i + 1, ping_payload), 1, 50 + i))

    # --- flow 5: a frame with a bad IPv4 header checksum --------------------
    add(0.100, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, DNS, udp(CLIENT, DNS, 53536, 53, query), 17, 60,
             corrupt_checksum=True))

    # --- flow 6: plain HTTP request and response ----------------------------
    hp = 51002
    h_seq, hs_seq = 70000, 80000
    add(0.050, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, hp, 80, h_seq, 0, SYN), 6, 70))
    add(0.020, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 80, hp, hs_seq, h_seq + 1, SYN | ACK), 6, 71))
    h_seq += 1
    hs_seq += 1
    add(0.001, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, hp, 80, h_seq, hs_seq, ACK), 6, 72))

    http_req = (b"GET /index.html HTTP/1.1\r\n"
                b"Host: example.com\r\n"
                b"User-Agent: netscope-demo/1.0\r\n"
                b"Accept: */*\r\n\r\n")
    add(0.002, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, hp, 80, h_seq, hs_seq, PSH | ACK, http_req), 6, 73))
    h_seq += len(http_req)
    # The response ACK arrives 45 ms later, giving the RTT estimator a sample.
    add(0.045, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 80, hp, hs_seq, h_seq, ACK), 6, 74))
    http_resp = (b"HTTP/1.1 200 OK\r\n"
                 b"Content-Type: text/html\r\n"
                 b"Content-Length: 13\r\n\r\n"
                 b"Hello, world!")
    add(0.005, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 80, hp, hs_seq, h_seq, PSH | ACK, http_resp), 6, 75))

    # --- flow 7: TLS ClientHello split across REORDERED segments -------------
    # The second half is captured before the first, so the SNI can only be read
    # after the reassembler puts the stream back in order.
    tp = 51003
    t_seq, ts_seq = 90000, 95000
    hello = tls_client_hello("secure.example.org")
    cut = len(hello) // 2
    add(0.050, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, tp, 443, t_seq, 0, SYN), 6, 80))
    add(0.018, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(SERVER, CLIENT, tcp(SERVER, CLIENT, 443, tp, ts_seq, t_seq + 1, SYN | ACK), 6, 81))
    t_seq += 1
    ts_seq += 1
    add(0.001, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, tp, 443, t_seq, ts_seq, ACK), 6, 82))
    add(0.003, ethernet(CLIENT_MAC, ROUTER_MAC) +          # tail arrives first
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, tp, 443, t_seq + cut, ts_seq, ACK,
                                 hello[cut:]), 6, 83))
    add(0.004, ethernet(CLIENT_MAC, ROUTER_MAC) +          # head fills the gap
        ipv4(CLIENT, SERVER, tcp(CLIENT, SERVER, tp, 443, t_seq, ts_seq, PSH | ACK,
                                 hello[:cut]), 6, 84))

    # --- flow 8: SSH banner exchange ----------------------------------------
    ssh_p = 51004
    s_c, s_s = 60000, 61000
    add(0.040, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, PEER, tcp(CLIENT, PEER, ssh_p, 22, s_c, 0, SYN), 6, 90))
    add(0.008, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(PEER, CLIENT, tcp(PEER, CLIENT, 22, ssh_p, s_s, s_c + 1, SYN | ACK), 6, 91))
    s_c += 1
    s_s += 1
    add(0.001, ethernet(CLIENT_MAC, ROUTER_MAC) +
        ipv4(CLIENT, PEER, tcp(CLIENT, PEER, ssh_p, 22, s_c, s_s, ACK), 6, 92))
    banner = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3\r\n"
    add(0.002, ethernet(ROUTER_MAC, CLIENT_MAC) +
        ipv4(PEER, CLIENT, tcp(PEER, CLIENT, 22, ssh_p, s_s, s_c, PSH | ACK, banner), 6, 93))

    # --- flow 9: a chatty UDP stream, to give the throughput graph shape ----
    for i in range(40):
        add(0.020, ethernet(CLIENT_MAC, SERVER_MAC) +
            ipv4(CLIENT, PEER, udp(CLIENT, PEER, 40000, 5004, bytes(1000)), 17, 100 + i))

    return out


def write_pcap(path, packets):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        # magic, major, minor, thiszone, sigfigs, snaplen, network
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535,
                             LINKTYPE_ETHERNET))
        for ts, frame in packets:
            sec = int(ts)
            usec = int(round((ts - sec) * 1_000_000))
            fh.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            fh.write(frame)


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else "captures/sample.pcap"
    pkts = build_packets()
    write_pcap(out_path, pkts)
    print(f"wrote {len(pkts)} packets to {out_path}")
