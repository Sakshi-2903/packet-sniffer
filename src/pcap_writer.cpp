#include "pcap_writer.hpp"

#include <cerrno>
#include <cstring>

namespace netscope {

namespace {

// The magic number doubles as an endianness marker: a reader that sees the bytes
// reversed knows every field in the file is byte-swapped. Writing in host order
// and letting the magic declare it is what libpcap itself does.
constexpr uint32_t kPcapMagic = 0xA1B2C3D4;
constexpr uint16_t kVersionMajor = 2;
constexpr uint16_t kVersionMinor = 4;
constexpr uint64_t kFlushEvery = 64;

template <typename T>
bool write_raw(std::FILE* f, T value) {
  return std::fwrite(&value, sizeof(value), 1, f) == 1;
}

}  // namespace

PcapWriter::~PcapWriter() { close(); }

bool PcapWriter::open(const std::string& path, int linktype, int snaplen,
                      std::string& err) {
  file_ = std::fopen(path.c_str(), "wb");
  if (file_ == nullptr) {
    err = "cannot open '" + path + "' for writing: " + std::strerror(errno);
    return false;
  }
  path_ = path;
  snaplen_ = snaplen > 0 ? static_cast<uint32_t>(snaplen) : 262144;

  const bool ok =
      write_raw<uint32_t>(file_, kPcapMagic) &&
      write_raw<uint16_t>(file_, kVersionMajor) &&
      write_raw<uint16_t>(file_, kVersionMinor) &&
      write_raw<int32_t>(file_, 0) &&          // thiszone: timestamps are UTC
      write_raw<uint32_t>(file_, 0) &&         // sigfigs: unused in practice
      write_raw<uint32_t>(file_, snaplen_) &&
      write_raw<uint32_t>(file_, static_cast<uint32_t>(linktype));
  if (!ok) {
    err = "cannot write pcap header to '" + path + "'";
    close();
    return false;
  }
  return true;
}

void PcapWriter::write(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                       const timeval& ts) {
  if (file_ == nullptr || data == nullptr) return;
  // A record must never claim more bytes than it stores, or readers will run off
  // the end of the file.
  if (caplen > snaplen_) caplen = snaplen_;
  if (wirelen < caplen) wirelen = caplen;

  if (!write_raw<uint32_t>(file_, static_cast<uint32_t>(ts.tv_sec)) ||
      !write_raw<uint32_t>(file_, static_cast<uint32_t>(ts.tv_usec)) ||
      !write_raw<uint32_t>(file_, caplen) ||
      !write_raw<uint32_t>(file_, wirelen)) {
    return;
  }
  if (std::fwrite(data, 1, caplen, file_) != caplen) return;

  ++packets_;
  bytes_ += caplen;
  // Periodic flushing keeps the file readable while capture is still running,
  // which matters when the process is killed rather than stopped cleanly.
  if (packets_ % kFlushEvery == 0) std::fflush(file_);
}

void PcapWriter::close() {
  if (file_ != nullptr) {
    std::fflush(file_);
    std::fclose(file_);
    file_ = nullptr;
  }
}

}  // namespace netscope
