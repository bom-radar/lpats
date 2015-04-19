#include "gpats.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <tuple>

// TEMP
#include <cstdio>

using namespace gpats;

static constexpr size_t wire_size = 24;

static auto verify_checksum(uint8_t const* packet) -> bool
{
  uint32_t sum = 0;
  for (size_t i = 0; i < wire_size; ++i)
    sum += packet[i];
  return (sum & 0xff) == 0;
}

static auto decode_network(uint8_t const* packet) -> uint8_t
{
  return packet[0] >> 4u;
}

static auto decode_time(uint8_t const* packet) -> std::pair<time_t, uint16_t>
{
  // get the time_t of midnight
  struct tm tmm;
  tmm.tm_sec = 0;
  tmm.tm_min = 0;
  tmm.tm_hour= 0;
  tmm.tm_mday = ((packet[6] & 0x0f) << 4) + (packet[7] >> 4);
  tmm.tm_mon = ((packet[6] & 0xf0) >> 4) - 1;
  tmm.tm_year = ((uint16_t(packet[7] & 0x0f) << 8) + packet[5]) - 1900;
  time_t time = timegm(&tmm);

  // add the seconds from midnight offset
  uint16_t mins = (uint16_t(packet[1]) << 8) + packet[2];
  uint16_t mills = (uint16_t(packet[4]) << 8) + packet[3];
  time += mins * 60 + (mills / 1000);

  // return the time_t and the millisecond remainder
  return { time, mills % 1000 };
}

static auto decode_angle(uint8_t const* packet, size_t i) -> float
{
  uint32_t raw
    = uint32_t(packet[i])
    + (uint32_t(packet[i+1]) << 8)
    + (uint32_t(packet[i+2]) << 16)
    + (uint32_t(packet[i+3]) << 24);
  return static_cast<int32_t>(raw) / 10000000.0f;
}

/* how our circular read buffer works:
 * - when writing into the first wire_size (24) bytes of the buffer we also replicate
 *   these bytes into the end of the buffer
 * - when the writer reaches the end of the buffer less wire_size it wraps to 0
 * - this means that as a reader, we treat the buffer as if it is wire_size shorter than
 *   it really is.
 * - since we know each packet is exactly wire_size long, this allows us to do all our
 *   decoding of a packet without needing to worry about the wrap around point of the buffer
 *   since the packet starting at rpos_ is always in a single contiguous block of memory */

// determine the number of bytes available in the buffer for reading
inline auto client::read_size() -> size_t
{
  return wpos_ < rpos_ ? (buffer_.size() - wire_size) - rpos_ + wpos_ : wpos_ - rpos_;
}

inline auto client::check_cur_type(message_type type) -> void
{
  if (cur_type_ != type)
  {
    if (cur_type_ == message_type::none)
      throw std::runtime_error{"gpats: no message dequeued for decoding"};
    else
      throw std::runtime_error{"gpats: incorrect type passed for decoding"};
  }
}

client::client(size_t max_buffer_size, size_t initial_buffer_size)
  : max_buffer_size_{max_buffer_size}
  , socket_{-1}
  , synchronized_{false}
  , buffer_(initial_buffer_size, 0)
  , wpos_{0}
  , rpos_{0}
  , cur_type_{message_type::none}
{
}

client::client(client&& rhs) noexcept
  : max_buffer_size_{rhs.max_buffer_size_}
  , address_(std::move(rhs.address_))
  , service_(std::move(rhs.service_))
  , socket_{rhs.socket_}
  , synchronized_{rhs.synchronized_}
  , buffer_(std::move(rhs.buffer_))
  , wpos_{rhs.wpos_}
  , rpos_{rhs.rpos_}
  , cur_type_{rhs.cur_type_}
  , ascii_{std::move(rhs.ascii_)}
  , ascii_block_count_{rhs.ascii_block_count_}
  , ascii_block_flags_{rhs.ascii_block_flags_}
{
  rhs.socket_ = -1;
}

auto client::operator=(client&& rhs) noexcept -> client&
{
  max_buffer_size_ = rhs.max_buffer_size_;
  address_ = std::move(rhs.address_);
  service_ = std::move(rhs.service_);
  socket_ = rhs.socket_;
  synchronized_ = rhs.synchronized_;
  buffer_ = std::move(rhs.buffer_);
  wpos_ = rhs.wpos_;
  rpos_ = rhs.rpos_;
  cur_type_ = rhs.cur_type_;
  ascii_ = std::move(rhs.ascii_);
  ascii_block_count_ = rhs.ascii_block_count_;
  ascii_block_flags_ = rhs.ascii_block_flags_;

  rhs.socket_ = -1;

  return *this;
}

client::~client()
{
  disconnect();
}

auto client::connect(std::string address, std::string service) -> void
{
  if (socket_ != -1)
    throw std::runtime_error{"gpats: connect called while already connected"};

  // store connection details
  address_ = std::move(address);
  service_ = std::move(service);

  // reset connection state
  synchronized_ = false;
  wpos_ = 0;
  rpos_ = 0;
  cur_type_ = message_type::none;

  // lookupt the host
  addrinfo hints, *addr;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = 0;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  int ret = getaddrinfo(address_.c_str(), service_.c_str(), &hints, &addr);
  if (ret != 0 || addr == nullptr)
    throw std::runtime_error{"gpats: unable to resolve server address"};

  // TODO - loop through all addresses?
  if (addr->ai_next)
  {
    
  }

  // create the socket
  socket_ = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (socket_ == -1)
  {
    freeaddrinfo(addr);
    throw std::system_error{errno, std::system_category(), "gpats: socket creation failed"};
  }

  // set non-blocking I/O
  int flags = fcntl(socket_, F_GETFL);
  if (flags == -1)
  {
    disconnect();
    freeaddrinfo(addr);
    throw std::system_error{errno, std::system_category(), "gpats: failed to read socket flags"};
  }
  if (fcntl(socket_, F_SETFL, flags | O_NONBLOCK) == -1)
  {
    disconnect();
    freeaddrinfo(addr);
    throw std::system_error{errno, std::system_category(), "gpats: failed to set socket flags"};
  }

  // connect to the remote host
  ret = ::connect(socket_, addr->ai_addr, addr->ai_addrlen);
  if (ret < 0)
  {
    if (errno != EINPROGRESS)
    {
      disconnect();
      freeaddrinfo(addr);
      throw std::system_error{errno, std::system_category(), "gpats: failed to establish connection"};
    }
    establish_wait_ = true;
  }
  else
    establish_wait_ = false;

  // clean up the address list allocated by getaddrinfo
  freeaddrinfo(addr);
}

auto client::disconnect() -> void
{
  if (socket_ != -1)
  {
    close(socket_);
    socket_ = -1;
  }
}

auto client::connected() const -> bool
{
  return socket_ != -1;
}

auto client::pollable_fd() const -> int
{
  return socket_;
}

auto client::poll_read() const -> bool
{
  return socket_ != -1 && !establish_wait_;
}

auto client::poll_write() const -> bool
{
  return socket_ != -1 && establish_wait_;
}

auto client::poll(int timeout) -> void
{
  if (socket_ == -1)
    throw std::runtime_error{"gpats: attempt to poll while disconnected"};

  struct pollfd fds;
  fds.fd = socket_;
  fds.events = POLLRDHUP | (poll_read() ? POLLIN : 0) | (poll_write() ? POLLOUT : 0);
  ::poll(&fds, 1, timeout);
}

auto client::process_traffic() -> bool
{
  // sanity check
  if (socket_ == -1)
    return false;

  // need to check our connection attempt progress
  if (establish_wait_)
  {
    int res = 0; socklen_t len = sizeof(res);
    if (getsockopt(socket_, SOL_SOCKET, SO_ERROR, &res, &len) < 0)
    {
      disconnect();
      throw std::system_error{errno, std::system_category(), "gpats: getsockopt failure"};
    }

    // not connected yet?
    if (res == EINPROGRESS)
      return false;

    // okay, connection attempt is complete.  did it succeed?
    if (res < 0)
    {
      disconnect();
      throw std::system_error{res, std::system_category(), "gpats: failed to establish connection (async)"};
    }

    establish_wait_ = false;
  }

  // read everything we can
  while (true)
  {
    // see how much contiguous space is left in our buffer
    auto space = wpos_ < rpos_ ? rpos_ - wpos_ : buffer_.size() - wire_size - wpos_;

    printf("space %d wpos %d rpos %d\n", space, wpos_, rpos_);

    // if our buffer is full, try expanding it a bit
    if (space == 0)
    {
      // determine how much to expand by
      space = std::min(buffer_.size() * 2, max_buffer_size_) - buffer_.size();
      if (space == 0)
        throw std::runtime_error{"gpats: buffer overflow (try increasing max_buffer_size)"};

      printf("expanding! %d to %d\n", buffer_.size(), buffer_.size() + space);

      // insert space at the write position
      buffer_.insert(buffer_.begin() + wpos_, space, 0);

      // if the read position was after the insertion point, increment it by the same amount
      if (rpos_ > wpos_)
        rpos_ += space;
    }

    // read some data off the wire
    auto bytes = recv(socket_, &buffer_[wpos_], space, 0);
    if (bytes > 0)
    {
      // if we wrote into the start zone of the buffer, make sure we replicate that section at the end
      if (wpos_ < wire_size)
      {
        for (size_t i = 0; i < wire_size; ++i)
          buffer_[buffer_.size() - 1 - wire_size] = buffer_[i];
      }

      // advance our write position
      wpos_ += bytes;

      printf("read %d new wpos %d bsnegwire %d\n", bytes, wpos_, buffer_.size() - wire_size);

      // if we reached the end of the buffer, wrap around our write cursor
      // BUG BUG - something not right with the wrap around when rpos == 0
      // see wikipedia - empty/full ambiguity resolutions
      if (wpos_ == buffer_.size() - wire_size)
        wpos_ = 0;

      return true;
    }
    else if (bytes < 0)
    {
      // if we've run out of data to read stop trying
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return false;

      // if we were interrupted by a signal handler just try again
      if (errno == EINTR)
        continue;

      // a real receive error - kill the connection
      auto err = errno;
      disconnect();
      throw std::system_error{err, std::system_category(), "gpats: recv failure"};
    }
    else /* if (bytes == 0) */
    {
      // connection has been closed
      disconnect();
      return false;
    }
  }
}

auto client::address() const -> std::string const&
{
  return address_;
}

auto client::service() const -> std::string const&
{
  return service_;
}

auto client::synchronized() const -> bool
{
  return synchronized_;
}

auto client::dequeue() -> message_type
{
  // move along to the next packet in the read buffer if needed
  if (cur_type_ != message_type::none)
    rpos_ = (rpos_ + wire_size) % (buffer_.size() - wire_size);

  // reset our current type
  cur_type_ = message_type::none;

  // while there is enough data for a whole packet
  while (read_size() >= wire_size)
  {
    // if we pass the checksum return the message type code
    if ((synchronized_ = verify_checksum(&buffer_[rpos_])))
    {
      switch (buffer_[rpos_] & 0x0f)
      {
      case 0x00:
      case 0x03:
        cur_type_ = message_type::stroke;
        break;

      case 0x01:
        cur_type_ = message_type::status;
        break;

      case 0x02:
        cur_type_ = message_type::timing;
        break;

      case 0x0a:
        // read the header, if message is not yet recurse to the next packet
        cur_type_ = message_type::ascii;
        if (!handle_ascii_header())
          dequeue();
        break;

      case 0x0b:
        // read the header, if message is not yet recurse to the next packet
        cur_type_ = message_type::ascii;
        if (!handle_ascii_body())
          dequeue();
        break;

      default:
        // unknown or unsupported packet type, proceed straight to the next packet
        dequeue();
        break;
      }

      return cur_type_;
    }

    // move along a character and try again (if there's enough data)
    ++rpos_;
  }

  return cur_type_;
}

auto client::decode(stroke& msg) -> void
{
  check_cur_type(message_type::stroke);
  auto const data = &buffer_[rpos_];

  msg.network_id = decode_network(data);
  std::tie(msg.time, msg.time_milliseconds) = decode_time(data);
  msg.cloud_to_cloud = (data[0] & 0xff) == 0x03;
  msg.latitude = decode_angle(data, 15);
  msg.longitude = decode_angle(data, 8);
  msg.amps = static_cast<int16_t>(uint16_t(data[13]) + (uint16_t(data[14]) << 8)) * 100;
  msg.gdop = data[19];
  msg.error_major_axis = data[20] * 250.0f;
  msg.error_minor_axis = data[21] * 250.0f;
  msg.error_azimuth = static_cast<int8_t>(data[22]);
}

auto client::decode(status& msg) -> void
{
  check_cur_type(message_type::status);
  auto const data = &buffer_[rpos_];

  msg.network_id = decode_network(data);
  std::tie(msg.time, msg.time_milliseconds) = decode_time(data);
  msg.name.assign(reinterpret_cast<char*>(&data[12]), 3);
  msg.codes[0] = data[15];
  msg.codes[1] = data[16];
  msg.codes[2] = data[17];
  msg.codes[3] = data[18];
  msg.codes[4] = data[19];
  msg.codes[5] = data[20];
  msg.status = data[22];
}

auto client::decode(timing& msg) -> void
{
  check_cur_type(message_type::timing);
  auto const data = &buffer_[rpos_];

  msg.network_id = decode_network(data);
  std::tie(msg.time, msg.time_milliseconds) = decode_time(data);
}

auto client::decode(ascii& msg) -> void
{
  check_cur_type(message_type::ascii);
  msg = std::move(ascii_);
}

auto client::handle_ascii_header() -> bool
{
  auto const data = &buffer_[rpos_];

  ascii_.network_id = 0xff;
  std::tie(ascii_.time, ascii_.time_milliseconds) = decode_time(data);
  ascii_.code[0] = data[8];
  ascii_.code[1] = data[9];
  ascii_.code[2] = data[10];
  ascii_.code[3] = data[11];
  ascii_.subcode_1[0] = data[12];
  ascii_.subcode_1[1] = data[13];
  ascii_.subcode_1[2] = data[14];
  ascii_.subcode_1[3] = data[15];
  ascii_.subcode_2[0] = data[16];
  ascii_.subcode_2[1] = data[17];
  ascii_.subcode_2[2] = data[18];
  ascii_.subcode_2[3] = data[19];
  ascii_block_count_ = data[20];
  ascii_block_flags_.reset();
  // make sure to use assign due to our move in the decode function
  ascii_.content.assign(ascii_block_count_ * 21, '\0');

  // if no body is expected, return true to allow immediate decoding by user
  return ascii_block_count_ == 0;
}

auto client::handle_ascii_body() -> bool
{
  auto const data = &buffer_[rpos_];

  auto block = data[1] - 1;
  if (block >= 0 && block < ascii_block_count_)
  {
    ascii_.content.replace(block * 21, 21, reinterpret_cast<char*>(&data[2]));
    ascii_block_flags_.set(block);
  }

  // if we've received all the blocks return true to allow decoding by the user
  return ascii_block_flags_.count() == ascii_block_count_;
}

