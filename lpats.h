/*------------------------------------------------------------------------------
 * LPATS Protocol Support Library
 *
 * Copyright 2016 Commonwealth of Australia, Bureau of Meteorology
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *----------------------------------------------------------------------------*/
#ifndef LPATS_H
#define LPATS_H

#include <atomic>
#include <bitset>
#include <cstdint>
#include <memory>
#include <string>

namespace lpats
{
  /// Get the SCM release tag that the library was built from
  auto release_tag() -> char const*;

  /// Available LPATS message types
  enum class message_type
  {
      stroke    ///< stroke indication
    , status    ///< network status
    , timing    ///< timing message
    , ascii     ///< ascii message
  };

  /// Base class for all LPATS messages
  struct message
  {
    uint8_t     network_id;         ///< identifier for originating network
    time_t      time;               ///< time of event (ie: stroke time)
    uint16_t    time_milliseconds;  ///< milliseconds component of time
  };

  /// Lightning stroke indication
  struct stroke : message
  {
    bool        cloud_to_cloud;     ///< is this a cloud to cloud stroke?
    float       latitude;           ///< latitude in degrees north
    float       longitude;          ///< longitude in degrees east
    float       amps;               ///< stroke amplitude in amps
    uint8_t     gdop;               ///< geometric dilution of precision (smaller = more accurate)
    float       error_major_axis;   ///< major axis length of 95% confidence interval ellipse in meters
    float       error_minor_axis;   ///< minor axis length of 95% confidence interval ellipse in meters
    float       error_azimuth;      ///< orientation of major axis of 95% confidence interval ellipse in degrees north
  };

  /// Network status
  struct status : message
  {
    std::string name;       ///< name of the network
    char        codes[6];   ///< status code for each receiver
    char        status;     ///< overall network status
  };

  /// Timing synchronization
  struct timing : message
  { };
  
  /// ASCII formatted message
  struct ascii : message
  {
    uint8_t     code[4];      ///< message code (LPATS internal use)
    uint8_t     subcode_1[4]; ///< sub-code block 1 (LPATS internal use)
    uint8_t     subcode_2[4]; ///< sub-code block 2 (LPATS internal use)
    std::string content;      ///< content of message
  };

  /// LPATS client connection manager
  /** This class is implemented with the expectation that it may be used in an environment where asynchronous I/O
   *  is desired.  As such, the most basic use of this class requires calling separate functions for checking
   *  data availability on the connection, processing connection traffic, dequeuing and decoding messages.
   *  If synchronous I/O is desired then these calls may simply be chained together one after another.
   *
   *  The basic synchronous usage sequence is:
   *    // create a connection and connect to LPATS server
   *    client con;
   *    con.connect("myhost", "1234");
   *
   *    // wait for data to arrive
   *    while (con.connected()) {
   *      con.poll();
   *    
   *      // process messages from LPATS
   *      bool again = true;
   *      while (again) {
   *        again = con.process_traffic();
   *    
   *        // dequeue each message
   *        message_type type;
   *        while (con.dequeue(type)) {
   *          // decode and handle interesting messages
   *          if (type == message_type::stroke) {
   *            stroke msg;
   *            con.decode(msg);
   *            ...
   *          }
   *        }
   *      }
   *    }
   *
   * For asynchronous usage, the user should use the pollable_fd(), poll_read() and poll_write() functions to
   * setup the appropriate multiplexed polling function for their application.
   *
   * It is also safe to use this class in a multi-threaded environment where one thread manages the communications
   * and another thread handles the incoming messages.  In such a setup thread safety is contingent on the following
   * conditions:
   *  - Communications is handled by a single thread which calls process_traffic()
   *  - Message processing is handled by a single thread which calls dequeue() and decode()
   *  - The connect() function must not be called at the same time as any other member function
   *
   * The const member functions may be called safely from any thread at any time.  It is suggested that the poll
   * functions be called from the communications thread, while the syncrhonized function be called from the 
   * message handler thread for maximum consistency.
   */
  class client
  {
  public:
    /// Construct a new LPATS connection
    /** By default the buffer is sized to hold 170 LPATS packets, which is just under 4kB. */
    client(size_t buffer_size = 4080);

    client(client const&) = delete;
    auto operator=(client const&) -> client& = delete;

    /// Move construct a client connection
    client(client&& rhs) noexcept;

    /// Move assign a client connection
    auto operator=(client&& rhs) noexcept -> client&;

    /// Destroy the client connection and automatically disconnect if needed
    ~client();

    /// Connect to a LPATS server
    auto connect(std::string address, std::string service) -> void;

    /// Disconnect from the LPATS server
    auto disconnect() -> void;

    /// Return true if a connection to the server is currently active
    auto connected() const -> bool;

    /// Get the file descriptor of the socket which may be used for multiplexed polling
    /** This function along with poll_read and poll_write are useful in an asynchronous I/O environment and you
     *  would like to block on multiple I/O sources.  The file descriptor returned by this function may be passed
     *  to pselect or a similar function.  The poll_read and poll_write functions return true if you should wait
     *  for read and write availability respectively. */
    auto pollable_fd() const -> int;

    /// Get whether the socket file descriptor should be monitored for read availability
    auto poll_read() const -> bool;

    /// Get whether the socket file descriptor should be montored for write availability
    auto poll_write() const -> bool;

    /// Wait (block) on the socket until some traffic arrives for processing
    /** The optional timeout parameter may be supplied to force the function to return after a cerain number
     *  of milliseconds.  The default is 5 seconds. */
    auto poll(int timeout = 5000) const -> void;

    /// Process traffic on the socket (may cause new messages to be available for dequeue)
    /** This function will read from the LPATS connection and queue any available messages in a buffer.  The
     *  messages may subsequently be retrieved by calling deqeue (and decode if desired) repeatedly until
     *  dequeue returns message_type::none.
     *
     *  If this function returns false then there is no more data currently available on the socket.  This
     *  behaviour can be used in an asynchronous I/O environment when deciding whether to continue processing
     *  traffic on this socket, or allow entry to a multiplexed wait (such as pselect). */
    auto process_traffic() -> bool;

    /// Get the hostname or address of the remote LPATS server
    auto address() const -> std::string const&;

    /// Get the service or port name for the LPATS connection
    auto service() const -> std::string const&;

    /// Is the stream successfully synchronized?
    auto synchronized() const -> bool;

    /// Dequeue the next available message and return its type
    /** If no message is available, the function returns false.
     *  Each time dequeue is called the stream position is advanced to the next message regardless of whether
     *  the decode function has been called for the current message.  This means that there is no need to decode
     *  messages about which you are not interested. */
    auto dequeue(message_type& type) -> bool;

    /// Decode the current message into the relevant message structure
    /** If the type of the message argument passed does not match the currently active message (as returned by the
     *  most recent call to dequeue) then a runtime exception will be thrown. */
    auto decode(stroke& msg) -> void;
    auto decode(status& msg) -> void;
    auto decode(timing& msg) -> void;
    auto decode(ascii& msg) -> void;

  private:
    using buffer = std::unique_ptr<uint8_t[]>;

  private:
    auto check_cur_type(message_type type) -> void;
    auto handle_ascii_header() -> bool;
    auto handle_ascii_body() -> bool;

  private:
    std::string         address_;           // remote LPATS hostname or address
    std::string         service_;           // remote service or port number
    int                 socket_;            // socket handle
    bool                establish_wait_;    // are we waiting for socket connection to be established?

    bool                synchronized_;      // have we got confirmed stream synchronization?
    buffer              buffer_;            // ring buffer to store packets off the wire
    size_t              capacity_;          // total usable buffer capacity
    std::atomic_size_t  wcount_;            // total bytes that have been written (wraps)
    std::atomic_size_t  rcount_;            // total bytes that have been read (wraps)
    message_type        cur_type_;          // type of currently dequeued message type

    ascii               ascii_;             // current ascii message being built up in pieces
    int                 ascii_block_count_; // number of body packets expected
    std::bitset<255>    ascii_block_flags_; // flags to indicate which body packets have been received
  };
}
#endif
