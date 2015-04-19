#include "gpats.h"
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <ctime>

auto header(gpats::message msg) -> std::string
{
  char buf[128], buf2[32];

  struct tm tmm;
  if (gmtime_r(&msg.time, &tmm) == nullptr)
    throw std::runtime_error("gmtime_r failed");

  strftime(buf, 128, " %F %T ", &tmm);
  snprintf(buf2, 32, "%04dms ", msg.time_milliseconds);
  std::ostringstream oss;
  oss << (int) msg.network_id << buf << buf2;
  return oss.str();
}

int main(int argc, char const* argv[])
{
  try
  {
    // connect to GPATS
    gpats::client con{256, 128};
    con.connect("comms.bom.gov.au", "30039");

    // one of each message type
    gpats::stroke stroke;
    gpats::status status;
    gpats::timing timing;
    gpats::ascii ascii;

    // loop forever as long as the connection stays open
    while (con.connected())
    {
      // wait for messages to arrive
      con.poll();

      // process received messages until we run out
      while (con.process_traffic())
      {
        std::cout << "continue" << std::endl;
        continue;
        // decode and print each message that we receive
        while (true)
        {
          switch (con.dequeue())
          {
          case gpats::message_type::none:
            break;
          case gpats::message_type::stroke:
            con.decode(stroke);
            std::cout
              << header(stroke)
              << " stroke"
              << " lat/lon " << stroke.latitude << " " << stroke.longitude
              << " amps " << stroke.amps
              << " gdop " << (int) stroke.gdop
              << " err " << stroke.error_major_axis << " " << stroke.error_minor_axis << " " << stroke.error_azimuth
              << std::endl;
            continue;
          case gpats::message_type::status:
            std::cout << header(status) << " status network " << status.name << std::endl;
            continue;
          case gpats::message_type::timing:
            std::cout << header(stroke) << " timing" << std::endl;
            continue;
          case gpats::message_type::ascii:
            std::cout << header(ascii) << " ascii content=" << ascii.content << std::endl;
            continue;
          }

          // if we get here the type was 'none', so break out of the dequeue loop
          break;
        }
      }
    }
  }
  catch (std::exception& err)
  {
    std::cerr << "fatal error: " << err.what() << std::endl;
    return EXIT_FAILURE;
  }
  catch (...)
  {
    std::cerr << "fatal error: unknown" << std::endl;
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
