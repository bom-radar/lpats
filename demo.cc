/*------------------------------------------------------------------------------
 * GPATS client connection API for C++11
 *
 * Copyright (C) 2015 Commonwealth of Australia, Bureau of Meteorology
 * See COPYING for licensing and warranty details
 *
 * Author: Mark Curtis (m.curtis@bom.gov.au)
 *----------------------------------------------------------------------------*/
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

  strftime(buf, 128, "%FT%T", &tmm);
  snprintf(buf2, 32, ".%04d network ", msg.time_milliseconds);
  std::ostringstream oss;
  oss << buf << buf2 << (int) msg.network_id;
  return oss.str();
}

void handle_gpats_messages(gpats::client& con)
{
  // decode and print each message that we receive
  gpats::message_type type;
  while (con.dequeue(type))
  {
    switch (type)
    {
    case gpats::message_type::stroke:
      {
        gpats::stroke stroke;
        con.decode(stroke);
        std::cout
          << header(stroke)
          << " stroke " << (stroke.cloud_to_cloud ? "c2c" : "gnd")
          << " location " << stroke.latitude << " " << stroke.longitude
          << " amps " << stroke.amps
          << " gdop " << (int) stroke.gdop
          << " err " << stroke.error_major_axis << " " << stroke.error_minor_axis << " " << stroke.error_azimuth
          << std::endl;
      }
      break;
    case gpats::message_type::status:
      {
        gpats::status status;
        con.decode(status);
        std::cout << header(status) << " status network " << status.name << std::endl;
      }
      break;
    case gpats::message_type::timing:
      {
        gpats::timing timing;
        con.decode(timing);
        std::cout << header(timing) << " timing" << std::endl;
      }
      break;
    case gpats::message_type::ascii:
      {
        gpats::ascii ascii;
        con.decode(ascii);
        std::cout << header(ascii) << " ascii content=" << ascii.content << std::endl;
      }
      break;
    }
  }
}

int main(int argc, char const* argv[])
{
  try
  {
    // connect to GPATS
    gpats::client con{256};
    con.connect("comms.bom.gov.au", "30039");

    // loop forever as long as the connection stays open
    while (con.connected())
    {
      // wait for messages to arrive
      con.poll();

      // process socket traffic and handle messages until socket runs dry
      while (con.process_traffic())
        handle_gpats_messages(con);

      // handle remaining messages and return to polling
      handle_gpats_messages(con);
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
