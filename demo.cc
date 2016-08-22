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
#include "lpats.h"

#include <iostream>
#include <sstream>
#include <stdexcept>
#include <cstring>
#include <ctime>

auto header(lpats::message msg) -> std::string
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

void handle_lpats_messages(lpats::client& con)
{
  // decode and print each message that we receive
  lpats::message_type type;
  while (con.dequeue(type))
  {
    switch (type)
    {
    case lpats::message_type::stroke:
      {
        lpats::stroke stroke;
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
    case lpats::message_type::status:
      {
        lpats::status status;
        con.decode(status);
        std::cout << header(status) << " status network " << status.name << std::endl;
      }
      break;
    case lpats::message_type::timing:
      {
        lpats::timing timing;
        con.decode(timing);
        std::cout << header(timing) << " timing" << std::endl;
      }
      break;
    case lpats::message_type::ascii:
      {
        lpats::ascii ascii;
        con.decode(ascii);
        std::cout << header(ascii) << " ascii content=" << ascii.content << std::endl;
      }
      break;
    }
  }
}

int main(int argc, char const* argv[])
{
  if (   argc == 2
      && (   strcmp(argv[1], "-v") == 0
          || strcmp(argv[1], "--version") == 0))
  {
    std::cout << "LPATS Protocol Support Library Demo\nVersion: " << lpats::release_tag() << std::endl;
    return EXIT_SUCCESS;
  }

  try
  {
    // connect to LPATS
    lpats::client con{256};
    con.connect("cmssdev.bom.gov.au", "35100");

    // loop forever as long as the connection stays open
    while (con.connected())
    {
      // wait for messages to arrive
      con.poll();

      // process socket traffic and handle messages until socket runs dry
      while (con.process_traffic())
        handle_lpats_messages(con);

      // handle remaining messages and return to polling
      handle_lpats_messages(con);
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
