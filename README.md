# LPATS Protocol Support Library

[![Build Status](https://travis-ci.org/bom-radar/lpats.svg?branch=master)](https://travis-ci.org/bom-radar/lpats)

This library implements the Lightning Position & Tracking System (LPATS) client
protocol and makes it easy for you to integrate live lightning data into your
application.

## Installation
To build and install the library use CMake to generate Makefiles.  For an
install to the standard locations on a linux system run the following commands
from the root of the source distribution:

    mkdir build
    cd build
    cmake ..
    make
    sudo make install

To install to a non-standard prefix (eg: ${HOME}/local) modify the cmake line
as such:

    mkdir build
    cd build
    cmake .. -DCMAKE_INSTALL_PREFIX=${HOME}/local
    make
    sudo make install


## Building the demo application
A demo application is included which simply uses the API to connect to an LPATS
server and print received lightning strike messages to the console.

To build and run this project, from within the 'build' directory above type:

    make demo
    ./demo

## Integrating with your project
To use the library within your project it is necessary to tell your build
system how to locate the correct header and shared library files.  Support
for discovery by `CMake` and `pkg-config` (and therefore `autotools`) is
included.

### Via CMake
To use the library within your `CMake` based project, simply add the line

    find_package(lpats)

to your `CMakeLists.txt`.  This function call will set the variables
`LPATS_INCLUDE_DIRS` and `LPATS_LIBRARIES` as needed.  A typical usage
scenario is found below:

    find_package(lpats REQUIRED)
    include_directories(${LPATS_INCLUDE_DIRS})
    add_executable(foo foo.cc)
    target_link_libraries(foo ${LPATS_LIBRARIES})

### Via pkg-config
To discover compilation and link flags via `pkg-config` use the following
commands:

    pkg-config --cflags lpats
    pkg-config --libs lpats

A typical usage scenario is found below:

    g++ -o foo $(pkg-config --cflags --libs lpats) foo.cc

If pkg-config cannot find the `lpats` package, ensure that you have set your
`PKG_CONFIG_PATH` environment variable correctly for the install prefix which
installed the library to.  For example, in the ${HOME}/local example above
the following will set the correct `PKG_CONFIG_PATH`:

    export PKG_CONFIG_PATH=${PKG_CONFIG_PATH}:${HOME}/local/lib/pkgconfig

### C++ compatibility note
The library is written in C++11.  It will not compile on compilers that lack
support for this version of C++ or later.  _Depending on your compiler you may
need to explicitly enable C++11 support by adding the `-std=c++11` flag._

For example:

    g++ -std=c++11 -o foo $(pkg-config --cflags --libs lpats) foo.cc

## Using the API
Please consult the lpats.h header and the source of demo.cc for examples on how
to use the API within your code.

## License
This library is open source and made freely available according to the below
text:

    Copyright 2016 Commonwealth of Australia, Bureau of Meteorology

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

A copy of the license is also provided in the LICENSE file included with the
source distribution of the library.
