cmake_minimum_required(VERSION 3.6)
project(setup_eth)

set(CMAKE_CXX_STANDARD 14)

find_library (LIBNL_LIBRARY nl-3)
find_library (LIBNL_ROUTE_LIBRARY nl-route-3)

find_path (LIBNL_INCLUDE_DIR
  NAMES
  netlink/netlink.h
  PATH_SUFFIXES
  libnl3
)

include_directories(${LIBNL_INCLUDE_DIR})

set(SOURCE_FILES setup_eth.cpp)
add_executable(setup_eth ${SOURCE_FILES})
target_link_libraries(setup_eth
        ${LIBNL_LIBRARY}
        ${LIBNL_ROUTE_LIBRARY}
        )
