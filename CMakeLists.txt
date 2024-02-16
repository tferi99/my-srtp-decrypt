# CMakeList.txt : CMake project for my-srtp-decrypt, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project ("my-srtp-decrypt")

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Set the build type (Release, Debug, etc.)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

message(STATUS "CMake build type: ${CMAKE_BUILD_TYPE}")

# Where to look first for cmake modules, before ${CMAKE_ROOT}/Modules/ is checked
set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)

find_package(Pcap REQUIRED)
find_package(GCrypt REQUIRED)

#if you don't want the full compiler output, remove the following line
SET(CMAKE_VERBOSE_MAKEFILE ON)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-Wall -g -O0 -fPIC -DSRTP -DDEBUG_SRTP)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(-Wall -O2 -fPIC -DSRTP)
endif()

set(LIBRARIES_FOR_LINK
    ${PCAP_LIBRARIES}
    ${GCRYPT_LIBRARY}
)

message(STATUS "Libraries for link: ${LIBRARIES_FOR_LINK}")

# Add source to this project's executable.
add_executable (my-srtp-decrypt 
	"srtp.c"
	"srtp-decrypt.c"
)

include_directories(
	${PCAP_INCLUDE_DIRS}
    ${GCRYPT_INCLUDE_DIR}
)

target_link_libraries( ${PROJECT_NAME} PRIVATE ${LIBRARIES_FOR_LINK})