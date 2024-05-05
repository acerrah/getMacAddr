cmake_minimum_required(VERSION 3.12)
project(arppacket)

# Set source and include directory
set(SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Source files
set(SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/arppacket.cpp)

# Include files
set(INCLUDES ${CMAKE_CURRENT_SOURCE_DIR}/src/arppacket.hpp)

add_library(arppacket STATIC ${SOURCES})

set_target_properties(arppacket PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)

# Specify the installation directory
install(TARGETS arppacket
    ARCHIVE DESTINATION /usr/local/lib
    LIBRARY DESTINATION /usr/local/lib
    RUNTIME DESTINATION /usr/local/bin)

install(FILES ${INCLUDES} DESTINATION /usr/local/include)