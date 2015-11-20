cmake_minimum_required(VERSION 2.8)

project( qtCrypto )

#------------------------------------------------------------------------------
# Find QT

find_path(QT5_ROOT_PREFIX 
   PATHS lib/cmake/Qt5Core/Qt5CoreConfig.cmake
   HINTS "${CMAKE_PREFIX_PATH}" 
   DOC   "Qt5 root path")

if( (NOT QT5_ROOT_PREFIX) OR (NOT IS_DIRECTORY "${QT5_ROOT_PREFIX}") )
    message(FATAL_ERROR "Qt5 path not found. please set QT5_ROOT_PREFIX")
endif()

list(FIND CMAKE_PREFIX_PATH "${QT5_ROOT_PREFIX}" _index)
if(_index LESS 0)
    list(APPEND CMAKE_PREFIX_PATH "${QT5_ROOT_PREFIX}")
endif()


find_package(Qt5Core        REQUIRED)

#------------------------------------------------------------------------------
# Find OpenSSL

find_package( OpenSSL REQUIRED )

#------------------------------------------------------------------------------

add_subdirectory(src)

option(BUILD_TESTING "Build test suite" ON)
option(BUILD_EXAMPLES "Build examples"  OFF)

if (BUILD_TESTING)
  add_subdirectory(test)
endif()

if (BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

