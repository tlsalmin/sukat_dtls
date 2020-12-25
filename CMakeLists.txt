cmake_minimum_required (VERSION 3.7)
project (sukat_dtls)

AUX_SOURCE_DIRECTORY(${CMAKE_SOURCE_DIR}/src SUKAT_DTLS_LIB_SRC)
AUX_SOURCE_DIRECTORY(${CMAKE_SOURCE_DIR}/nc SUKAT_DTLS_NC_SRC)
add_library(sukat_dtls SHARED
  ${SUKAT_DTLS_LIB_SRC})
include_directories(${CMAKE_SOURCE_DIR}/include)

add_executable(nc_dtls ${SUKAT_DTLS_NC_SRC})
include_directories(${CMAKE_SOURCE_DIR}/src)
target_link_libraries(nc_dtls ssl crypto sukat_dtls)

option(test "Build all tests." OFF)
if (test)
  enable_testing()
  add_subdirectory(tests)
endif()

