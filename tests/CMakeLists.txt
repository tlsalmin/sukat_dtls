include_directories(${CMAKE_SOURCE_DIR}/include)
add_definitions(-std=c++11)

set(list_of_tests "dtls_server")

add_definitions( -DCERT_PATH="${CMAKE_CURRENT_SOURCE_DIR}/certs")
foreach(test_var ${list_of_tests})
  add_executable(test_${test_var} test_${test_var}.cpp)
endforeach()

foreach(test_var ${list_of_tests})
  target_link_libraries(test_${test_var} gtest gtest_main ssl crypto pthread)
  target_link_libraries(test_${test_var} sukat_dtls)
  add_test(NAME TEST-${test_var} COMMAND test_${test_var})
endforeach()
