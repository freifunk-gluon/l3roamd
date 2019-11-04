ADD_DEFINITIONS(-D_GNU_SOURCE)


list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${L3ROAMD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

list(APPEND COMMON_DEPS socket.c config.c intercom.c arp.c ipmgr.c icmp6.c syscallwrappers.c routemgr.c prefix.c vector.c wifistations.c genl.c clientmgr.c taskqueue.c timespec.c util.c packet.c)
list(APPEND DAEMON_DEPS main.c)
list(APPEND TEST_DEPS test.c)

add_library(common_libs OBJECT ${COMMON_DEPS})
add_library(test_deps OBJECT ${TEST_DEPS})
add_library(daemon_deps OBJECT ${DAEMON_DEPS})


add_executable(l3roamd $<TARGET_OBJECTS:daemon_deps> $<TARGET_OBJECTS:common_libs>)
add_executable(l3roamd-test $<TARGET_OBJECTS:test_deps> $<TARGET_OBJECTS:common_libs>)


target_link_libraries(l3roamd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES} ${JSON_C_LIBRARIES})
target_link_libraries(l3roamd-test ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES} ${JSON_C_LIBRARIES})

#set_target_properties(l3roamd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall -fsanitize=address" LINK_FLAGS " -fno-omit-frame-pointer -fsanitize=address -static-libasan")
set( CMAKE_C_FLAGS "-std=gnu11 -flto -Wall -Wcast-align -Wextra -Os " )


install(TARGETS l3roamd RUNTIME DESTINATION bin)

# Get the current working branch
execute_process(
  COMMAND git rev-parse --abbrev-ref HEAD
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Get the latest abbreviated commit hash of the working branch
execute_process(
  COMMAND git log -1 --format=%h
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  OUTPUT_VARIABLE GIT_COMMIT_HASH
  OUTPUT_STRIP_TRAILING_WHITESPACE
)

configure_file(
  ${CMAKE_SOURCE_DIR}/src/version.h.in
  ${CMAKE_BINARY_DIR}/src/version.h
)
