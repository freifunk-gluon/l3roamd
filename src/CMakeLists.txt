ADD_DEFINITIONS(-D_GNU_SOURCE)

list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${L3ROAMD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(l3roamd main.c socket.c config.c intercom.c arp.c ipmgr.c
	icmp6.c syscallwrappers.c routemgr.c prefix.c vector.c wifistations.c
	genl.c clientmgr.c taskqueue.c timespec.c util.c packet.c)

add_executable(test test.c socket.c config.c intercom.c arp.c ipmgr.c
	icmp6.c syscallwrappers.c routemgr.c prefix.c vector.c wifistations.c
	genl.c clientmgr.c taskqueue.c timespec.c util.c packet.c)

target_link_libraries(l3roamd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES} ${JSON_C_LIBRARIES})
target_link_libraries(test ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES} ${JSON_C_LIBRARIES})

#set_target_properties(l3roamd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall -fsanitize=address" LINK_FLAGS " -fno-omit-frame-pointer -fsanitize=address -static-libasan")
set_target_properties(l3roamd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall" LINK_FLAGS "")

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
