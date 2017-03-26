ADD_DEFINITIONS(-D_GNU_SOURCE)

list(APPEND CMAKE_REQUIRED_DEFINITIONS '-D_GNU_SOURCE')

include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${L3ROAMD_BINARY_DIR} ${CMAKE_CURRENT_BINARY_DIR})

add_executable(l3roamd main.c socket.c config.c intercom.c arp.c ipmgr.c icmp6.c routemgr.c vector.c wifistations.c genl.c clientmgr.c taskqueue.c timespec.c)

target_link_libraries(l3roamd ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})

set_target_properties(l3roamd PROPERTIES COMPILE_FLAGS "-std=gnu11 -Wall" LINK_FLAGS "")

install(TARGETS l3roamd RUNTIME DESTINATION bin)
