cmake_minimum_required(VERSION 2.6)
project(utdnsd C)

add_definitions(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations)

option(DEBUG "Compile for debugging purposes." OFF)
if(DEBUG)
  add_definitions(-DDEBUG -g3)
endif()

find_library(UBOX NAMES ubox)

add_executable(utdnsd utdnsd.c)
target_link_libraries(utdnsd ${UBOX})
install(TARGETS utdnsd
	RUNTIME DESTINATION sbin
)

add_custom_target(check sh test.sh
	WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
