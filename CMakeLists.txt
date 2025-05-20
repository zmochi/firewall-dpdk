set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
cmake_minimum_required(VERSION 3.10)
project(firewall)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

set(EXTERNAL_LIBS_DIR external)
set(INTERFACE_DIR ${CMAKE_SOURCE_DIR}/interfaces)

set(PCRE2_build_dir ${CMAKE_SOURCE_DIR}/external/PCRE2.build)
set(PCRE2_INCLUDE_DIR ${PCRE2_build_dir})
set(PCRE2_LIBRARIES ${PCRE2_build_dir}/libpcre2-8.a)

set(LWIP_DIR ${EXTERNAL_LIBS_DIR}/lwip)
set(LWIP_OPTS_DIR ${EXTERNAL_LIBS_DIR})
include(lwip.cmake)

set(INTERFACE_SOURCES
	${INTERFACE_DIR}/interface_main.cpp
	${INTERFACE_DIR}/interface_main.cpp 
	${INTERFACE_DIR}/ruletable_client.cpp 
	${INTERFACE_DIR}/logs_client.cpp 
	${INTERFACE_DIR}/logs_server.cpp 
	ruletable.cpp 
	parsers/logs_parser.cpp 
	parsers/ruletable_parser.cpp 
)

file(GLOB DLP_SOURCES DLP/*.cpp)
foreach(file ${DLP_SOURCES})
	set_source_files_properties(${file} PROPERTIES COMPILE_FLAGS "-I${PCRE2_INCLUDE_DIR}")
endforeach()

set(FW_SOURCES
	main.cpp 
	interfaces/logs_server.cpp 
	ruletable.cpp 
	logger.cpp 
	macaddr.cpp 
	interfaces/ruletable_server.cpp 
	fnv_hash.cpp 
	conn_table.cpp 
	MITM/setup.cpp
	${DLP_SOURCES}
	parsers/ruletable_parser.cpp
)

add_custom_target(external_libs
	COMMAND make -C ${CMAKE_SOURCE_DIR}/external
	COMMENT "Building external dependencies"
)

add_library(dpdk_objs OBJECT fw_dpdk.cpp)
target_compile_options(dpdk_objs PRIVATE ${DPDK_CFLAGS})

add_executable(fw ${FW_SOURCES})
target_include_directories(fw PRIVATE ${CMAKE_SOURCE_DIR} ${DPDK_INCLUDE_DIRS})
add_dependencies(fw external_libs)
target_link_libraries(fw PRIVATE ${DPDK_LIBRARIES} ${PCRE2_LIBRARIES} $<TARGET_OBJECTS:dpdk_objs> lwip)

add_executable(main ${INTERFACE_SOURCES})
add_dependencies(main external_libs)
target_include_directories(main PRIVATE ${CMAKE_SOURCE_DIR})

option(DEBUG_BUILD "Build with debug flags -g -O0 -DDEBUG" OFF)
if(DEBUG_BUILD)
	set(CMAKE_BUILD_TYPE Debug)
	target_compile_definitions(fw PRIVATE DEBUG)
	target_compile_definitions(lwip INTERFACE LWIP_DEBUG)
	target_compile_options(fw PRIVATE -g -O0)
	target_compile_definitions(main PRIVATE DEBUG)
	target_compile_options(main PRIVATE -g -O0)
endif()
