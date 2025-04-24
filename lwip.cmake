# CMake file that sets up lwip for this project.
# Must set LWIP_DIR, LWIP_OPTS_DIR before including this file.
# Eventually link with your exectuable: target_link_libraries(your_exe lwip)
set(LWIP_CONTRIB_DIR ${LWIP_DIR}/contrib)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_DIR}/contrib"
    "${LWIP_DIR}/contrib/ports/unix/port/include"
    "${LWIP_OPTS_DIR}"
)

include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)
include(${LWIP_DIR}/src/Filelists.cmake)
include(${LWIP_DIR}/contrib/Filelists.cmake)
include(${LWIP_DIR}/contrib/ports/unix/Filelists.cmake)

add_library(lwip INTERFACE)
target_link_libraries(lwip INTERFACE ${LWIP_SANITIZER_LIBS} lwipcore lwipcontribportunix)
target_include_directories(lwip INTERFACE ${LWIP_INCLUDE_DIRS})
target_compile_definitions(lwip INTERFACE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
