CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
PROJECT(dms)

message(STATUS "BUILD_TYPE = ${CMAKE_BUILD_TYPE}")
if (${CMAKE_BUILD_TYPE} STREQUAL "Debug"
     OR ${CMAKE_BUILD_TYPE} STREQUAL "")
    message(STATUS "CMAKE_BUILD_TYPE is Debug")
    set(CMAKE_BUILD_TYPE Debug)
    add_compile_definitions(_DEBUG)
elseif (${CMAKE_BUILD_TYPE} STREQUAL "Release")
    message(STATUS "CMAKE_BUILD_TYPE is Release")
    set(CMAKE_BUILD_TYPE Release)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
else ()
    message(FATAL_ERROR "unknown CMAKE_BUILD_TYPE = " ${CMAKE_BUILD_TYPE})
endif ()

set(COMPONENT "GaussDB Kernel")

if(OPENGAUSS STREQUAL "yes")
    message(STATUS "OPENGAUSS=yes")
    add_definitions(-DOPENGAUSS)
    set(COMPONENT "openGauss")
endif()

EXECUTE_PROCESS(
        COMMAND bash -c "git rev-parse HEAD | cut -b 1-8"
        OUTPUT_VARIABLE COMMIT_ID
        OUTPUT_STRIP_TRAILING_WHITESPACE
)
EXECUTE_PROCESS(
        COMMAND bash -c "date \"+%Y-%m-%d %H:%M:%S\""
        OUTPUT_VARIABLE COMPILE_TIME
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

# DMS_VERSION_STR like: libdms.so (openGauss build ab4a14da) compiled at 2000-01-01 00:00:00 debug)
SET(DMS_VERSION_STR
        "libdms.so (${COMPONENT} build ${COMMIT_ID}) compiled at ${COMPILE_TIME} ${CMAKE_BUILD_TYPE}"
)

message(STATUS "Version info: ${DMS_VERSION_STR}")

if(DMS_TEST STREQUAL "ON")
    message(STATUS "DMS_TEST=ON")
    add_definitions(-DDMS_TEST)
    message(STATUS "DMS_TEST is ON")
endif()

if(UT_TEST STREQUAL "ON")
    message(STATUS "UT_TEST=ON")
    add_definitions(-DUT_TEST)
    message(STATUS "UT_TEST is ON")
endif()

set(CMAKE_C_FLAGS "-std=c99 ${CMAKE_C_FLAGS} -D__FILE_NAME__='\"$(notdir $(subst .o,,$(abspath $@)))\"'" )

add_compile_options(-fPIC -Wall -MMD -fno-strict-aliasing -fsigned-char -fms-extensions -lpthread)
add_compile_definitions(_GNU_SOURCE _LARGEFILE64_SOURCE KNL_PREFIX _REENTRANT __PERF_STAT__)
add_link_options(-pie)
add_link_options(-Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now)
add_compile_options(-fvisibility=default -fstack-protector-strong --param ssp-buffer-size=4)

# 安全编译选项
set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ldl -pthread -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now")
add_compile_options(-fno-common)
add_compile_options(-Wtrampolines)
add_compile_options(-freg-struct-return)
add_compile_options(-pipe)
add_compile_options(-Wl,-Bsymbolic)
add_compile_options(-rdynamic)

OPTION(ENABLE_GCOV "Enable gcov (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_GCOV = ${ENABLE_GCOV}")
IF (ENABLE_GCOV AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable gcov (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fprofile-arcs -ftest-coverage -lgcov")
ENDIF()

OPTION(ENABLE_ASAN "Enable ASAN (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_ASAN = ${ENABLE_ASAN}")
IF (ENABLE_ASAN AND NOT WIN32 AND NOT APPLE)
    message(STATUS "Enable ASAN (debug, Linux builds only).")
    SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -fsanitize=address -fsanitize=leak -fsanitize-recover=address,all -O0 -Wall -g -fPIC -fno-omit-frame-pointer")
ENDIF()

OPTION(ENABLE_FUZZASAN "ENABLE FUZZASAN (debug, Linux builds only)" OFF)
message(STATUS "ENABLE_FUZZASAN = ${ENABLE_FUZZASAN}")
IF (ENABLE_FUZZASAN)
    set(DMS_FUZZ_LIB_PATH ${PROJECT_SOURCE_DIR}/test/fuzz_test/lib)
    message(STATUS "DMS_FUZZ_LIB_PATH = ${DMS_FUZZ_LIB_PATH}")
ENDIF()

OPTION(ENABLE_EXPORT_API "Enable hidden internal api" OFF)
message(STATUS "ENABLE_EXPORT_API = ${ENABLE_EXPORT_API}")
IF (ENABLE_EXPORT_API)
    add_compile_options(-fvisibility=hidden)
ENDIF()

execute_process(
    COMMAND uname -m
    OUTPUT_VARIABLE OS_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(CMAKE_SYSTEM_PROCESSOR ${OS_ARCH})
if (OS_ARCH STREQUAL "aarch64")
    option(USE_H1620 OFF)
    if (USE_H1620)
        add_compile_options(-march=armv8-a+crc+lse)
        message(STATUS "Toolchain: Build aarch64 USE_H1620")
    else ()
        add_compile_options(-march=armv8-a+crc)
    endif (USE_H1620)

    add_compile_options(-mtune=cortex-a72 -fsigned-char -g -ggdb3 -march=armv8-a+crc -funwind-tables)
else ()
    add_compile_options(-msse4.2 )
endif ()
Add_Definitions(-DWSEC_COMPILE_CAC_OPENSSL -DWSEC_AES_GCM_SUPPORT -DWSEC_USE_OPENSSL_110)

## dms include_directories
set(DMS_COMMON_PATH ${PROJECT_SOURCE_DIR}/src/common)
set(DMS_DRC_PATH ${PROJECT_SOURCE_DIR}/src/drc)
set(DMS_DCS_PATH ${PROJECT_SOURCE_DIR}/src/dcs)
set(DMS_DLS_PATH ${PROJECT_SOURCE_DIR}/src/dls)
set(DMS_DMS_PATH ${PROJECT_SOURCE_DIR}/src/dms)
set(DMS_RC_PATH ${PROJECT_SOURCE_DIR}/src/rc)
set(DMS_INTERFACE_PATH ${PROJECT_SOURCE_DIR}/src/interface)
set(DMS_OCK_PATH ${PROJECT_SOURCE_DIR}/src/ock)

## other dependency include 
set(DMS_SECUREC_INC_PATH        "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/include")
set(DMS_OPENSSL_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/include")
set(DMS_CBB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/include")
set(ZLIB_INC_PATH               "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/include/")

## lib
set(SECUREC_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/huawei_security/lib")
set(OPENSSL_LIB_PATH            "${CMAKE_CURRENT_SOURCE_DIR}/library/openssl/lib")
set(CBB_LIB_PATH                "${CMAKE_CURRENT_SOURCE_DIR}/library/cbb/lib")
set(ZLIB_PATH                   "${CMAKE_CURRENT_SOURCE_DIR}/library/zlib/lib/")

## output path
set (LIBRARY_OUTPUT_PATH        ${CMAKE_CURRENT_SOURCE_DIR}/output/lib)
set (EXECUTABLE_OUTPUT_PATH     ${CMAKE_CURRENT_SOURCE_DIR}/output/bin)

## add source
link_directories(${LIBRARY_OUTPUT_PATH} ${SECUREC_LIB_PATH} ${OPENSSL_LIB_PATH} ${ZLIB_PATH} ${CBB_LIB_PATH})

CONFIGURE_FILE(config.h.in ${DMS_COMMON_PATH}/config.h)

IF (ENABLE_FUZZASAN)
    link_directories(${DMS_FUZZ_LIB_PATH})
    set(fuzz_lib "libSecodefuzz.a")
ENDIF()

set(vpp_libsecurec "libsecurec.a")
set(vpp_libipsi_crypto "libcrypto.a")
set(3rd_libssl "libssl.a")
set(3rd_libccb "libcbb.a")
set(zlib "libz.a")

add_subdirectory(src)

