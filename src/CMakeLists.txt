option(ENABLE_FUZZASAN OFF)
if (ENABLE_FUZZASAN)
    add_compile_options(-fsanitize-coverage=trace-pc)
endif (ENABLE_FUZZASAN)

## other dependency include 
include_directories(${DMS_SECUREC_INC_PATH})
include_directories(${DMS_OPENSSL_PATH})
include_directories(${ZLIB_INC_PATH})
include_directories(${LZ4_INC_PATH})
include_directories(${DMS_CBB_PATH})

## source
include_directories(${DMS_COMMON_PATH})
include_directories(${DMS_DCS_PATH})
include_directories(${DMS_DMS_PATH})
include_directories(${DMS_DLS_PATH})
include_directories(${DMS_DRC_PATH})
include_directories(${DMS_RC_PATH})
include_directories(${DMS_INTERFACE_PATH})
include_directories(${DMS_OCK_PATH})

aux_source_directory(${DMS_COMMON_PATH} COMMON_SRC)
aux_source_directory(${DMS_DCS_PATH} DCS_SRC)
aux_source_directory(${DMS_DLS_PATH} DLS_SRC)
aux_source_directory(${DMS_DRC_PATH} DRC_SRC)
aux_source_directory(${DMS_DMS_PATH} DMS_SRC)
aux_source_directory(${DMS_RC_PATH} RC_SRC)
aux_source_directory(${DMS_OCK_PATH} OCK_SRC)

set(SRC_DMS_LIST ${COMMON_SRC} ${DCS_SRC} ${DLS_SRC} ${DRC_SRC} ${DMS_SRC} ${RC_SRC} ${OCK_SRC})

add_library(dms SHARED ${SRC_DMS_LIST})

if (ENABLE_FUZZASAN)
    target_link_libraries(dms pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} ${lz4} ${3rd_libccb} ${vpp_libipsi_crypto} ${fuzz_lib} -Wl,--no-whole-archive)
else()
    target_link_libraries(dms pthread dl rt -Wl,--whole-archive ${vpp_libsecurec} ${3rd_libssl} ${lz4} ${3rd_libccb} ${vpp_libipsi_crypto} -Wl,--no-whole-archive)
endif(ENABLE_FUZZASAN)