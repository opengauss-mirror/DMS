include_directories(
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

aux_source_directory(. PATCH_SRC)

link_directories(${LIBRARY_OUTPUT_PATH} ${SECUREC_LIB_PATH} ${OPENSSL_LIB_PATH} ${ZLIB_PATH} ${LZ4_PATH} ${CBB_LIB_PATH})

if (OS_ARCH STREQUAL "aarch64")
    add_compile_options(-mtls-dialect=trad)
endif()

add_library(hotpatch_obj OBJECT ${PATCH_SRC})