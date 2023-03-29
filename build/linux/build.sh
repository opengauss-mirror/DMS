#!/bin/bash
# Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
# version V1.0
#
# used for build dms entry
#
set -e

export GIT_SSL_NO_VERIFY=true
export PYTHON3_HOME=${PYTHON3_HOME}
export PYTHON_INCLUDE_DIR=${PYTHON3_HOME}

BUILD_DIR=$(cd "$(dirname $0)"; pwd)
DMS_DIR=$(cd ../../; pwd)
OUTPUT_DIR="${DMS_DIR}/output"
TMP_DIR="${BUILD_DIR}/tmp"
PLATFORM_DIR="${DMS_DIR}/platform"
CBB_DIR="${PLATFORM_DIR}/CBB"
DMS_MES_DIR=${CBB_DIR}/src/cm_mes

############  pkg  ############
source $BUILD_DIR/get_OS_Version.sh

PACKAGE_PRE_NAME="DMS"
PACKAGE_OS_VERSION=$(echo $OS_VERSION |  tr "[a-z]" "[A-Z]")
SERVER_PACKAGE_NAME="${PACKAGE_PRE_NAME}_${PACKAGE_OS_VERSION}"
SYMBOL_PACKAGE_NAME="${PACKAGE_PRE_NAME}_${PACKAGE_OS_VERSION}_SYMBOL"
PACKAGE_HOME="${OUTPUT_DIR}/"

use_ss_cbb=0

function func_pkg_symbol()
{
    echo "pkg symbol"
    mkdir -p ${PACKAGE_HOME}/${SYMBOL_PACKAGE_NAME}/
    cp -r ${PACKAGE_HOME}/symbol/* ${PACKAGE_HOME}/${SYMBOL_PACKAGE_NAME}/
    chmod 500 ${PACKAGE_HOME}/${SYMBOL_PACKAGE_NAME}/*
    cd ${PACKAGE_HOME} && tar --owner=root --group=root -zcf ${SYMBOL_PACKAGE_NAME}.tar.gz ${SYMBOL_PACKAGE_NAME}/
}

function prepare_release_symbol()
{
    echo "release symbol"
    mkdir -p ${PACKAGE_HOME}/symbol

    sh  ${BUILD_DIR}/seperate_symbol.sh ${PACKAGE_HOME}/lib/libdms.so
    mv -f ${PACKAGE_HOME}/lib/libdms.so.symbol  ${PACKAGE_HOME}/symbol
}

function func_version()
{
    version=${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/version
   
    commit_id=$(git rev-parse HEAD)
    merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
    echo "git_id     = ${commit_id}" >> ${version}
    echo "merge_time = ${merge_time}" >> ${version}

    cd ${PACKAGE_HOME}/lib/
    md5sum *.so* >> ${version}
    cd - > /dev/null 2>&1
}

function make_package()
{
    echo "make server pkg"
    
    cd ${PACKAGE_HOME}/
    build_package_mode=$1
    if [[ "${build_package_mode}" = 'Release' ]]; then
        func_pkg_symbol
    fi
    
    mkdir -p ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/header/

    func_version $1

    cp -rf lib ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/
    cp -rf add-ons ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/
    cp -rf ${DMS_DIR}/src/interface/*.h ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/header/

    chmod 777  ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/lib/*
    chmod 500  ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/add-ons/*
    chmod 600  ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/header/*
    chmod 400  ${PACKAGE_HOME}/${SERVER_PACKAGE_NAME}/version

    tar --owner=root --group=root -zcf ${SERVER_PACKAGE_NAME}.tar.gz ${SERVER_PACKAGE_NAME}
}

function func_making_package()
{
    build_clean
    build_package_mode=$1
    if [[ -z "${build_package_mode}" ]]; then
        build_package_mode = 'Debug'
    fi

    ## compile
    if [[ "${build_package_mode}" = 'Debug' ]]; then
        build_make_debug
    else
        build_make_release    
    fi

    ## package
    make_package $1
    echo "make server pkg finished!"

}

############  clean  ############
function build_clean() {
    [ -d "${OUTPUT_DIR}" ] && rm -rf ${OUTPUT_DIR}/*
    [ -d "${TMP_DIR}" ] && rm -rf ${TMP_DIR}/*
    echo "-- clean dms up --"
    [ -f "${CBB_DIR}/build.sh" ] && sh "${CBB_DIR}"/build.sh clean
    echo "-- clean cbb up --"
}


############  debug or release  ############
function build_ut()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -DCMAKE_BUILD_TYPE=Debug -D DMS_TEST=ON -D UT_TEST=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*
    cd -
}

function build_test_coverage()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -DCMAKE_BUILD_TYPE=Debug -D DMS_TEST=ON -D ENABLE_GCOV=ON -D UT_TEST=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*
    cd -
}

function build_test()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -DCMAKE_BUILD_TYPE=Debug -D DMS_TEST=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*
    cd -
}

function build_opengauss_test()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -DCMAKE_BUILD_TYPE=Debug -D DMS_TEST=ON -DOPENGAUSS=yes -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*
    cd -
}

function build_debug()
{
    openGauss_flag=$1
    cd ${DMS_DIR}/
    CMAKE_OPT=""
    if [ ${openGauss_flag} -eq 1 ];then
        CMAKE_OPT="$CMAKE_OPT -DOPENGAUSS=yes"
    fi
    export BUILD_MODE=Debug
    cmake . -DCMAKE_BUILD_TYPE=Debug ${CMAKE_OPT} -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*
    cd -
}

function build_release()
{
  openGauss_flag=$1
    cd ${DMS_DIR}/
    CMAKE_OPT=""
    if [ ${openGauss_flag} -eq 1 ];then
        CMAKE_OPT="$CMAKE_OPT -DOPENGAUSS=yes"
    fi
    export BUILD_MODE=Release
    cmake . -DCMAKE_BUILD_TYPE=Release ${CMAKE_OPT} -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    sed -i "s/-O3/-O2/g" CMakeCache.txt
    make -j8

    chmod 777 $PACKAGE_HOME/lib/*   
    cd -
}

function build_fuzzasan()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -D CMAKE_BUILD_TYPE=Debug -D ENABLE_ASAN=ON -D ENABLE_GCOV=ON -D ENABLE_FUZZASAN=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8
    chmod 777 $PACKAGE_HOME/lib/*
}

function build_asan()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -D CMAKE_BUILD_TYPE=Debug -D ENABLE_ASAN=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8
    chmod 777 $PACKAGE_HOME/lib/*
}

function build_coverage()
{
    cd ${DMS_DIR}/
    export BUILD_MODE=Debug
    cmake . -D CMAKE_BUILD_TYPE=Debug -D ENABLE_GCOV=ON -B ${TMP_DIR}
    cd "${TMP_DIR}"/
    make -j8

    chmod 777 $PACKAGE_HOME/lib/* 
}

############  Put the dependent header file and lib library to build ############
function local_cpy_headfiles() {
    ## securec
    mkdir -p ${DMS_DIR}/library/huawei_security/include;
    cp -rf ${DMS_DIR}/platform/Huawei_Secure_C/include/*.h ${DMS_DIR}/library/huawei_security/include

    ## cbb
    mkdir -p ${DMS_DIR}/library/cbb/include;
    cp -fr "${PLATFORM_DIR}"/CBB/output/include/* ${DMS_DIR}/library/cbb/include
}

function local_cpy_libfiles() {
    ## cbb
    mkdir -p ${DMS_DIR}/library/cbb/lib
    cp -fr "${PLATFORM_DIR}"/CBB/output/lib/* ${DMS_DIR}/library/cbb/lib
}

function build_source_prepare() {
    # down cbb code
    cd ${PLATFORM_DIR}/CBB/
    sh "${PLATFORM_DIR}"/CBB/get_cbb_code.sh
    if [[ "$1" = 'Release' ]]; then
        build_cbb_mode="release"
    elif [[ "$1" = 'Debug' ]]; then
        build_cbb_mode="debug"
    elif [[ "$1" = 'Test' ]]; then
        build_cbb_mode="debug"
    elif [[ "$1" = 'OGtest' ]]; then
        build_cbb_mode="debug"
    elif [[ "$1" = 'Ut' ]]; then
        build_cbb_mode="debug"
    elif [[ "$1" = 'Test-Cov' ]]; then
        build_cbb_mode="debug"
    else
        build_cbb_mode="debug"
    fi

    sed -i "s/openssl;make;make install/openssl;make -j8;make install/g" "${PLATFORM_DIR}"/CBB/build/linux/compile_opensource.sh
    
    if [ "$1" != 'Ut' ] && [ "$1" != 'Test-Cov' ]; then
        sed -i "s/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" OFF)/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" ON)/g" "${PLATFORM_DIR}"/CBB/CMakeLists.txt
    fi
    
    sh "${PLATFORM_DIR}"/CBB/build.sh ${build_cbb_mode}
    cd -

    ## compile open_source
    sh ${BUILD_DIR}/compile_opensource.sh  ${DMS_DIR}/../

    local_cpy_headfiles
    local_cpy_libfiles
    
    rm -rf $TMP_DIR/*
}

############  Put the dependent header file and lib library to build with cbb in shared_storage folder  ############
function local_cpy_headfiles_with_ss_cbb() {
    ## securec
    mkdir -p ${DMS_DIR}/library/huawei_security/include;
    cp -rf ${CBB_DIR}/platform/Huawei_Secure_C/include/*.h ${DMS_DIR}/library/huawei_security/include
 
    ## openssl
    mkdir -p ${DMS_DIR}/library/openssl/include;
    cp -rf ${CBB_DIR}/library/openssl/include/* ${DMS_DIR}/library/openssl/include
    
    ## cbb
    mkdir -p ${DMS_DIR}/library/cbb/include;
    cp -rf ${CBB_DIR}/output/include/* ${DMS_DIR}/library/cbb/include
}
 
function local_cpy_libfiles_with_ss_cbb() {	
    ## securec
    mkdir -p ${DMS_DIR}/library/huawei_security/lib;
    cp -rf ${CBB_DIR}/library/huawei_security/lib/* ${DMS_DIR}/library/huawei_security/lib
 
    ## openssl
    mkdir -p ${DMS_DIR}/library/openssl/lib;
    cp -rf ${CBB_DIR}/library/openssl/lib/*  ${DMS_DIR}/library/openssl/lib
    
    ## cbb
    mkdir -p ${DMS_DIR}/library/cbb/lib;
    cp -rf ${CBB_DIR}/output/lib/* ${DMS_DIR}/library/cbb/lib
}
 
function build_source_prepare_with_ss_cbb() {

    if [[ ! -d "${CBB_DIR}" ]]; then
        echo "CBB does not exist under shared storage folder"
        exit 0
    fi
 
    if [[ ! -d "${CBB_DIR}/output/include" ]]; then
        if [[ "$1" = 'Release' ]]; then
            build_cbb_mode="release"
        elif [[ "$1" = 'Debug' ]]; then
            build_cbb_mode="debug"
        elif [[ "$1" = 'Test' ]]; then
            build_cbb_mode="debug"
        elif [[ "$1" = 'OGtest' ]]; then
            build_cbb_mode="debug"
        elif [[ "$1" = 'Ut' ]]; then
            build_cbb_mode="debug"
        elif [[ "$1" = 'Test-Cov' ]]; then
            build_cbb_mode="debug"
        else
            build_cbb_mode="debug"
        fi
        sed -i "s/openssl;make;make install/openssl;make -j8;make install/g" "${CBB_DIR}"/build/linux/compile_opensource.sh
        
        if [ "$1" != 'Ut' ] && [ "$1" != 'Test-Cov' ]; then
            sed -i "s/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" OFF)/OPTION(ENABLE_EXPORT_API \"Enable hidden internal api\" ON)/g" "${CBB_DIR}"/CMakeLists.txt
        fi
 
        cd ${CBB_DIR}/build/linux
        sh build.sh ${build_cbb_mode}
    fi
    cd $BUILD_DIR
 
    local_cpy_headfiles_with_ss_cbb
    local_cpy_libfiles_with_ss_cbb
    
    rm -rf $TMP_DIR/*
}

function build_after()
{
    ADD_ONES_DIR="${OUTPUT_DIR}/add-ons"
    mkdir -p $ADD_ONES_DIR
}

function build_all()
{
    cd $BUILD_DIR
    build_mode=$1
    openGauss_flag=$2
    if [[ ${use_ss_cbb} == 1 ]]; then
        build_source_prepare_with_ss_cbb $build_mode
    else
        build_source_prepare $build_mode
    fi
  
    if [[ -z "${build_mode}" ]]; then
        build_mode='Debug'
    fi

    if [[ -z "${openGauss_flag}" ]]; then
        openGauss_flag=0
    fi

    if [[ "${build_mode}" = 'Ut' ]]; then
        build_ut
    elif [[ "${build_mode}" = 'Test' ]]; then
        build_test
    elif [[ "${build_mode}" = 'OGtest' ]]; then
        build_opengauss_test
    elif [[ "${build_mode}" = 'Test-Cov' ]]; then
        build_test_coverage
    elif [[ "${build_mode}" = 'Debug' ]]; then
        build_debug ${openGauss_flag}
    elif [[ "${build_mode}" = 'Release' ]]; then
        build_release ${openGauss_flag}
    elif [[ "${build_mode}" = 'Coverage' ]]; then
        build_coverage
    elif [[ "${build_mode}" = 'Asan' ]]; then
        build_asan
    elif [[ "${build_mode}" = 'FuzzAsan' ]]; then
        build_fuzzasan
    else 
        echo "build mode error"
        exit 1
    fi

    build_after
}

function build_make_ut()
{
    echo "make ut"
    build_clean
    build_all Ut
}

function build_make_test()
{
    echo "make test"
    build_clean
    build_all Test
}

function build_make_ogtest()
{
    echo "make ogtest"
    build_clean
    build_all OGtest
}

function build_make_test_coverage()
{
    echo "make test"
    build_clean
    build_all Test-Cov
}

function build_make_debug()
{
    echo "make debug"
    build_clean
    build_all Debug $1
}

function build_make_release()
{
    echo "make release"
    build_clean
    build_all Release $1
    prepare_release_symbol
}

function build_make_coverage()
{
    echo "make coverage"
    build_clean
    build_all Coverage
}

function build_make_asan()
{
    echo "make asan"
    build_clean
    build_all Asan
}

function build_make_fuzzasan()
{
    echo "make fuzzasan"
    build_clean
    build_all FuzzAsan
}

function build_usage() {
    echo "[Error]: Unknown parameters"
    echo "[Usage]: ./build.sh"
    echo " sh build.sh ut < Compiling the Test Version. It is independent on CMS. CBB is not hidden >"
    echo " sh build.sh test < Compiling the Test Version. It is independent on CMS. CBB is hidden >"
    echo " sh build.sh test-cov < Compiling the Test Version. It is independent on CMS. CBB is hidden,Compiling the Debug version, but measure the code coverage >"
    echo " sh build.sh debug [ openGauss ] < Compiling the Debug Version >"
    echo " sh build.sh release [ openGauss ] < Compiling the Release Version >"
    echo " sh build.sh clean < Clear compilation information >"
    echo " sh build.sh package | sh build.sh package-debug < Package the debug version >"
    echo " sh build.sh cov < Compiling the Debug version, but measure the code coverage.>"
    echo " sh build.sh asan < Compiling the Debug version, but use the AddressSanitizer.>"
    echo " sh build.sh fuzzasan < Compiling the Debug version, but use the AddressSanitizer and measure the code coverage.>"
    exit 0
}

############  Parameter Parsing ############
function main() {
    arg1=$1
    arg_num=$#
    arg_list=($1 $2 $3)
    opengauss_flag=0
    for((i=1;i<=$arg_num;i++));
    do
        value=${arg_list[i-1]}
        if [ x"${value}" != x ];then
            str=$(echo ${value} | tr 'a-z' 'A-Z')
            if [ x"${str}" == x"OPENGAUSS" ];then
                opengauss_flag=1
                echo "Build DMS with openGauss..."
            elif [ x"${str}" == x"USE_COMMON_CBB" ];then
                use_ss_cbb=1
                CBB_DIR="${DMS_DIR}/../CBB"
                echo "Build DMS with CBB in shared_storage"
            fi
        fi
    done

    case "${arg1}" in
    'ut')
        build_make_ut
        ;;
    'test')
        build_make_test
        ;;
    'ogtest')
        build_make_ogtest
        ;;
    'test-cov')
        build_make_test_coverage
        ;;
    'debug')
        build_make_debug ${opengauss_flag}
        ;;
    'release')
        build_make_release ${opengauss_flag}
        ;;
    'cov')
        build_make_coverage
        ;;
    'asan')
        build_make_asan
        ;;
    'fuzzasan')
        build_make_fuzzasan
        ;;           
    'clean')
        build_clean
        ;;
    'package'|'package-debug')
        func_making_package Debug
        ;;
    'package-release')
        func_making_package Release
        ;;
    *)
        build_usage
        exit 1
        ;;
    esac
}

main "$@"