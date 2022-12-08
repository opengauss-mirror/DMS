#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e
export GIT_SSL_NO_VERIFY=true
export WORKSPACE=$1
export OPEN_SOURCE=${WORKSPACE}/DMS/open_source/
export PLATFORM=${WORKSPACE}/DMS/platform
export LIBRARY=${WORKSPACE}/DMS/library
export CI=${WORKSPACE}/DMS/ci

echo "BUILD_MODE=${BUILD_MODE}"

if [[ ! -d "${OPEN_SOURCE}/openssl" ]]; then
    python3 ${CI}/manifest_download.py manifest_opensource.xml ${WORKSPACE}
fi

if [[ ! -d "${PLATFORM}/Huawei_Secure_C" ]]; then
    python3 ${CI}/manifest_download.py manifest_platform.xml ${WORKSPACE}
fi

#secure
if [[ ! -d "${LIBRARY}/huawei_security/lib" ]]; then
    cd ${PLATFORM}/Huawei_Secure_C/src;
    make CHECK_OPTION=check
    make lib CHECK_OPTION=check
    rm -rf ${LIBRARY}/huawei_security
    mkdir -p ${LIBRARY}/huawei_security/lib
    cp ${PLATFORM}/Huawei_Secure_C/lib/* ${LIBRARY}/huawei_security/lib/
fi

## openssl
if [[ ! -d "${LIBRARY}/openssl/lib" ]]; then
    ARCH=$(uname -p)
    cd ${OPEN_SOURCE}/openssl/;
    cd openssl-1.1.1n/
    if [ "${ARCH}" == x86_64 ]; then
        CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./config no-shared --prefix=${OPEN_SOURCE}/openssl;make -j8;make install
    else
        CFLAGS='-Wall -Wtrampolines -fno-common -fvisibility=default -fstack-protector-strong -fPIC --param ssp-buffer-size=4 -D_FORTIFY_SOURCE=2 -O2 -Wl,-z,relro,-z,now,-z,noexecstack' ./config no-asm no-shared -fPIC --prefix=${OPEN_SOURCE}/openssl;make -j8;make install
    fi
    rm -rf ${LIBRARY}/openssl
    mkdir -p ${LIBRARY}/openssl/lib
    mkdir -p ${LIBRARY}/openssl/include

    cp -r ${OPEN_SOURCE}/openssl/include/openssl ${LIBRARY}/openssl/include
    cp -r ${OPEN_SOURCE}/openssl/lib/* ${LIBRARY}/openssl/lib
fi

