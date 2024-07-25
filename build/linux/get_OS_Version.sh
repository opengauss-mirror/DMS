#!/bin/bash
# Copyright Huawei Technologies Co., Ltd. 2010-2018. All rights reserved.
set -e
declare OS_VERSION=""
declare OS_SUFFIX=""
declare OS_MAJOR_VERSION=""
declare OS_MINOR_VERSION=""
declare OS_ARCH=""

OS_NAME=$(uname -s)
ARCH=$(getconf LONG_BIT)

SUSE_VERSION_PATH=/etc/SuSE-release
REDHAT_VERSION_PATH=/etc/redhat-release
CENTOS_VERSION_PATH=/etc/centos-release
NEOKYLIN_VERSION_PATH=/etc/neokylin-release
KYLIN_VERSION_PATH=/etc/kylin-release
OPENEULER_VERSION_PATH=/etc/openEuler-release
EULER_VERSION_PATH=/etc/euleros-release

CODE_HOME_PATH=$(echo $(dirname $(pwd)))/..

if [[ ${OS_NAME} -ne "Linux" ]]; then
    echo "Not on Linux OS"
    exit 1
else
    OS_ARCH=$(uname -i)
fi

if [[ -f ${SUSE_VERSION_PATH} ]]; then
    OS_MAJOR_VERSION=$(cat ${SUSE_VERSION_PATH} | grep VERSION |cut -d ' ' -f 3)
    OS_MINOR_VERSION=$(cat ${SUSE_VERSION_PATH} | grep PATCHLEVEL |cut -d ' ' -f 3)
    OS_SUFFIX=SUSE"${OS_MAJOR_VERSION}SP${OS_MINOR_VERSION}"
    if [ ${OS_ARCH} == "x86_64" ];then
        OS_VERSION=suse11_SP3_X86_${ARCH}
    elif [ ${OS_ARCH} == "aarch64" ];then
        OS_VERSION=suse12_SP5_${OS_ARCH}
    else
        echo "Unsupported centos System"
        exit 1
    fi
elif [[ -f ${KYLIN_VERSION_PATH} ]]; then
    OS_SUFFIX=KYLIN
    OS_VERSION=kylin_${OS_ARCH}
elif [[ -f ${NEOKYLIN_VERSION_PATH} ]]; then
    OS_SUFFIX=KYLINREDHAT
    OS_VERSION=kylin_${OS_ARCH}
elif [[ -f ${EULER_VERSION_PATH} ]]; then
    if [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP3)') ]]; then
        OS_SUFFIX=EULER20SP3
        OS_VERSION=euler20_SP3_${OS_ARCH}
    elif [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP5)') ]]; then
        OS_SUFFIX=EULER20SP5
        OS_VERSION=euler20_SP3_${OS_ARCH}
    elif [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP8)') ]]; then
        OS_SUFFIX=EULER20SP8
        OS_VERSION=euler20_SP8_${OS_ARCH}
    elif [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP9') ]]; then
        if [ ${OS_ARCH} == "x86_64" ]; then
            OS_SUFFIX=EULER20SP9
            OS_VERSION=euler20_SP9_${OS_ARCH}
        elif [ ${OS_ARCH} == "aarch64" ]; then
            OS_SUFFIX=EULER20SP9
            OS_VERSION=euler20_SP9_${OS_ARCH}
        else
            echo "Unsupported centos System"
            exit 1
        fi
    elif [[ -n $(cat ${EULER_VERSION_PATH} | grep '2.0 (SP10') ]]; then
        if [ ${OS_ARCH} == "x86_64" ]; then
            OS_SUFFIX=EULER20SP10
            OS_VERSION=euler20_SP10_${OS_ARCH}
        elif [ ${OS_ARCH} == "aarch64" ]; then
            OS_SUFFIX=EULER20SP10
            OS_VERSION=euler20_SP10_${OS_ARCH}
        else
            echo "Unsupported centos System"
            exit 1
        fi
    else
        echo "Unsupported centos System"
        exit 1
    fi
elif [[ -f ${CENTOS_VERSION_PATH} ]]; then
    if [ ${OS_ARCH} == "x86_64" ]; then
        OS_SUFFIX=CentOS
        OS_VERSION=redhat72_X86_${ARCH}
    elif [ ${OS_ARCH} == "aarch64" ]; then
        OS_SUFFIX=CentOS
        OS_VERSION=euler20_SP8_${OS_ARCH}
    else
        echo "Unsupported centos System"
        exit 1
    fi
elif [[ -f ${REDHAT_VERSION_PATH} ]]; then
    if [[ -n $(cat ${REDHAT_VERSION_PATH} | grep 'Red Hat') ]]; then
        OS_SUFFIX=REDHAT
        OS_VERSION=redhat72_X86_${ARCH}
    else
        echo "Unsupported centos System"
        exit 1
    fi
elif [[ -f ${OPENEULER_VERSION_PATH} ]]; then
    OS_SUFFIX=OPENEULER
    OS_VERSION=openEuler_${OS_ARCH}
else
    echo "Unsupported OS System"
    exit 1
fi
