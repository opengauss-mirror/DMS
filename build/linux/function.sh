#!/bin/bash
# Copyright (c) 2026 Huawei Technologies Co., Ltd.
# DMS is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -e

func_prepare_git_msg()
{
    git_id=$(git rev-parse --short HEAD)
    WHOLE_COMMIT_ID=$(git rev-parse HEAD)
    merge_time=$(git log | grep Date | sed -n '1p' | sed 's/^Date:\s*//g')
    cat /dev/null > $BUILD_DIR/conf/git_message.in
    echo "git_id=${git_id}" >> $BUILD_DIR/conf/git_message.in
    echo "gitVersion=${WHOLE_COMMIT_ID}" >> $BUILD_DIR/conf/git_message.in
    echo "merge_time=${merge_time}" >> $BUILD_DIR/conf/git_message.in
}