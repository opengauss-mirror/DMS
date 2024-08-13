#!/bin/bash
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