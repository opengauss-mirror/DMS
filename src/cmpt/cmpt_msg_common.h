/*
 * Copyright (c) 2022 Huawei Technologies Co.,Ltd.
 *
 * DMS is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * cmpt_msg_common.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_COMMON_H__
#define __CMPT_MSG_COMMON_H__

#include "cm_types.h"
#include "dms_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_MSG_HEAD_UNUSED_SIZE 24
typedef struct st_dms_message_head {
    unsigned int msg_proto_ver;
    unsigned int sw_proto_ver;
    unsigned int cmd;
    unsigned int  flags;
    unsigned long long ruid;
    unsigned char src_inst;
    unsigned char dst_inst;
    unsigned short size;
    unsigned int cluster_ver;
    unsigned short src_sid;
    unsigned short dst_sid;
    unsigned short tickets;
    unsigned short unused;
    union {
        struct {
            long long judge_time; // for message used in reform, check if it is the same round of reform
        };
        struct {
            unsigned long long seq;
        };
        unsigned char reserved[DMS_MSG_HEAD_UNUSED_SIZE]; /* 64 bytes total */
    };
} dms_message_head_t;

typedef enum en_msg_flags {
    MSG_FLAG_DIRTY_PAGE = 0x01,  // sent local dirty page, owner has edp
    MSG_FLAG_REMOTE_DIRTY_PAGE = 0x02,  // sent remote dirty page, owner has edp
    MSG_FLAG_SHARED_PAGE = 0x04,  // sent page is shared copy
    MSG_FLAG_NO_PAGE = 0x08, // requester has shared copy, no page sent
    MSG_FLAG_CEIL = 0x80
} msg_flags_t;

#define DCS_ACK_PAGE_IS_DIRTY(msg) ((((msg)->head->flags & MSG_FLAG_DIRTY_PAGE) != 0) ? CM_TRUE : CM_FALSE)
#define DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg) (((msg)->head->flags & MSG_FLAG_REMOTE_DIRTY_PAGE) ? CM_TRUE : CM_FALSE)

typedef struct st_msg_error {
    dms_message_head_t head;
    int32 code;
} msg_error_t;

typedef struct st_dms_common_ack {
    dms_message_head_t head;
    int32 ret;
} dms_common_ack_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_COMMON_H__