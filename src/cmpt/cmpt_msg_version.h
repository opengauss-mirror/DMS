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
 * cmpt_msg_version.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_version.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_VERSION_H__
#define __CMPT_MSG_VERSION_H__

#include "cmpt_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum st_dms_protocol_version {
    DMS_PROTO_VER_0 = 0,    // invalid version
    DMS_PROTO_VER_1 = 1,    // first version
    DMS_PROTO_VER_2 = 2,
    DMS_PROTO_VER_3 = 3,    // add MSG_REQ_OPENGAUSS_IMMEDIATE_CKPT, MSG_ACK_OPENGAUSS_IMMEDIATE_CKPT
    DMS_PROTO_VER_4 = 4,    // add reform step
    DMS_PROTO_VER_5 = 5,    // BCM 1.11.0: add DRM; change DRC hash from single to group hash
    DMS_PROTO_VER_NUMS
} dms_protocol_version_t;

#define DMS_INVALID_PROTO_VER DMS_PROTO_VER_0
#define DMS_SW_PROTO_VER      DMS_PROTO_VER_5

typedef enum en_dms_protocol_result {
    DMS_PROTOCOL_VERSION_NOT_MATCH = 0,
    DMS_PROTOCOL_VERSION_NOT_SUPPORT = 1,
} dms_protocol_result_e;

typedef struct st_dms_protocol_result_ack {
    dms_message_head_t head;
    dms_protocol_result_e result;
} dms_protocol_result_ack_t;

typedef struct st_dms_proto_version_attr {
    uint32 req_size;
} dms_proto_version_attr;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_VERSION_H__