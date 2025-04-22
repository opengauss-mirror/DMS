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
 * cmpt_msg_pcr.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_pcr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_PCR_H__
#define __CMPT_MSG_PCR_H__

#include "cmpt_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_cr_type {
    CR_TYPE_HEAP,
    CR_TYPE_BTREE,
} cr_type_t;

typedef struct st_msg_pcr_request {
    dms_message_head_t head;
    uint8 cr_type;
    bool8 force_cvt; // force convert
    uint32 ssn;
    uint64 query_scn;
    char pageid[DMS_PAGEID_SIZE];
    char xid[DMS_XID_SIZE];
    dms_session_e sess_type;
} msg_pcr_request_t;

typedef struct st_msg_pcr_ack {
    dms_message_head_t head;
    bool8 force_cvt;
} msg_pcr_ack_t;

typedef struct st_msg_index_pcr_request {
    msg_pcr_request_t pcr_request;
    char entry[DMS_PAGEID_SIZE];
    char profile[DMS_INDEX_PROFILE_SIZE];
} msg_index_pcr_request_t;

typedef struct st_msg_cr_check {
    dms_message_head_t head;
    uint64 query_scn;
    uint32 ssn;
    char xid[DMS_XID_SIZE];
    char rowid[DMS_ROWID_SIZE];
} msg_cr_check_t;

typedef struct st_msg_cr_check_ack {
    dms_message_head_t head;
    bool8 is_found;
} msg_cr_check_ack_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_PCR_H__