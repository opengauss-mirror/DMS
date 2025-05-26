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
 * cmpt_msg_lock.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_lock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_LOCK_H__
#define __CMPT_MSG_LOCK_H__

#include "cmpt_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(4)
typedef struct st_dms_smon_deadlock_alock_req {
    dms_message_head_t head;
    alockid_t          alockid;
} dms_smon_deadlock_alock_req_t;

typedef struct st_dms_smon_deadlock_alock_rsp {
    dms_message_head_t head;
    uint32 ret_code;
    uint32 data_size;
    char data[0];
} dms_smon_deadlock_alock_rsp_t;
#pragma pack()

typedef struct st_dcs_req_tlock_by_rm {
    uint32 type;
    uint16 sid;
    uint16 rmid;
} dcs_req_tlock_by_rm_t;

typedef struct st_dcs_req_tlock_by_tid {
    char tlock[DMS_SMON_TLOCK_MSG_MAX_LEN];
} dcs_req_tlock_by_tid_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_LOCK_H__