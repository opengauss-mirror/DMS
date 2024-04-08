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
 * dcs_smon.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_smon.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef DCS_SMON_H
#define DCS_SMON_H

#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dcs_req_tlock_by_rm {
    uint32 type;
    uint16 sid;
    uint16 rmid;
} dcs_req_tlock_by_rm_t;

typedef struct st_dcs_req_tlock_by_tid {
    char tlock[DMS_SMON_TLOCK_MSG_MAX_LEN];
} dcs_req_tlock_by_tid_t;

void dcs_proc_smon_dlock_msg(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_process_get_itl_lock(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_smon_deadlock_sql(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_smon_broadcast_req(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_smon_tlock_by_rm(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_smon_tlock_by_tid(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_smon_alock_by_drid(dms_process_context_t *ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif
#endif