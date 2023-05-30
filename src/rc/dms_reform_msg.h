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
 * dms_reform_msg.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_msg.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_MSG_H__
#define __DMS_REFORM_MSG_H__

#include "dms.h"
#include "mes_type.h"
#include "dms_process.h"
#include "drc_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_REFORM_MSG_MAX_LENGTH           SIZE_K(32)

typedef struct st_dms_reform_ack_common {
    mes_message_head_t  head;
    int                 result;         // proc result
    uint8               last_fail;      // for ack MSG_REQ_REFORM_PREPARE
    uint8               dms_status;     // for ack MSG_REQ_DATABASE_STATUS
    uint8               lock_mode;
    bool8               is_edp;
    uint64              lsn;
    uint64              start_time;
} dms_reform_ack_common_t;

typedef struct st_dms_reform_req_sync_step {
    mes_message_head_t  head;
    uint64              scn;
    uint64              start_time;
    uint8               last_step;
    uint8               curr_step;
    uint8               next_step;
} dms_reform_req_sync_step_t;
void dms_reform_init_req_sync_step(dms_reform_req_sync_step_t *req);
int dms_reform_req_sync_step_wait(void);
void dms_reform_proc_sync_step(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

void dms_reform_init_req_sync_next_step(dms_reform_req_sync_step_t *req, uint8 dst_id);
int dms_reform_req_sync_next_step_wait(void);
void dms_reform_proc_sync_next_step(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_sync_share_info {
    mes_message_head_t  head;
    share_info_t        share_info;
} dms_reform_req_sync_share_info_t;
void dms_reform_init_req_sync_share_info(dms_reform_req_sync_share_info_t *req, uint8 dst_id);
int dms_reform_req_sync_share_info_wait(void);
void dms_reform_proc_sync_share_info(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_partner_status {
    mes_message_head_t  head;
    uint64              lsn;
} dms_reform_req_partner_status_t;
void dms_reform_init_req_dms_status(dms_reform_req_partner_status_t *req, uint8 dst_id, uint32 sess_id);
int dms_reform_req_dms_status_wait(uint8 *online_status, uint64 *online_times, uint8 dst_id, uint32 sess_id);
void dms_reform_proc_req_dms_status(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_prepare {
    mes_message_head_t  head;
    bool8               last_fail;
} dms_reform_req_prepare_t;
void dms_reform_init_req_prepare(dms_reform_req_prepare_t *req, uint8 dst_id);
int dms_reform_req_prepare_wait(bool8 *last_fail, int *in_reform);
void dms_reform_proc_req_prepare(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_gcv_sync {
    mes_message_head_t  head;
    bool8               pushing;
} dms_reform_req_gcv_sync_t;

typedef struct st_dms_reform_ack_gcv_sync {
    mes_message_head_t  head;
    bool8               updated;
} dms_reform_ack_gcv_sync_t;
void dms_reform_init_req_gcv_sync(dms_reform_req_gcv_sync_t *req, uint8 dst_id, bool8 pushing);
int dms_reform_req_gcv_sync_wait(bool8 *updated, bool8 pushing);
void dms_reform_proc_req_gcv_sync(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_migrate {
    mes_message_head_t head;
    uint32 part_id;
    uint32 res_num;
    bool8  is_part_end;
    uint8  res_type;
} dms_reform_req_migrate_t;
int dms_reform_req_migrate_res(migrate_task_t *migrate_task, uint8 type, void *handle, uint32 sess_id);
void dms_reform_proc_req_migrate(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_rebuild {
    mes_message_head_t head;
    uint32 offset;
} dms_reform_req_rebuild_t;
int dms_reform_req_page_rebuild(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, uint8 master_id, bool8 rebuild);
int dms_reform_req_page_rebuild_parallel(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, uint8 master_id,
    uint8 thread_index, bool8 rebuild);
int dms_reform_req_rebuild_lock(const drc_local_lock_res_t *lock_res, uint8 master_id);
int dms_reform_req_rebuild_lock_parallel(const drc_local_lock_res_t *lock_res, uint8 master_id, uint8 thread_index);
void dms_reform_proc_req_lock_rebuild(dms_process_context_t *ctx, mes_message_t *receive_msg);
void dms_reform_proc_req_page_rebuild(dms_process_context_t *ctx, mes_message_t *receive_msg);
void dms_reform_proc_req_page_validate(dms_process_context_t *ctx, mes_message_t *receive_msg);

enum dms_reform_req_page_action {
    DMS_REQ_CONFIRM_OWNER,
    DMS_REQ_CONFIRM_CONVERTING,
    DMS_REQ_EDP_LSN,
    DMS_REQ_FLUSH_COPY,
    DMS_REQ_NEED_FLUSH,
};

typedef struct st_dms_reform_req_res {
    mes_message_head_t head;
    uint32 action;
    uint32 sess_id;
    uint64 rsn;
    char resid[DMS_RESID_SIZE];
    uint8 res_type;
} dms_reform_req_res_t;
void dms_reform_init_req_res(dms_reform_req_res_t *req, uint8 type, char *pageid, uint8 dst_id, uint32 action,
    uint32 sess_id);
int dms_reform_req_page_wait(int *result, uint8 *lock_mode, bool8 *is_edp, uint64 *lsn, uint32 sess_id);
void dms_reform_proc_req_page(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

int dms_reform_send_data(mes_message_head_t *msg_head, uint32 sess_id);

typedef struct st_dms_reform_req_switchover {
    mes_message_head_t head;
    uint64 start_time;
} dms_reform_req_switchover_t;
void dms_reform_init_req_switchover(dms_reform_req_switchover_t *req, uint8 reformer_id, uint16 sess_id);
int dms_reform_req_switchover_wait(uint16 sess_id, uint64 *start_time);
void dms_reform_proc_req_switchover(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

void dms_reform_proc_reform_done_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
int dms_reform_check_reform_done(void);

typedef struct st_dms_reform_ack_map {
    mes_message_head_t head;
    remaster_info_t remaster_info;
} dms_reform_ack_map_t;
void dms_reform_init_map_info_req(mes_message_head_t *head, uint8 dst_id);
int dms_reform_map_info_req_wait(void);
void dms_reform_proc_map_info_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

typedef struct st_dms_reform_req_opengauss_ondemand_redo {
    mes_message_head_t head;
    uint16 len;
} dms_reform_req_opengauss_ondemand_redo_t;
void dms_reform_proc_opengauss_ondemand_redo_buffer(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_MSG_H__ */