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
#include "mes_interface.h"
#include "dms_process.h"
#include "drc_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_REFORM_MSG_MAX_LENGTH           SIZE_K(32)

typedef struct st_dms_reform_ack_common {
    dms_message_head_t  head;
    int                 result;         // proc result
    uint8               last_fail;      // for ack MSG_REQ_REFORM_PREPARE
    union {
        uint8               dms_status;     // for ack MSG_REQ_DATABASE_STATUS
        uint8               has_ddl_2phase;
    };
    uint8               lock_mode;
    bool8               is_edp;
    uint64              lsn;
    uint64              start_time;
    uint64              bitmap_has_xa;
    uint8               db_is_readwrite;
} dms_reform_ack_common_t;

typedef struct st_dms_reform_req_sync_step {
    dms_message_head_t  head;
    uint64              scn;
    uint64              start_time;
    uint8               last_step;
    uint8               curr_step;
    uint8               next_step;
} dms_reform_req_sync_step_t;
void dms_reform_init_req_sync_step(dms_reform_req_sync_step_t *req);
int dms_reform_req_sync_step_wait(uint64 ruid);
void dms_reform_proc_sync_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_sync_next_step(dms_reform_req_sync_step_t *req, uint8 dst_id);
int dms_reform_req_sync_next_step_wait(uint64 ruid);
void dms_reform_proc_sync_next_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_sync_share_info {
    dms_message_head_t  head;
    share_info_t        share_info;
} dms_reform_req_sync_share_info_t;

typedef struct st_dms_reform_req_sync_xa_owners {
    dms_message_head_t head;
    uint64 bitmap_has_xa;
} dms_reform_req_sync_xa_owners_t;

int dms_reform_init_req_sync_share_info(dms_reform_req_sync_share_info_t *req, uint8 dst_id);
int dms_reform_req_sync_share_info_wait(uint64 ruid);
void dms_reform_proc_sync_share_info(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_partner_status {
    dms_message_head_t  head;
    uint64              lsn;
    driver_ping_info_t driver_ping_info;
} dms_reform_req_partner_status_t;
void dms_reform_init_req_dms_status(dms_reform_req_partner_status_t *req, uint8 dst_id, uint32 sess_id);
int dms_reform_req_dms_status_wait(uint8 *online_status, uint64 *online_times, uint8 *online_rw_status,
    uint8 dst_id, uint64 ruid);
void dms_reform_proc_req_dms_status(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_prepare {
    dms_message_head_t  head;
    bool8               last_fail;
} dms_reform_req_prepare_t;
void dms_reform_init_req_prepare(dms_reform_req_prepare_t *req, uint8 dst_id);
int dms_reform_req_prepare_wait(bool8 *last_fail, int *in_reform, bool8 *has_ddl_2phase, uint64 ruid);
void dms_reform_proc_req_prepare(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_gcv_sync {
    dms_message_head_t  head;
    bool8               pushing;
} dms_reform_req_gcv_sync_t;

typedef struct st_dms_reform_ack_gcv_sync {
    dms_message_head_t  head;
    bool8               updated;
} dms_reform_ack_gcv_sync_t;
void dms_reform_init_req_gcv_sync(dms_reform_req_gcv_sync_t *req, uint8 dst_id, bool8 pushing);
int dms_reform_req_gcv_sync_wait(bool8 *updated, bool8 pushing, uint64 ruid);
void dms_reform_proc_req_gcv_sync(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_migrate {
    dms_message_head_t head;
    uint32 part_id;
    uint32 res_num;
    bool8  is_part_end;
    uint8  res_type;
} dms_reform_req_migrate_t;
int dms_reform_req_migrate_res(migrate_task_t *migrate_task, uint8 type, void *handle, uint32 sess_id);
void dms_reform_proc_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_reform_ack_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result);

typedef struct st_dms_reform_req_rebuild {
    dms_message_head_t head;
    uint32 offset;
} dms_reform_req_rebuild_t;
int dms_reform_req_page_rebuild(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id);
int dms_reform_req_page_rebuild_parallel(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id, uint8 thread_index);
int dms_reform_req_rebuild_lock(msg_command_t cmd, void *lock_res, uint32 append_size, uint8 master_id);
int dms_reform_req_rebuild_lock_parallel(msg_command_t cmd, void *lock_res, uint32 append_size, 
    uint8 master_id, uint8 thread_index);
void dms_reform_proc_req_lock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_lock_validate(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_page_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_page_validate(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_tlock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_tlock_validate(dms_process_context_t *ctx, dms_message_t *receive_msg);

typedef int (*dms_reform_proc_lock_info_rebuild)(void *lock_info, uint8 src_inst);
typedef int (*dms_reform_proc_lock_info_validate)(void *lock_info, uint8 src_inst);
void dms_reform_proc_req_lock_rebuild_base(dms_process_context_t *ctx, dms_message_t *receive_msg, 
    uint32 entry_size, dms_reform_proc_lock_info_rebuild proc);
void dms_reform_proc_req_lock_validate_base(dms_process_context_t *ctx, dms_message_t *receive_msg, 
    uint32 entry_size, dms_reform_proc_lock_info_validate proc); 

enum dms_reform_req_page_action {
    DMS_REQ_CONFIRM_OWNER,
    DMS_REQ_CONFIRM_CONVERTING,
    DMS_REQ_EDP_LSN,
    DMS_REQ_FLUSH_COPY,
    DMS_REQ_NEED_FLUSH,
    DMS_REQ_SET_EDP_TO_OWNER,
};

typedef struct st_dms_reform_req_res {
    dms_message_head_t head;
    uint32 action;
    uint32 sess_id;
    uint64 ruid;
    char resid[DMS_RESID_SIZE];
    uint8 res_type;
    uint64 lsn;
} dms_reform_req_res_t;
void dms_reform_init_req_res(dms_reform_req_res_t *req, uint8 type, char *pageid, uint8 dst_id, uint32 action,
    uint32 sess_id);
int dms_reform_req_page_wait(int *result, uint8 *lock_mode, bool8 *is_edp, uint64 *lsn, uint64 ruid);
void dms_reform_proc_req_page(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

int dms_reform_send_data(dms_message_head_t *msg_head, uint32 sess_id);

typedef struct st_dms_reform_req_switchover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_switchover_t;
void dms_reform_init_req_switchover(dms_reform_req_switchover_t *req, uint8 reformer_id, uint16 sess_id);
int dms_reform_req_switchover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_proc_reform_done_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
int dms_reform_check_reform_done(void);

typedef struct st_dms_reform_ack_map {
    dms_message_head_t head;
    remaster_info_t remaster_info;
} dms_reform_ack_map_t;
void dms_reform_init_map_info_req(dms_message_head_t *head, uint8 dst_id);
int dms_reform_map_info_req_wait(uint64 ruid);
void dms_reform_proc_map_info_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_opengauss_ondemand_redo {
    dms_message_head_t head;
    uint16 len;
} dms_reform_req_opengauss_ondemand_redo_t;
void dms_reform_proc_opengauss_ondemand_redo_buffer(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_reform_ack_req_rebuild(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result);

void dms_reform_set_judge_time(dms_message_head_t *req_head);
bool32 dms_reform_check_judge_time(dms_message_head_t *req_head);

typedef struct st_dms_reform_req_group {
    dms_message_head_t head;
    uint32 offset;
} dms_reform_req_group_t;

void dms_reform_req_group_init(uint8 thread_index);
void dms_reform_req_group_free(uint8 thread_index);
int dms_reform_req_group(msg_command_t cmd, uint8 dst_id, uint8 thread_index, void *data, uint32 data_len);
int dms_reform_req_group_send_rest(uint8 thread_index);

typedef struct st_lsn_validate_item {
    char    pageid[DMS_PAGEID_SIZE];
    uint64  lsn;
    bool8   in_recovery;
} lsn_validate_item_t;
void dms_reform_proc_req_lsn_validate(dms_process_context_t *ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_az_switchover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_az_switchover_t;
void dms_reform_init_req_az_switchover_demote(dms_reform_req_az_switchover_t *req,
    uint8 reformer_id, uint16 sess_id);
int dms_reform_req_az_switchover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_az_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

typedef struct st_dms_reform_req_az_failover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_az_failover_t;
void dms_reform_init_req_az_failover(dms_reform_req_az_failover_t *req,
    uint8 reformer_id, uint16 sess_id);
int dms_reform_req_az_failover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_az_failover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_MSG_H__ */