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
#include "cmpt_msg_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_REFORM_MSG_MAX_LENGTH           SIZE_K(32)

void dms_reform_init_req_sync_step(dms_reform_req_sync_step_t *req);
int dms_reform_req_sync_step_wait(uint64 ruid);
void dms_reform_proc_sync_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_sync_next_step(dms_reform_req_sync_step_t *req, uint8 dst_id);
int dms_reform_req_sync_next_step_wait(uint64 ruid);
void dms_reform_proc_sync_next_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg);


int dms_reform_init_req_sync_share_info(dms_reform_req_sync_share_info_t *req, uint8 dst_id);
int dms_reform_req_sync_share_info_wait(uint64 ruid);
void dms_reform_proc_sync_share_info(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_dms_status(dms_reform_req_partner_status_t *req, uint8 dst_id, uint32 sess_id);
int dms_reform_req_dms_status_wait(uint8 dst_id, uint64 ruid, online_status_t *online_info);
void dms_reform_proc_req_dms_status(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_prepare(dms_reform_req_prepare_t *req, uint8 dst_id);
int dms_reform_req_prepare_wait(bool8 *last_fail, int *in_reform, bool8 *has_ddl_2phase, uint64 ruid);
void dms_reform_proc_req_prepare(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_gcv_sync(dms_reform_req_gcv_sync_t *req, uint8 dst_id, bool8 pushing);
int dms_reform_req_gcv_sync_wait(bool8 *updated, bool8 pushing, uint64 ruid);
void dms_reform_proc_req_gcv_sync(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

int dms_reform_req_migrate_res(migrate_task_t *migrate_task, uint8 type, void *handle, uint32 sess_id);
void dms_reform_proc_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_reform_ack_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result);

int dms_reform_req_page_rebuild(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id);
int dms_reform_req_page_rebuild_parallel(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id, uint8 thread_index);
int dms_reform_req_rebuild_lock(msg_command_t cmd, void *lock_res, uint32 append_size, uint8 master_id);
int dms_reform_req_rebuild_lock_parallel(msg_command_t cmd, void *lock_res, uint32 append_size, 
    uint8 master_id, uint8 thread_index);
void dms_reform_proc_req_lock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_page_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dms_reform_proc_req_tlock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);

typedef int (*dms_reform_proc_lock_info_rebuild)(void *lock_info, uint8 src_inst);
void dms_reform_proc_req_lock_rebuild_base(dms_process_context_t *ctx, dms_message_t *receive_msg, 
    uint32 entry_size, dms_reform_proc_lock_info_rebuild proc);

void dms_reform_proc_req_page(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
int dms_reform_send_data(dms_message_head_t *msg_head, uint32 sess_id);

void dms_reform_init_req_switchover(dms_reform_req_switchover_t *req, uint8 reformer_id, uint16 sess_id);
int dms_reform_req_switchover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_proc_reform_done_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
int dms_reform_check_reform_done(void);

void dms_reform_init_map_info_req(dms_message_head_t *head, uint8 dst_id);
int dms_reform_map_info_req_wait(uint64 ruid);
void dms_reform_proc_map_info_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_proc_opengauss_ondemand_redo_buffer(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_reform_ack_req_rebuild(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result);

void dms_reform_set_judge_time(dms_message_head_t *req_head);
bool32 dms_reform_check_judge_time(dms_message_head_t *req_head);

void dms_reform_req_group_init(uint8 thread_index);
void dms_reform_req_group_free(uint8 thread_index);
int dms_reform_req_group(msg_command_t cmd, uint8 dst_id, uint8 thread_index, void *data, uint32 data_len);
int dms_reform_req_group_send_rest(uint8 thread_index);

void dms_reform_init_req_az_switchover_demote(dms_reform_req_az_switchover_t *req,
    uint8 reformer_id, uint16 sess_id);
int dms_reform_req_az_switchover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_az_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_init_req_az_failover(dms_reform_req_az_failover_t *req,
    uint8 reformer_id, uint16 sess_id);
int dms_reform_req_az_failover_wait(uint64 ruid, uint64 *start_time);
void dms_reform_proc_req_az_failover(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

void dms_reform_proc_repair(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_MSG_H__ */