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
 * dcs_page.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_page.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCS_PAGE_H__
#define __DCS_PAGE_H__

#include "cm_types.h"
#include "drc.h"
#include "dcs_msg.h"
#include "dms_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCS_RESEND_MSG_INTERVAL (5)  // unit: ms
#define DCS_WAIT_MSG_TIMEOUT (5000)   // unit: ms
#define DCS_CR_REQ_TIMEOUT (10000) // unit: ms
#define DCS_RLS_PAGE_OWN_INTERVAL (10)

#define DCS_INSTID_VALID(instid) ((instid) != CM_INVALID_ID8)

typedef struct st_msg_page_batch_op {
    dms_message_head_t head;
    uint32 count;
    atomic_t lsn;
    uint64 scn;
} msg_page_batch_op_t;

void dcs_proc_try_ask_master_for_page_owner_id(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_release_owner_req(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_ask_remote_for_edp(dms_process_context_t *ctx, dms_message_t *receive_msg);
void dcs_proc_release_owner_batch_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
int dcs_owner_transfer_page(dms_process_context_t *ctx, dms_res_req_info_t *req_info);

int32 dcs_handle_ack_need_load(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dcs_handle_ack_already_owner(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dcs_handle_ack_page_ready(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint32 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dcs_handle_ack_edp_local(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dcs_handle_ack_edp_remote(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dcs_handle_ask_edp_remote(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 remote_id, dms_lock_mode_t req_mode);
int dcs_send_requester_edp_remote(dms_process_context_t *ctx, dms_ask_res_req_t *page_req,
    drc_req_owner_result_t *result);
void dcs_send_requester_edp_local(dms_process_context_t *ctx, dms_ask_res_req_t *page_req);

#ifdef __cplusplus
}
#endif

#endif /* __DCS_PAGE_H__ */

