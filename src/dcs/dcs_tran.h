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
 * dcs_tran.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_tran.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCS_TRAN_H__
#define __DCS_TRAN_H__

#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

void dcs_proc_opengauss_lock_buffer_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_txn_status_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_update_xid_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_xid_csn_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_txn_snapshot_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_txn_of_master_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_txn_info_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_txn_snapshot_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_txn_wait_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_txn_awake_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dcs_proc_opengauss_page_status_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);

#ifdef __cplusplus
}
#endif
#endif
