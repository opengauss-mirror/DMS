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
 * dcs_ckpt.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_ckpt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DCS_CKPT_H__
#define __DCS_CKPT_H__

#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

void dcs_proc_master_ckpt_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dcs_proc_owner_ckpt_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dcs_proc_master_clean_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dcs_proc_owner_clean_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif
#endif
