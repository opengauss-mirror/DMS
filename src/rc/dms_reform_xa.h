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
 * dms_reform_proc.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_XA_H__
#define __DMS_REFORM_XA_H__

#include "dms.h"
#include "cm_types.h"
#include "drc_lock.h"
#include "dms_reform_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_proc_xa_rebuild(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_reform_delete_xa_rms(void *db_handle, uint8 undo_seg_id);
int dms_reform_xa_drc_access(void);

#ifdef __cplusplus
}
#endif

#endif