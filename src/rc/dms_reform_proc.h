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

#ifndef __DMS_REFORM_PROC_H__
#define __DMS_REFORM_PROC_H__

#include "dms.h"
#include "cm_types.h"
#include "drc_lock.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_proc_thread(thread_t *thread);
int dms_reform_rebuild_buf_res_inner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty,
    uint8 master_id);
int dms_reform_rebuild_lock_l(drc_local_lock_res_t *lock_res, uint8 src_inst);
int dms_reform_rebuild_buf_res_l(char *resid, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty, uint8 inst_id);
void dms_reform_display_buf(drc_buf_res_t *buf_res, const char *desc);
bool8 dms_reform_res_need_rebuild(uint8 master_id);
bool32 dms_reform_version_same(version_info_t *v1, version_info_t *v2);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_PROC_H__ */