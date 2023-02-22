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
int dms_reform_rebuild_buf_res(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num);
int dms_reform_rebuild_buf_res_inner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty,
    uint8 master_id, uint8 thread_index);
int dms_reform_rebuild_lock_l(drc_local_lock_res_t *lock_res, uint8 src_inst);
int dms_reform_rebuild_buf_res_l(char *resid, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty, uint8 inst_id);
bool8 dms_reform_res_need_rebuild(uint8 master_id);
bool32 dms_reform_version_same(version_info_t *v1, version_info_t *v2);
void dms_reform_next_step(void);
int dms_reform_reconnect_channel(uint8 inst_id, uint32 index, uint32 sess_id);
int dms_reform_clean_buf_res_by_part(bilist_t *part_list, uint32 sess_id);
void dms_reform_migrate_collect_local_task(migrate_info_t *local_migrate_info);
int dms_reform_migrate_inner(migrate_task_t *migrate_task, void *handle, uint32 sess_id);
int dms_reform_repair_by_part(bilist_t *part_list, void *handle, uint32 sess_id);
void dms_reform_recovery_set_flag_by_part(bilist_t *part_list);
int dms_reform_flush_copy_by_part(bilist_t *part_list, void *handle, uint32 sess_id);
void dms_reform_rebuild_buffer_init(uint8 thread_index);
void dms_reform_rebuild_buffer_free(void *handle, uint8 thread_index);
int dms_reform_rebuild_lock(uint32 sess_id, uint8 thread_index, uint8 thread_num);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_PROC_H__ */