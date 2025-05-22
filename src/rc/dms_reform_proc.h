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
int dms_reform_proc_lock_rebuild(void *resid, uint8 len, uint8 type, uint8 lock_mode, uint8 src_inst);
int dms_reform_proc_page_rebuild(dms_ctrl_info_t *ctrl_info, uint8 inst_id);
bool32 dms_reform_version_same(version_info_t *v1, version_info_t *v2);
void dms_reform_next_step(void);
void dms_reform_migrate_collect_local_task(migrate_info_t *local_migrate_info);
int dms_reform_migrate_inner(migrate_task_t *migrate_task, void *handle, uint32 sess_id);
void dms_reform_recovery_set_flag_by_part(drc_part_list_t *part);
void dms_reform_rebuild_buffer_init(uint8 thread_index);
void dms_reform_rebuild_buffer_free(void *handle, uint8 thread_index);
int dms_reform_rebuild_lock(uint32 sess_id, uint8 thread_index, uint8 thread_num);
char *dms_reform_get_step_desc(uint32 step);
int dms_reform_rebuild_xa_res(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num);
int dms_reform_undo_init(instance_list_t *list);
int dms_reform_tx_area_init(instance_list_t *list);
int dms_reform_tx_area_load(instance_list_t *list);
int dms_reform_tx_rollback_start(instance_list_t *list);
int dms_reform_full_clean(void);
int dms_reform_migrate(void);
int dms_reform_rebuild(void);
int dms_reform_remaster(void);
void dms_reform_remaster_inner(void);
int dms_reform_rebuild_inner(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num);
int drc_get_lock_remaster_id(void *lock_id, uint8 len, uint8 *master_id);
void dms_rebuild_assist_list_init(void);
bool8 dms_reform_rebuild_set_type(drc_page_t *drc_page, reform_assist_list_type_e type);
int dms_reform_repair_by_partid(uint8 thread_index, uint16 part_id);
int dms_reform_repair(void);
void dms_reform_rebuild_add_to_flush_copy(drc_page_t *drc_page);
void dms_reform_rebuild_del_from_flush_copy(drc_page_t *drc_page);

typedef struct st_repair_item {
    char        page_id[DMS_PAGEID_SIZE];
    uint32      action;
} repair_item_t;

#ifdef __cplusplus
}
#endif

#endif /* __DMS_REFORM_PROC_H__ */