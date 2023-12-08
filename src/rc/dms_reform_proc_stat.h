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
 * dms_reform_proc_stat.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc_stat.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_PROC_STAT_H__
#define __DMS_REFORM_PROC_STAT_H__

#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_dms_reform_proc_stat {
    DRPS_BASE = DMS_REFORM_STEP_COUNT - 1,
    DRPS_DISCONNECT_GET_LOCK,
    DRPS_DRC_CLEAN_NO_OWNER,
    DRPS_DRC_CLEAN_NO_CVT,
    DRPS_DRC_CLEAN_CONFIRM_COPY,
    DRPS_DRC_CLEAN_OWNER_CVT_FAULT,
    DRPS_DRC_CLEAN_CONFIRM_OWNER,
    DRPS_DRC_CLEAN_CONFIRM_CVT,
    DRPS_DRC_CLEAN_PAGE,
    DRPS_DRC_CLEAN_LOCK,
    DRPS_DRC_CLEAN_XA,
    DRPS_DRC_REBUILD_PAGE,
    DRPS_DRC_REBUILD_PAGE_LOCAL,
    DRPS_DRC_REBUILD_PAGE_REMOTE,
    DRPS_DRC_REBUILD_PAGE_REMOTE_REST,
    DRPS_DRC_REBUILD_LOCK,
    DRPS_DRC_REBUILD_LOCK_RES,
    DRPS_DRC_REBUILD_LOCK_LOCAL,
    DRPS_DRC_REBUILD_LOCK_REMOTE,
    DRPS_DRC_REBUILD_LOCK_REMOTE_REST,
    DRPS_DRC_REBUILD_XA,
    DRPS_DRC_REBUILD_XA_LOCAL,
    DRPS_DRC_REBUILD_XA_REMOTE,
    DRPS_DRC_REBUILD_XA_REMOTE_REST,
    DRPS_DRC_MIGRATE_PAGE,
    DRPS_DRC_MIGRATE_LOCK,
    DRPS_DRC_MIGRATE_XA,
    DRPS_DRC_REPAIR_NEED_FLUSH,
    DRPS_DRC_REPAIR_NEED_NOT_FLUSH,
    DRPS_DRC_REPAIR_WITH_COPY,
    DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH,
    DRPS_DRC_REPAIR_WITH_LAST_EDP,
    DRPS_DRC_REPAIR_WITH_EDP_MAP,
    DRPS_DRC_REPAIR_PAGE,
    DRPS_DRC_REPAIR_LOCK,
    DRPS_DRC_FLUSH_COPY_LOCAL,
    DRPS_DRC_FLUSH_COPY_REMOTE,
    DRPS_DRC_EDP_TO_OWNER_LOCAL,
    DRPS_DRC_EDP_TO_OWNER_REMOTE,
    DRPS_TXN_DEPOSIT_DELETE_XA,
    DRPS_ROLLBACK_UNDO_INIT,
    DRPS_ROLLBACK_TX_AREA_INIT,
    DRPS_ROLLBACK_TX_AREA_LOAD,
    DRPS_ROLLBACK_CVT_TO_RW,
    DRPS_REFORM,

    /* add new item above */
    DRPS_COUNT
} dms_reform_proc_stat_e;

typedef struct st_dms_reform_proc_stat_item {
    uint64          start_time;
    uint64          total_time;
    uint64          max_time;
    uint64          times;
} drps_item_t;

typedef struct st_dms_reform_proc_stat_items {
    drps_item_t     drps_item[DRPS_COUNT];
} drps_items_t;

typedef struct st_dms_reform_proc_stat {
    drps_items_t    items_total;
    drps_items_t    items_proc;
    drps_items_t    items_proc_parallel[DMS_PARALLEL_MAX_THREAD];
} drps_t;

typedef struct st_dms_reform_proc_stat_desc {
    uint32          item;
    uint32          level;
    char            desc[CM_BUFLEN_32];
} drps_desc_t;

typedef enum en_drps_level {
    DRPS_LEVEL_TOP = 0,
    DRPS_LEVEL_ONE,
    DRPS_LEVEL_TWO,
    DRPS_LEVEL_THREE,

    DRPS_LEVEL_COUNT
} drps_level_e;

typedef struct st_drps_level_format {
    char        format[CM_BUFLEN_64];
} drps_level_format_t;

void dms_reform_proc_stat_start(uint32 item);
void dms_reform_proc_stat_end(uint32 item);
void dms_reform_proc_stat_times(uint32 item);
void dms_reform_proc_stat_bind_proc(void);
void dms_reform_proc_stat_bind_proc_parallel(uint32 index);
void dms_reform_proc_stat_clear_total(void);
void dms_reform_proc_stat_clear_current(void);
void dms_reform_proc_stat_collect_total(void);
void dms_reform_proc_stat_collect_current(void);
void dms_reform_proc_stat_log_total(void);
void dms_reform_proc_stat_log_current(void);

#ifdef __cplusplus
}
#endif
#endif