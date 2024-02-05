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
 * dms_reform_proc_stat.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc_stat.h"
#include "cm_timer.h"
#include "dms_process.h"
#include "dms_reform_proc.h"

drps_t g_drps;
thread_local_var drps_items_t *g_drps_items = NULL;

void dms_reform_proc_stat_start(uint32 item)
{
    if (g_drps_items == NULL || item >= DRPS_COUNT) {
        return;
    }
    drps_item_t *drps_item = &g_drps_items->drps_item[item];
    drps_item->start_time = (uint64)g_timer()->now;
}

void dms_reform_proc_stat_end(uint32 item)
{
    if (g_drps_items == NULL || item >= DRPS_COUNT) {
        return;
    }
    drps_item_t *drps_item = &g_drps_items->drps_item[item];
    uint64 diff_time = ((uint64)g_timer()->now - drps_item->start_time);
    drps_item->total_time += diff_time;
    drps_item->times++;
    if (diff_time > drps_item->max_time) {
        drps_item->max_time = diff_time;
    }
}

// only used for stating execution times
void dms_reform_proc_stat_times(uint32 item)
{
    if (g_drps_items == NULL || item >= DRPS_COUNT) {
        return;
    }
    drps_item_t *drps_item = &g_drps_items->drps_item[item];
    drps_item->times++;
}

void dms_reform_proc_stat_clear_total(void)
{
    MEMS_RETVOID_IFERR(memset_s(&g_drps, sizeof(g_drps), 0, sizeof(g_drps)));
}

void dms_reform_proc_stat_clear_current(void)
{
    MEMS_RETVOID_IFERR(memset_s(&g_drps.items_proc_total, sizeof(drps_items_t), 0, sizeof(drps_items_t)));
    MEMS_RETVOID_IFERR(memset_s(&g_drps.items_mes_total, sizeof(drps_items_t), 0, sizeof(drps_items_t)));
    uint32 size = sizeof(drps_items_t) * DMS_PARALLEL_MAX_THREAD;
    MEMS_RETVOID_IFERR(memset_s(g_drps.items_proc_parallel, size, 0, size));
    size = sizeof(drps_items_t) * DMS_MAX_WORK_THREAD_CNT;
    MEMS_RETVOID_IFERR(memset_s(g_drps.items_mes_task, size, 0, size));
}

void dms_reform_proc_stat_bind_proc(void)
{
    g_drps_items = &g_drps.items_proc_total;
}

void dms_reform_proc_stat_bind_proc_parallel(uint32 index)
{
    g_drps_items = &g_drps.items_proc_parallel[index];
}

void dms_reform_proc_stat_bind_mes_task(uint32 index)
{
    g_drps_items = &g_drps.items_mes_task[index];
}

static void dms_reform_proc_stat_merge_item(drps_item_t *to_item, drps_item_t *from_item)
{
    to_item->times += from_item->times;
    to_item->total_time += from_item->total_time;
    if (to_item->max_time < from_item->max_time) {
        to_item->max_time = from_item->max_time;
    }
}

static void dms_reform_proc_stat_merge_items(drps_items_t *to_items, drps_items_t *from_items)
{
    for (uint32 i = 0; i < DRPS_COUNT; i++) {
        dms_reform_proc_stat_merge_item(&to_items->drps_item[i], &from_items->drps_item[i]);
    }
}

void dms_reform_proc_stat_collect_current(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;

    if (!reform_info->parallel_enable) {
        return;
    }

    drps_items_t *to_items = &g_drps.items_proc_total;
    drps_items_t *from_items = NULL;
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        from_items = &g_drps.items_proc_parallel[i];
        dms_reform_proc_stat_merge_items(to_items, from_items);
    }

    to_items = &g_drps.items_mes_total;
    for (uint32 i = 0; i < DMS_MAX_WORK_THREAD_CNT; i++) {
        from_items = &g_drps.items_mes_task[i];
        dms_reform_proc_stat_merge_items(to_items, from_items);
    }
}

void dms_reform_proc_stat_collect_total(void)
{
    dms_reform_proc_stat_merge_items(&g_drps.items_total, &g_drps.items_proc_total);
    dms_reform_proc_stat_merge_items(&g_drps.items_total, &g_drps.items_mes_total);
}

drps_desc_t g_mes_drps_desc_t[] = {
    {DRPS_MES_TASK_STAT_CONFIRM_OWNER_PAGE,                     DRPS_LEVEL_TOP,     "CFM_OWNER_PAGE"},
    {DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_OWNER_BUCKET_LOCK,     DRPS_LEVEL_ONE,     "BUCKET_LOCK"},
    {DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_OWNER_GET_DISK_LSN,    DRPS_LEVEL_ONE,     "GET_DISK_LSN"},
    {DRPS_MES_TASK_STAT_CONFIRM_OWNER_LOCK,                     DRPS_LEVEL_TOP,     "CFM_OWNER_LOCK"},
    {DRPS_MES_TASK_STAT_CONFIRM_CVT_PAGE,                       DRPS_LEVEL_TOP,     "CFM_CVT_PAGE"},
    {DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_CVT_BUCKET_LOCK,       DRPS_LEVEL_ONE,     "BUCKET_LOCK"},
    {DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_CVT_SS_READ_LOCK,      DRPS_LEVEL_ONE,     "SS_READ_LOCK"},
    {DRPS_MES_TASK_STAT_CONFIRM_CVT_LOCK,                       DRPS_LEVEL_TOP,     "CFM_CVT_LOCK"},
    {DRPS_MES_TASK_STAT_NEED_FLUSH,                             DRPS_LEVEL_TOP,     "NEED_FLUSH"},
    {DRPS_CALLBACK_MES_TASK_STAT_NEED_FLUSH_ALLOC_CTRL,         DRPS_LEVEL_ONE,     "ALLOC_CTRL"},
    {DRPS_CALLBACK_MES_TASK_STAT_NEED_FLUSH_SS_READ_LOCK,       DRPS_LEVEL_ONE,     "SS_READ_LOCK"},
    {DRPS_MES_TASK_STAT_EDP_TO_OWNER,                           DRPS_LEVEL_TOP,     "EDP_TO_OWNER"},
    {DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_GET_DISK_LSN,     DRPS_LEVEL_ONE,     "GET_DISK_LSN"},
    {DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_ALLOC_CTRL,       DRPS_LEVEL_ONE,     "ALLOC_CTRL"},
    {DRPS_MES_TASK_STAT_VALIDATE_LSN,                           DRPS_LEVEL_TOP,     "VALIDATE_LSN"},
    {DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL,         DRPS_LEVEL_ONE,     "GET_CTRL"},
    {DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL_TIMEOUT, DRPS_LEVEL_ONE,     "GET_CTRL_TIMEOUT"},
    {DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_DISK_LSN,     DRPS_LEVEL_ONE,     "GET_DISK_LSN"},
    {DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_BUF_UNLATCH,      DRPS_LEVEL_ONE,     "BUF_UNLATCH"},
};

drps_desc_t g_drps_desc_t[] = {
    {DMS_REFORM_STEP_PREPARE,                                   DRPS_LEVEL_TOP,     "PREPARE"},
    {DMS_REFORM_STEP_DISCONNECT,                                DRPS_LEVEL_TOP,     "DISCONNECT"},
    {DRPS_DISCONNECT_GET_LOCK,                                  DRPS_LEVEL_ONE,     "GET LOCK"},
    {DMS_REFORM_STEP_RECONNECT,                                 DRPS_LEVEL_TOP,     "RECONNECT"},
    {DMS_REFORM_STEP_START,                                     DRPS_LEVEL_TOP,     "START"},
    {DMS_REFORM_STEP_SWITCHOVER_DEMOTE,                         DRPS_LEVEL_TOP,     "DEMOTE"},
    {DMS_REFORM_STEP_DRC_INACCESS,                              DRPS_LEVEL_TOP,     "DRC_INACCESS"},
    {DMS_REFORM_STEP_LOCK_INSTANCE,                             DRPS_LEVEL_TOP,     "LOCK_INSTANCE"},
    {DMS_REFORM_STEP_DRC_CLEAN,                                 DRPS_LEVEL_TOP,     "DRC_CLEAN"},
    {DRPS_DRC_CLEAN_TIMEOUT,                                    DRPS_LEVEL_ONE,     "ACK TIMEOUT"},
    {DRPS_DRC_CLEAN_PAGE,                                       DRPS_LEVEL_ONE,     "PAGE"},
    {DRPS_DRC_CLEAN_PAGE_NO_OWNER,                              DRPS_LEVEL_TWO,     "NO_OWNER"},
    {DRPS_DRC_CLEAN_PAGE_NO_CVT,                                DRPS_LEVEL_TWO,     "NO_CVT"},
    {DRPS_DRC_CLEAN_PAGE_CONFIRM_COPY,                          DRPS_LEVEL_TWO,     "CONFIRM_COPY"},
    {DRPS_DRC_CLEAN_PAGE_OWNER_CVT_FAULT,                       DRPS_LEVEL_TWO,     "BOTH_FAULT"},
    {DRPS_DRC_CLEAN_PAGE_CONFIRM_OWNER,                         DRPS_LEVEL_TWO,     "CONFIRM_OWNER"},
    {DRPS_DRC_CLEAN_PAGE_CONFIRM_CVT,                           DRPS_LEVEL_TWO,     "CONFIRM_CVT"},
    {DRPS_DRC_CLEAN_LOCK,                                       DRPS_LEVEL_ONE,     "LOCK"},
    {DRPS_DRC_CLEAN_LOCK_NO_OWNER,                              DRPS_LEVEL_TWO,     "NO_OWNER"},
    {DRPS_DRC_CLEAN_LOCK_NO_CVT,                                DRPS_LEVEL_TWO,     "NO_CVT"},
    {DRPS_DRC_CLEAN_LOCK_CONFIRM_COPY,                          DRPS_LEVEL_TWO,     "CONFIRM_COPY"},
    {DRPS_DRC_CLEAN_LOCK_OWNER_CVT_FAULT,                       DRPS_LEVEL_TWO,     "BOTH_FAULT"},
    {DRPS_DRC_CLEAN_LOCK_CONFIRM_OWNER,                         DRPS_LEVEL_TWO,     "CONFIRM_OWNER"},
    {DRPS_DRC_CLEAN_LOCK_CONFIRM_CVT,                           DRPS_LEVEL_TWO,     "CONFIRM_CVT"},
    {DRPS_DRC_CLEAN_XA,                                         DRPS_LEVEL_ONE,     "XA"},
    {DMS_REFORM_STEP_REBUILD,                                   DRPS_LEVEL_TOP,     "REBUILD"},
    {DRPS_DRC_REBUILD_PAGE,                                     DRPS_LEVEL_ONE,     "PAGE"},
    {DRPS_CALLBACK_STAT_CKPT_LATCH,                             DRPS_LEVEL_TWO,     "CKPT_LATCH"},
    {DRPS_CALLBACK_STAT_BUCKET_LOCK,                            DRPS_LEVEL_TWO,     "BUCKET_LOCK"},
    {DRPS_CALLBACK_STAT_SS_READ_LOCK,                           DRPS_LEVEL_TWO,     "SS_READ_LOCK"},
    {DRPS_CALLBACK_STAT_GET_DISK_LSN,                           DRPS_LEVEL_TWO,     "GET_DISK_LSN"},
    {DRPS_CALLBACK_STAT_DRC_EXIST,                              DRPS_LEVEL_TWO,     "DRC_EXIST"},
    {DRPS_CALLBACK_STAT_CLEAN_EDP,                              DRPS_LEVEL_TWO,     "CLEAN_EDP"},
    {DRPS_CALLBACK_STAT_NEED_NOT_REBUILD,                       DRPS_LEVEL_TWO,     "NEED_NOT"},
    {DRPS_CALLBACK_STAT_EXPIRE,                                 DRPS_LEVEL_TWO,     "EXPIRE"},
    {DRPS_DRC_REBUILD_PAGE_LOCAL,                               DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_DRC_REBUILD_PAGE_REMOTE,                              DRPS_LEVEL_TWO,     "REMOTE"},
    {DRPS_DRC_REBUILD_PAGE_REMOTE_REST,                         DRPS_LEVEL_TWO,     "REMOTE_REST"},
    {DRPS_DRC_REBUILD_LOCK,                                     DRPS_LEVEL_ONE,     "LOCK"},
    {DRPS_DRC_REBUILD_LOCK_RES,                                 DRPS_LEVEL_TWO,     "LOCAL RES"},
    {DRPS_DRC_REBUILD_LOCK_LOCAL,                               DRPS_LEVEL_THREE,   "LOCAL"},
    {DRPS_DRC_REBUILD_LOCK_REMOTE,                              DRPS_LEVEL_THREE,   "REMOTE"},
    {DRPS_DRC_REBUILD_LOCK_REMOTE_REST,                         DRPS_LEVEL_TWO,     "REMOTE_REST"},
    {DRPS_DRC_REBUILD_XA,                                       DRPS_LEVEL_ONE,     "XA"},
    {DRPS_DRC_REBUILD_XA_LOCAL,                                 DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_DRC_REBUILD_XA_REMOTE,                                DRPS_LEVEL_TWO,     "REMOTE"},
    {DRPS_DRC_REBUILD_XA_REMOTE_REST,                           DRPS_LEVEL_TWO,     "REMOTE_REST"},
    {DMS_REFORM_STEP_REMASTER,                                  DRPS_LEVEL_TOP,     "REMASTER"},
    {DMS_REFORM_STEP_MIGRATE,                                   DRPS_LEVEL_TOP,     "MIGRATE"},
    {DRPS_DRC_MIGRATE_PAGE,                                     DRPS_LEVEL_ONE,     "PAGE"},
    {DRPS_DRC_MIGRATE_LOCK,                                     DRPS_LEVEL_ONE,     "LOCK"},
    {DRPS_DRC_MIGRATE_XA,                                       DRPS_LEVEL_ONE,     "XA"},
    {DMS_REFORM_STEP_REPAIR,                                    DRPS_LEVEL_TOP,     "REPAIR"},
    {DRPS_DRC_REPAIR_TIMEOUT,                                   DRPS_LEVEL_ONE,     "ACK TIMEOUT"},
    {DRPS_DRC_REPAIR_PAGE,                                      DRPS_LEVEL_ONE,     "PAGE"},
    {DRPS_DRC_REPAIR_PAGE_NEED_FLUSH,                           DRPS_LEVEL_TWO,     "NEED_FLUSH"},
    {DRPS_DRC_REPAIR_PAGE_NEED_NOT_FLUSH,                       DRPS_LEVEL_TWO,     "NOT_FLUSH"},
    {DRPS_DRC_REPAIR_PAGE_WITH_COPY,                            DRPS_LEVEL_TWO,     "WITH_COPY"},
    {DRPS_DRC_REPAIR_PAGE_WITH_COPY_NEED_FLUSH,                 DRPS_LEVEL_THREE,   "COPY_NEED_FLUSH"},
    {DRPS_DRC_REPAIR_PAGE_WITH_LAST_EDP,                        DRPS_LEVEL_TWO,     "WITH_LAST_EDP"},
    {DRPS_DRC_REPAIR_PAGE_WITH_EDP_MAP,                         DRPS_LEVEL_TWO,     "WITH_EDP_MAP"},
    {DRPS_DRC_REPAIR_PAGE_WITH_EDP_MAP_GET_LSN,                 DRPS_LEVEL_THREE,   "GET_DISK_LSN"},
    {DRPS_DRC_REPAIR_LOCK,                                      DRPS_LEVEL_ONE,     "LOCK"},
    {DRPS_DRC_REPAIR_LOCK_NEED_FLUSH,                           DRPS_LEVEL_TWO,     "NEED_FLUSH"},
    {DRPS_DRC_REPAIR_LOCK_NEED_NOT_FLUSH,                       DRPS_LEVEL_TWO,     "NOT_FLUSH"},
    {DRPS_DRC_REPAIR_LOCK_WITH_COPY,                            DRPS_LEVEL_TWO,     "WITH_COPY"},
    {DRPS_DRC_REPAIR_LOCK_WITH_COPY_NEED_FLUSH,                 DRPS_LEVEL_THREE,   "COPY_NEED_FLUSH"},
    {DRPS_DRC_REPAIR_LOCK_WITH_LAST_EDP,                        DRPS_LEVEL_TWO,     "WITH_LAST_EDP"},
    {DRPS_DRC_REPAIR_LOCK_WITH_EDP_MAP,                         DRPS_LEVEL_TWO,     "WITH_EDP_MAP"},
    {DRPS_DRC_REPAIR_LOCK_WITH_EDP_MAP_GET_LSN,                 DRPS_LEVEL_THREE,   "GET_DISK_LSN"},
    {DMS_REFORM_STEP_RECOVERY_ANALYSE,                          DRPS_LEVEL_TOP,     "RECOVERY_ANALYSE"},
    {DMS_REFORM_STEP_FLUSH_COPY,                                DRPS_LEVEL_TOP,     "FLUSH_COPY"},
    {DRPS_DRC_FLUSH_COPY_TIMEOUT,                               DRPS_LEVEL_ONE,     "ACK TIMEOUT"},
    {DRPS_DRC_FLUSH_COPY_LOCAL,                                 DRPS_LEVEL_ONE,     "FLUSH_COPY_L"},
    {DRPS_DRC_FLUSH_COPY_REMOTE,                                DRPS_LEVEL_ONE,     "FLUSH_COPY_R"},
    {DRPS_DRC_EDP_TO_OWNER_LOCAL,                               DRPS_LEVEL_ONE,     "EDP_TO_OWNER_L"},
    {DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_GET_DISK_LSN,     DRPS_LEVEL_TWO,     "GET_DISK_LSN"},
    {DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_ALLOC_CTRL,       DRPS_LEVEL_TWO,     "ALLOC_CTRL"},
    {DRPS_DRC_EDP_TO_OWNER_REMOTE,                              DRPS_LEVEL_ONE,     "EDP_TO_OWNER_R"},
    {DRPS_DRC_FLUSH_COPY_VALIDATE_LSN,                          DRPS_LEVEL_ONE,     "VALIDATE_LSN"},
    {DMS_REFORM_STEP_DW_RECOVERY,                               DRPS_LEVEL_TOP,     "DW_RECOVERY"},
    {DMS_REFORM_STEP_DF_RECOVERY,                               DRPS_LEVEL_TOP,     "DF_RECOVERY"},
    {DMS_REFORM_STEP_RESET_USER,                                DRPS_LEVEL_TOP,     "RESET_USER"},
    {DMS_REFORM_STEP_VALIDATE_LOCK_MODE,                        DRPS_LEVEL_TOP,     "VALIDATE_LOCK_MODE"},
    {DRPS_VALIDATE_LOCK_MODE_PAGE,                              DRPS_LEVEL_ONE,     "PAGE"},
    {DRPS_CALLBACK_STAT_VALIDATE_DRC_PAGE_BUCKET_LOCK,          DRPS_LEVEL_TWO,     "BUCKET_LOCK"},
    {DRPS_CALLBACK_STAT_VALIDATE_DRC_PAGE_SS_READ_LOCK,         DRPS_LEVEL_TWO,     "SS_READ_LOCK"},
    {DRPS_VALIDATE_LOCK_MODE_PAGE_LOCAL,                        DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE,                       DRPS_LEVEL_TWO,     "REMOTE"},
    {DRPS_VALIDATE_LOCK_MODE_LOCK,                              DRPS_LEVEL_ONE,     "LOCK"},
    {DRPS_VALIDATE_LOCK_MODE_LOCK_BUCKET_LOCK,                  DRPS_LEVEL_TWO,     "BUCKET_LOCK"},
    {DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL_RES_LOCK,               DRPS_LEVEL_TWO,     "LOCAL_RES_LOCK"},
    {DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL,                        DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE,                       DRPS_LEVEL_TWO,     "REMOTE"},
    {DMS_REFORM_STEP_DRC_ACCESS,                                DRPS_LEVEL_TOP,     "DRC_ACCESS"},
    {DMS_REFORM_STEP_PAGE_ACCESS,                               DRPS_LEVEL_TOP,     "PAGE_ACCESS"},
    {DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS,                DRPS_LEVEL_TOP,     "F_PROMOTE"},
    {DMS_REFORM_STEP_STARTUP_OPENGAUSS,                         DRPS_LEVEL_TOP,     "STARTUP"},
    {DMS_REFORM_STEP_RECOVERY,                                  DRPS_LEVEL_TOP,     "RECOVERY"},
    {DMS_REFORM_STEP_RECOVERY_OPENGAUSS,                        DRPS_LEVEL_TOP,     "RECOVERY"},
    {DMS_REFORM_STEP_VALIDATE_LSN,                              DRPS_LEVEL_TOP,     "VALIDATE_LSN"},
    {DRPS_VALIDATE_LSN_COUNT,                                   DRPS_LEVEL_ONE,     "COUNT"},
    {DMS_REFORM_STEP_DRC_RCY_CLEAN,                             DRPS_LEVEL_TOP,     "DRC_RCY_CLEAN"},
    {DMS_REFORM_STEP_CTL_RCY_CLEAN,                             DRPS_LEVEL_TOP,     "CTL_RCY_CLEAN"},
    {DMS_REFORM_STEP_BCAST_UNABLE,                              DRPS_LEVEL_TOP,     "BCAST_UNABLE"},
    {DMS_REFORM_STEP_UPDATE_SCN,                                DRPS_LEVEL_TOP,     "UPDATE_SCN"},
    {DMS_REFORM_STEP_ROLLBACK,                                  DRPS_LEVEL_TOP,     "ROLLBACK"},
    {DRPS_ROLLBACK_UNDO_INIT,                                   DRPS_LEVEL_ONE,     "UNDO_INIT"},
    {DRPS_ROLLBACK_TX_AREA_INIT,                                DRPS_LEVEL_ONE,     "TX_AREA_INIT"},
    {DRPS_ROLLBACK_TX_AREA_LOAD,                                DRPS_LEVEL_ONE,     "TX_AREA_LOAD"},
    {DRPS_ROLLBACK_CVT_TO_RW,                                   DRPS_LEVEL_ONE,     "CVT_TO_RW"},
    {DMS_REFORM_STEP_SPACE_RELOAD,                              DRPS_LEVEL_TOP,     "SPACE_RELOAD"},
    {DMS_REFORM_STEP_TXN_DEPOSIT,                               DRPS_LEVEL_TOP,     "TXN_DEPOSIT"},
    {DRPS_TXN_DEPOSIT_DELETE_XA,                                DRPS_LEVEL_ONE,     "XA DELETE"},
    {DMS_REFORM_STEP_XA_DRC_ACCESS,                             DRPS_LEVEL_TOP,     "XA ACCESS"},
    {DMS_REFORM_STEP_BCAST_ENABLE,                              DRPS_LEVEL_TOP,     "BCAST_ENABLE"},
    {DMS_REFORM_STEP_SWITCH_LOCK,                               DRPS_LEVEL_TOP,     "SWITCH_LOCK"},
    {DMS_REFORM_STEP_COLLECT_XA_OWNER,                          DRPS_LEVEL_TOP,     "XA COLLECT"},
    {DMS_REFORM_STEP_MERGE_XA_OWNERS,                           DRPS_LEVEL_TOP,     "XA MERGE"},
    {DMS_REFORM_STEP_RECOVERY_XA,                               DRPS_LEVEL_TOP,     "XA RECOVERY"},
    {DMS_REFORM_STEP_SWITCHOVER_PROMOTE,                        DRPS_LEVEL_TOP,     "PROMOTE"},
    {DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS,              DRPS_LEVEL_TOP,     "S_PROMOTE"},
    {DMS_REFORM_STEP_SUCCESS,                                   DRPS_LEVEL_TOP,     "SUCCESS"},
    {DMS_REFORM_STEP_WAIT_CKPT,                                 DRPS_LEVEL_TOP,     "WAIT_CKPT"},
    {DMS_REFORM_STEP_SET_REMOVE_POINT,                          DRPS_LEVEL_TOP,     "SET POINT"},
    {DMS_REFORM_STEP_DONE,                                      DRPS_LEVEL_TOP,     "DONE"},
    {DMS_REFORM_STEP_DONE_CHECK,                                DRPS_LEVEL_TOP,     "DONE_CHECK"},
    {DMS_REFORM_STEP_SELF_FAIL,                                 DRPS_LEVEL_TOP,     "SELF_FAIL"},
    {DMS_REFORM_STEP_REFORM_FAIL,                               DRPS_LEVEL_TOP,     "REFORM_FAIL"},
    {DMS_REFORM_STEP_SYNC_WAIT,                                 DRPS_LEVEL_TOP,     "SYNC_WAIT"},
    {DMS_REFORM_STEP_SET_PHASE,                                 DRPS_LEVEL_TOP,     "SET_PHASE"},
    {DMS_REFORM_STEP_WAIT_DB,                                   DRPS_LEVEL_TOP,     "WAIT_DB"},
    {DMS_REFORM_STEP_DRC_VALIDATE,                              DRPS_LEVEL_TOP,     "DRC_VALIDATE"},
    {DRPS_DRC_BLOCK,                                            DRPS_LEVEL_TOP,     "DRC_BLOCK"},
};

drps_level_format_t g_drps_level_format[DRPS_LEVEL_COUNT] = {
    [DRPS_LEVEL_TOP]    = {"%-22s%16.3lf%16.3lf%9llu"},
    [DRPS_LEVEL_ONE]    = {"  %-20s%16.3lf%16.3lf%9llu"},
    [DRPS_LEVEL_TWO]    = {"    %-18s%16.3lf%16.3lf%9llu"},
    [DRPS_LEVEL_THREE]  = {"      %-16s%16.3lf%16.3lf%9llu"},
};

#define MICROSECS_PER_MILLISECF     1000.0

static void drps_log(drps_desc_t *drps_descs, uint32 drps_desc_num, drps_items_t *drps_items)
{
    drps_item_t *drps_item = NULL;
    LOG_RUN_INF("%-24s%-16s%-16s%-7s", "DESC", "TOTAL_TIME(ms)", "MAX_TIME(ms)", "TIMES");
    LOG_RUN_INF("%-24s%-16s%-16s%-7s", "----------------------", "--------------", "--------------", "-------");
    for (uint32 i = 0; i < drps_desc_num; i++) {
        drps_desc_t *drps_desc = &drps_descs[i];
        drps_item = &drps_items->drps_item[drps_desc->item];
        if (drps_item->times == 0 || drps_desc->level >= DRPS_LEVEL_COUNT) {
            continue;
        }
        LOG_RUN_INF(g_drps_level_format[drps_desc->level].format, drps_desc->desc,
            drps_item->total_time / MICROSECS_PER_MILLISECF, drps_item->max_time / MICROSECS_PER_MILLISECF,
            drps_item->times);
    }
}

void dms_reform_proc_stat_log_total(void)
{
    LOG_RUN_INF("[DMS REFORM PROC STAT]total statistic");
    LOG_RUN_INF("[DMS REFORM PROC STAT]reform details are as follows");
    drps_log(g_drps_desc_t, sizeof(g_drps_desc_t) / sizeof(drps_desc_t), &g_drps.items_total);
    LOG_RUN_INF("[DMS REFORM PROC STAT]mes_task details are as follows");
    drps_log(g_mes_drps_desc_t, sizeof(g_mes_drps_desc_t) / sizeof(drps_desc_t), &g_drps.items_total);
}

void dms_reform_proc_stat_log_current(void)
{
    drps_item_t *drps_item = &g_drps.items_proc_total.drps_item[DRPS_REFORM];
    LOG_RUN_INF("[DMS REFORM PROC STAT]current statistic");
    LOG_RUN_INF("[DMS REFORM PROC STAT]reform elapsed: %0.3fms, the details are as follows",
        drps_item->total_time / MICROSECS_PER_MILLISECF);
    drps_log(g_drps_desc_t, sizeof(g_drps_desc_t) / sizeof(drps_desc_t), &g_drps.items_proc_total);
    LOG_RUN_INF("[DMS REFORM PROC STAT]mes_task details are as follows");
    drps_log(g_mes_drps_desc_t, sizeof(g_mes_drps_desc_t) / sizeof(drps_desc_t), &g_drps.items_mes_total);
}

dms_reform_proc_stat_e g_callback_stat_map[REFORM_CALLBACK_STAT_COUNT] = {
    [REFORM_CALLBACK_STAT_CKPT_LATCH] = DRPS_CALLBACK_STAT_CKPT_LATCH,
    [REFORM_CALLBACK_STAT_BUCKET_LOCK] = DRPS_CALLBACK_STAT_BUCKET_LOCK,
    [REFORM_CALLBACK_STAT_SS_READ_LOCK] = DRPS_CALLBACK_STAT_SS_READ_LOCK,
    [REFORM_CALLBACK_STAT_GET_DISK_LSN] = DRPS_CALLBACK_STAT_GET_DISK_LSN,
    [REFORM_CALLBACK_STAT_DRC_EXIST] = DRPS_CALLBACK_STAT_DRC_EXIST,
    [REFORM_CALLBACK_STAT_CLEAN_EDP] = DRPS_CALLBACK_STAT_CLEAN_EDP,
    [REFORM_CALLBACK_STAT_NEED_NOT_REBUILD] = DRPS_CALLBACK_STAT_NEED_NOT_REBUILD,
    [REFORM_CALLBACK_STAT_EXPIRE] = DRPS_CALLBACK_STAT_EXPIRE,
    [REFORM_MES_TASK_STAT_CONFIRM_OWNER_BUCKET_LOCK] = DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_OWNER_BUCKET_LOCK,
    [REFORM_MES_TASK_STAT_CONFIRM_OWNER_GET_DISK_LSN] = DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_OWNER_GET_DISK_LSN,
    [REFORM_MES_TASK_STAT_CONFIRM_CVT_BUCKET_LOCK] = DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_CVT_BUCKET_LOCK,
    [REFORM_MES_TASK_STAT_CONFIRM_CVT_SS_READ_LOCK] = DRPS_CALLBACK_MES_TASK_STAT_CONFIRM_CVT_SS_READ_LOCK,
    [REFORM_MES_TASK_STAT_NEED_FLUSH_ALLOC_CTRL] = DRPS_CALLBACK_MES_TASK_STAT_NEED_FLUSH_ALLOC_CTRL,
    [REFORM_MES_TASK_STAT_NEED_FLUSH_SS_READ_LOCK] = DRPS_CALLBACK_MES_TASK_STAT_NEED_FLUSH_SS_READ_LOCK,
    [REFORM_MES_TASK_STAT_EDP_TO_OWNER_GET_DISK_LSN] = DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_GET_DISK_LSN,
    [REFORM_MES_TASK_STAT_EDP_TO_OWNER_ALLOC_CTRL] = DRPS_CALLBACK_MES_TASK_STAT_EDP_TO_OWNER_ALLOC_CTRL,
    [REFORM_CALLBACK_STAT_VALIDATE_DRC_PAGE_BUCKET_LOCK] = DRPS_CALLBACK_STAT_VALIDATE_DRC_PAGE_BUCKET_LOCK,
    [REFORM_CALLBACK_STAT_VALIDATE_DRC_PAGE_SS_READ_LOCK] = DRPS_CALLBACK_STAT_VALIDATE_DRC_PAGE_SS_READ_LOCK,
    [REFORM_CALLBACK_STAT_VALIDATE_DRC_PAGE_REMOTE] = DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE,
    [REFORM_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL] = DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL,
    [REFORM_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL_TIMEOUT] = DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_CTRL_TIMEOUT,
    [REFORM_MES_TASK_STAT_VALIDATE_LSN_GET_DISK_LSN] = DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_GET_DISK_LSN,
    [REFORM_MES_TASK_STAT_VALIDATE_LSN_BUF_UNLATCH] = DRPS_CALLBACK_MES_TASK_STAT_VALIDATE_LSN_BUF_UNLATCH,
};

void dms_reform_proc_callback_stat_start(reform_callback_stat_e callback_stat)
{
    if (callback_stat >= REFORM_CALLBACK_STAT_COUNT) {
        return;
    }
    uint32 item = (uint32)g_callback_stat_map[callback_stat];
    dms_reform_proc_stat_start(item);
}

void dms_reform_proc_callback_stat_end(reform_callback_stat_e callback_stat)
{
    if (callback_stat >= REFORM_CALLBACK_STAT_COUNT) {
        return;
    }
    uint32 item = (uint32)g_callback_stat_map[callback_stat];
    dms_reform_proc_stat_end(item);
}

void dms_reform_proc_callback_stat_times(reform_callback_stat_e callback_stat)
{
    if (callback_stat >= REFORM_CALLBACK_STAT_COUNT) {
        return;
    }
    uint32 item = (uint32)g_callback_stat_map[callback_stat];
    dms_reform_proc_stat_times(item);
}

bool32 dms_reform_proc_stat_desc_check(void)
{
    bool8 has_desc[DRPS_COUNT] = { 0 };

    for (uint32 i = 0; i < sizeof(g_drps_desc_t) / sizeof(drps_desc_t); i++) {
        drps_desc_t *drps_desc = &g_drps_desc_t[i];
        has_desc[drps_desc->item] = CM_TRUE;
    }

    for (uint32 i = 0; i < sizeof(g_mes_drps_desc_t) / sizeof(drps_desc_t); i++) {
        drps_desc_t *drps_desc = &g_mes_drps_desc_t[i];
        has_desc[drps_desc->item] = CM_TRUE;
    }

    for (uint32 i = 0; i < DRPS_COUNT; i++) {
        if (i == DRPS_REFORM) {
            continue;
        }
        if (!has_desc[i]) {
            (void)printf("proc stat(%u) has defined enum, but no desc", i);
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}