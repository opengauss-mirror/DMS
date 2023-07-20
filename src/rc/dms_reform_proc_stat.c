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
    MEMS_RETVOID_IFERR(memset_s(&g_drps.items_proc, sizeof(drps_items_t), 0, sizeof(drps_items_t)));
    uint32 size = sizeof(drps_items_t) * DMS_PARALLEL_MAX_THREAD;
    MEMS_RETVOID_IFERR(memset_s(g_drps.items_proc_parallel, size, 0, size));
}

void dms_reform_proc_stat_bind_proc(void)
{
    g_drps_items = &g_drps.items_proc;
}

void dms_reform_proc_stat_bind_proc_parallel(uint32 index)
{
    g_drps_items = &g_drps.items_proc_parallel[index];
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

    drps_items_t *to_items = &g_drps.items_proc;
    drps_items_t *from_items = NULL;
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        from_items = &g_drps.items_proc_parallel[i];
        dms_reform_proc_stat_merge_items(to_items, from_items);
    }
}

void dms_reform_proc_stat_collect_total(void)
{
    drps_items_t *to_items = &g_drps.items_total;
    drps_items_t *from_items = &g_drps.items_proc;
    dms_reform_proc_stat_merge_items(to_items, from_items);
}

drps_desc_t g_drps_desc_t[DRPS_COUNT] = {
    {DRPS_REFORM,                                   DRPS_LEVEL_TOP,     "REFORM"},
    {DMS_REFORM_STEP_DONE,                          DRPS_LEVEL_ONE,     "DONE"},
    {DMS_REFORM_STEP_PREPARE,                       DRPS_LEVEL_ONE,     "PREPARE"},
    {DMS_REFORM_STEP_START,                         DRPS_LEVEL_ONE,     "START"},
    {DMS_REFORM_STEP_DISCONNECT,                    DRPS_LEVEL_ONE,     "DISCONNECT"},
    {DMS_REFORM_STEP_RECONNECT,                     DRPS_LEVEL_ONE,     "RECONNECT"},
    {DMS_REFORM_STEP_DRC_CLEAN,                     DRPS_LEVEL_ONE,     "DRC_CLEAN"},
    {DRPS_DRC_CLEAN_NO_OWNER,                       DRPS_LEVEL_TWO,     "NO_OWNER"},
    {DRPS_DRC_CLEAN_NO_CVT,                         DRPS_LEVEL_TWO,     "NO_CVT"},
    {DRPS_DRC_CLEAN_CONFIRM_COPY,                   DRPS_LEVEL_TWO,     "CONFIRM_COPY"},
    {DRPS_DRC_CLEAN_OWNER_CVT_FAULT,                DRPS_LEVEL_TWO,     "BOTH_FAULT"},
    {DRPS_DRC_CLEAN_CONFIRM_OWNER,                  DRPS_LEVEL_TWO,     "CONFIRM_OWNER"},
    {DRPS_DRC_CLEAN_CONFIRM_CVT,                    DRPS_LEVEL_TWO,     "CONFIRM_CVT"},
    {DMS_REFORM_STEP_MIGRATE,                       DRPS_LEVEL_ONE,     "MIGRATE"},
    {DMS_REFORM_STEP_REBUILD,                       DRPS_LEVEL_ONE,     "REBUILD"},
    {DRPS_DRC_REBUILD_LOCAL,                        DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_DRC_REBUILD_REMOTE,                       DRPS_LEVEL_TWO,     "REMOTE"},
    {DMS_REFORM_STEP_REMASTER,                      DRPS_LEVEL_ONE,     "REMASTER"},
    {DMS_REFORM_STEP_REPAIR,                        DRPS_LEVEL_ONE,     "REPAIR"},
    {DRPS_DRC_REPAIR_NEED_FLUSH,                    DRPS_LEVEL_TWO,     "NEED_FLUSH"},
    {DRPS_DRC_REPAIR_NEED_NOT_FLUSH,                DRPS_LEVEL_TWO,     "NOT_FLUSH"},
    {DRPS_DRC_REPAIR_WITH_COPY,                     DRPS_LEVEL_TWO,     "WITH_COPY"},
    {DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH,          DRPS_LEVEL_THREE,   "COPY_NEED_FLUSH"},
    {DRPS_DRC_REPAIR_WITH_LAST_EDP,                 DRPS_LEVEL_TWO,     "WITH_LAST_EDP"},
    {DRPS_DRC_REPAIR_WITH_EDP_MAP,                  DRPS_LEVEL_TWO,     "WITH_EDP_MAP"},
    {DRPS_DRC_REPAIR_PAGE,                          DRPS_LEVEL_TWO,     "PAGE"},
    {DRPS_DRC_REPAIR_LOCK,                          DRPS_LEVEL_TWO,     "LOCK"},
    {DMS_REFORM_STEP_SWITCH_LOCK,                   DRPS_LEVEL_ONE,     "SWITCH_LOCK"},
    {DMS_REFORM_STEP_SWITCHOVER_DEMOTE,             DRPS_LEVEL_ONE,     "DEMOTE"},
    {DMS_REFORM_STEP_SWITCHOVER_PROMOTE,            DRPS_LEVEL_ONE,     "PROMOTE"},
    {DMS_REFORM_STEP_RECOVERY,                      DRPS_LEVEL_ONE,     "RECOVERY"},
    {DMS_REFORM_STEP_RECOVERY_OPENGAUSS,            DRPS_LEVEL_ONE,     "RECOVERY"},
    {DMS_REFORM_STEP_DRC_RCY_CLEAN,                 DRPS_LEVEL_ONE,     "DRC_RCY_CLEAN"},
    {DMS_REFORM_STEP_CTL_RCY_CLEAN,                 DRPS_LEVEL_ONE,     "CTL_RCY_CLEAN"},
    {DMS_REFORM_STEP_TXN_DEPOSIT,                   DRPS_LEVEL_ONE,     "TXN_DEPOSIT"},
    {DMS_REFORM_STEP_ROLLBACK,                      DRPS_LEVEL_ONE,     "ROLLBACK"},
    {DMS_REFORM_STEP_SUCCESS,                       DRPS_LEVEL_ONE,     "SUCCESS"},
    {DMS_REFORM_STEP_SELF_FAIL,                     DRPS_LEVEL_ONE,     "SELF_FAIL"},
    {DMS_REFORM_STEP_REFORM_FAIL,                   DRPS_LEVEL_ONE,     "REFORM_FAIL"},
    {DMS_REFORM_STEP_SYNC_WAIT,                     DRPS_LEVEL_ONE,     "SYNC_WAIT"},
    {DMS_REFORM_STEP_PAGE_ACCESS,                   DRPS_LEVEL_ONE,     "PAGE_ACCESS"},
    {DMS_REFORM_STEP_DW_RECOVERY,                   DRPS_LEVEL_ONE,     "DW_RECOVERY"},
    {DMS_REFORM_STEP_DF_RECOVERY,                   DRPS_LEVEL_ONE,     "DF_RECOVERY"},
    {DMS_REFORM_STEP_FILE_ORGLSN_RECOVERY,          DRPS_LEVEL_ONE,     "LSN_RECOVERY"},
    {DMS_REFORM_STEP_DRC_ACCESS,                    DRPS_LEVEL_ONE,     "DRC_ACCESS"},
    {DMS_REFORM_STEP_DRC_INACCESS,                  DRPS_LEVEL_ONE,     "DRC_INACCESS"},
    {DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS,  DRPS_LEVEL_ONE,     "S_PROMOTE"},
    {DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS,    DRPS_LEVEL_ONE,     "F_PROMOTE"},
    {DMS_REFORM_STEP_STARTUP_OPENGAUSS,             DRPS_LEVEL_ONE,     "STARTUP"},
    {DMS_REFORM_STEP_FLUSH_COPY,                    DRPS_LEVEL_ONE,     "FLUSH_COPY"},
    {DRPS_DRC_FLUSH_COPY_LOCAL,                     DRPS_LEVEL_TWO,     "LOCAL"},
    {DRPS_DRC_FLUSH_COPY_REMOTE,                    DRPS_LEVEL_TWO,     "REMOTE"},
    {DMS_REFORM_STEP_DONE_CHECK,                    DRPS_LEVEL_ONE,     "DONE_CHECK"},
    {DMS_REFORM_STEP_SET_PHASE,                     DRPS_LEVEL_ONE,     "SET_PHASE"},
    {DMS_REFORM_STEP_WAIT_DB,                       DRPS_LEVEL_ONE,     "WAIT_DB"},
    {DMS_REFORM_STEP_BCAST_ENABLE,                  DRPS_LEVEL_ONE,     "BCAST_ENABLE"},
    {DMS_REFORM_STEP_BCAST_UNABLE,                  DRPS_LEVEL_ONE,     "BCAST_UNABLE"},
    {DMS_REFORM_STEP_UPDATE_SCN,                    DRPS_LEVEL_ONE,     "UPDATE_SCN"},
    {DMS_REFORM_STEP_WAIT_CKPT,                     DRPS_LEVEL_ONE,     "WAIT_CKPT"},
    {DMS_REFORM_STEP_DRC_VALIDATE,                  DRPS_LEVEL_ONE,     "DRC_VALIDATE"},
    {DMS_REFORM_STEP_LOCK_INSTANCE,                 DRPS_LEVEL_ONE,     "LOCK_INSTANCE"},
};

drps_level_format_t g_drps_level_format[DRPS_LEVEL_COUNT] = {
    [DRPS_LEVEL_TOP]    = {"%-22s%16.3lf%16.3l%9llu"},
    [DRPS_LEVEL_ONE]    = {"  %-20s%16.3lf%16.3l%9llu"},
    [DRPS_LEVEL_TWO]    = {"    %-18s%16.3lf%16.3l%9llu"},
    [DRPS_LEVEL_THREE]  = {"      %-16s%16.3lf%16.3l%9llu"},
};

#define MICROSECS_PER_MILLISECF     1000.0

static void dms_reform_proc_stat_log_inner(drps_items_t *drps_items)
{
    LOG_RUN_INF("%-24s%-16s%-16s%-7s", "DESC", "TOTAL_TIME(ms)", "MAX_TIME(ms)", "TIMES");
    LOG_RUN_INF("%-24s%-16s%-16s%-7s", "----------------------", "--------------", "--------------", "-------");
    for (uint32 i = 0; i < DRPS_COUNT; i++) {
        drps_desc_t *drps_desc = &g_drps_desc_t[i];
        if (strlen(drps_desc->desc) == 0) { // if add new stat without updating g_drps_desc_t, its desc is empty
            continue;
        }
        drps_item_t *drps_item = &drps_items->drps_item[drps_desc->item];
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
    dms_reform_proc_stat_log_inner(&g_drps.items_total);
}

void dms_reform_proc_stat_log_current(void)
{
    LOG_RUN_INF("[DMS REFORM PROC STAT]current statistic");
    dms_reform_proc_stat_log_inner(&g_drps.items_proc);
}