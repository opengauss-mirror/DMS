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
 * dms_reform_health.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_health.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_health.h"
#include "dms_process.h"
#include "dms_reform_proc.h"
#include "dms_reform_judge.h"
#include "cm_timer.h"
#include "dms_dynamic_trace.h"

void dms_reform_health_set_running(void)
{
    health_info_t *health_info = DMS_HEALTH_INFO;
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

    while (CM_TRUE) {
        if (health_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            health_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            break;
        }
        DMS_REFORM_SHORT_SLEEP;
    }
    LOG_RUN_INF("[DMS REFORM]dms_reform_health running");
    health_info->thread_status = DMS_THREAD_STATUS_RUNNING;
    health_info->dyn_log_time = cm_clock_monotonic_now();
    cm_sem_post(&reform_context->sem_health);
}

void dms_reform_health_set_pause(void)
{
    health_info_t *health_info = DMS_HEALTH_INFO;
    CM_ASSERT(health_info->thread_status == DMS_THREAD_STATUS_RUNNING);

    LOG_RUN_INF("[DMS REFORM]dms_reform_health pausing");
    health_info->thread_status = DMS_THREAD_STATUS_PAUSING;

    while (health_info->thread_status != DMS_THREAD_STATUS_PAUSED) {
        DMS_REFORM_SHORT_SLEEP;
    }
}

static void dms_reform_health_dyn_log(void)
{
    health_info_t *health_info = DMS_HEALTH_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    date_t time_now = cm_clock_monotonic_now();
    if (time_now - health_info->dyn_log_time >= DMS_REFORM_HEALTH_TRIGGER_DYN * MICROSECS_PER_SECOND) {
        LOG_RUN_INF("[DMS REFORM]health check trigger dyn log");
#ifndef OPENGAUSS
        g_dms.callback.dyn_log(reform_ctx->handle_health, health_info->dyn_log_time);
#else
        uint8 step = reform_ctx->reform_info.current_step;
        uint8 role = reform_ctx->reform_info.dms_role;
        g_dms.callback.reform_check_opengauss(reform_ctx->handle_health, step, role, health_info->dyn_log_time);
#endif
        health_info->dyn_log_time = cm_clock_monotonic_now();
    }
}

static bool32 dms_reform_health_check_reformer(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    version_info_t reformer_version = share_info->reformer_version;
    version_info_t switch_version = share_info->switch_version;

    cm_spin_lock(&reform_info->version_lock, NULL);
    version_info_t local_version = reform_info->reformer_version;
    cm_spin_unlock(&reform_info->version_lock);

    if (dms_reform_version_same(&local_version, &reformer_version)) {
        return CM_TRUE;
    }

    // SWITCHOVER will change reformer, local_version will be changed after new reformer get online status
    if (!REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        LOG_RUN_ERR("[DMS REFORM]local reformer version(%d, %llu) is not same as share reformer version(%d, %llu)",
            local_version.inst_id, local_version.start_time, reformer_version.inst_id, reformer_version.start_time);
        return CM_FALSE;
    }

    if (dms_reform_version_same(&local_version, &switch_version)) {
        return CM_TRUE;
    }

    LOG_RUN_ERR("[DMS REFORM]local reformer version(%d, %llu) is not same as share reformer version(%d, %llu) and"
        "share switchover version(%d, %llu)", local_version.inst_id, local_version.start_time, reformer_version.inst_id,
        reformer_version.start_time, switch_version.inst_id, switch_version.start_time);

    return CM_FALSE;
}

// if there is instance status before less than now
// it means the instance restart in the period of reform, set reform fail
static bool32 dms_reform_cmp_online_status(node_info_t *node_infos)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint64 list_online_cache = 0;
    bool32 in_list_cache = CM_FALSE;

    dms_reform_list_to_bitmap(&list_online_cache, &share_info->list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_cache = bitmap64_exist(&list_online_cache, i);
        if (!in_list_cache) {
            continue;
        }
        online_status_t *old_status = DMS_ONLINE_STATUS(i);
        online_status_t *new_status = &node_infos[i].online_status;
        if (old_status->status > new_status->status) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), status cache: %d, current: %d",
                i, old_status->status, new_status->status);
            return CM_FALSE;
        } else {
            old_status->status = new_status->status;
        }

        // for switchover, not need to use start_times to judge
        if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
            if (new_status->status != DMS_STATUS_IN) {
                LOG_RUN_ERR("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), current: %d, "
                    "excepted: %d in switchover", i, new_status->status, DMS_STATUS_IN);
                return CM_FALSE;
            }
            continue;
        }
        if (new_status->start_time != old_status->start_time) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), time cache: %llu, current: %llu",
                        i, old_status->start_time, new_status->start_time);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

// if there is instance in online list before and not in online list now, set reform fail
static bool32 dms_reform_cmp_list_online(instance_list_t *list_online)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    bool32 in_list_current = CM_FALSE;
    bool32 in_list_cache = CM_FALSE;
    uint64 bitmap_online_current = 0;

    dms_reform_list_to_bitmap(&bitmap_online_current, list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_current = bitmap64_exist(&bitmap_online_current, i);
        in_list_cache = bitmap64_exist(&share_info->bitmap_online, i);
        if (in_list_cache && !in_list_current) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_cmp_list_online error, inst(%d) offline, cache: %llu, current: %llu",
                i, share_info->bitmap_online, bitmap_online_current);
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

// in the period of reform, some errors may occur
static bool32 dms_reform_health_check_partner(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    node_info_t node_infos[DMS_MAX_INSTANCES] = { 0 };
    instance_list_t list_online;
    instance_list_t list_offline;

    if (!DMS_IS_REFORMER || !reform_info->build_complete || reform_info->maintain) {
        return CM_TRUE;
    }

    uint64 online_version = 0ULL;
    if (dms_reform_get_list_from_cm(&list_online, &list_offline, &online_version) != DMS_SUCCESS) {
        return CM_TRUE;
    }

    if (dms_reform_cmp_list_online(&list_online) != CM_TRUE) {
        return CM_FALSE;
    }

    if (dms_reform_get_online_status(&list_online, reform_ctx->sess_health, node_infos)
        != DMS_SUCCESS) {
        return CM_TRUE;
    }

    dms_set_driver_ping_info(online_version, &list_online, node_infos);

    return dms_reform_cmp_online_status(node_infos);
}

void dms_get_driver_ping_info(driver_ping_info_t *driver_ping_info)
{
    cm_spin_lock(&g_dms.dms_driver_ping_info.lock, NULL);
    /* REFORMER:dms_set_driver_ping_info */
    g_dms.dms_driver_ping_info.driver_ping_info.dms_role = g_dms.reform_ctx.reform_info.dms_role;
    *driver_ping_info = g_dms.dms_driver_ping_info.driver_ping_info;
    cm_spin_unlock(&g_dms.dms_driver_ping_info.lock);
    LOG_DEBUG_INF("[DMS] rw_bitmap:%llu, dms_role:%d, major_version:%llu, minor_version:%llu",
        driver_ping_info->rw_bitmap, driver_ping_info->dms_role, driver_ping_info->major_version,
        driver_ping_info->minor_version);
}

static void dms_reform_health_handle_fail(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
#ifdef OPENGAUSS
    reform_info->reform_fail = CM_TRUE;
    dms_reform_handle_fail_in_special_scenario();
#else
    uint64 time_now = (uint64)g_timer()->now;
    if (time_now - reform_info->proc_time > MAX_ALIVE_TIME_FOR_ABNORMAL_STATUS * MICROSECS_PER_MILLISEC) {
        LOG_RUN_ERR("[DMS REFORM]dms_reform_proc is inactive for %d seconds, exit", MAX_ALIVE_TIME_FOR_ABNORMAL_STATUS);
        cm_exit(0);
    } else if (!reform_info->reform_fail) {
        reform_info->reform_fail = CM_TRUE;
        LOG_RUN_INF("[DMS REFORM]set reform fail, health check");
    }
#endif
}

static void dms_reform_health_check(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    dms_reform_health_dyn_log();

    // if has set reform fail, no need check again, just wait timeout and abort
    if (reform_info->reform_fail) {
        dms_reform_health_handle_fail();
        return;
    }

    if (dms_reform_health_check_reformer() != CM_TRUE) {
        LOG_RUN_ERR("[DMS REFORM]reformer abort during reform");
        dms_reform_health_handle_fail();
    }

    if (dms_reform_health_check_partner() != CM_TRUE) {
        LOG_RUN_ERR("[DMS REFORM]partner abort during reform");
        dms_reform_health_handle_fail();
    }
}

void dms_reform_health_thread(thread_t *thread)
{
    dms_set_is_reform_thrd(CM_TRUE);
    cm_set_thread_name(DMS_REFORM_HEALTH_THRD_NAME);
    mes_block_sighup_signal();
    health_info_t *health_info = DMS_HEALTH_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    dms_set_tls_sid(reform_ctx->sess_health);
    LOG_RUN_INF("[DMS REFORM]dms_reform_health thread started");
    while (!thread->closed) {
        if (health_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            health_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            cm_sem_wait(&reform_ctx->sem_health);
            continue;
        }
        if (health_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_health paused");
            health_info->thread_status = DMS_THREAD_STATUS_PAUSED;
            continue;
        }
        if (health_info->thread_status == DMS_THREAD_STATUS_RUNNING) {
            dms_reform_health_check();
            DMS_REFORM_SHORT_SLEEP;
        }
    }
}

#ifdef OPENGAUSS
void dms_reform_handle_fail_in_special_scenario(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (!reform_info->reform_fail) {
        return;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type) && share_info->demote_id == g_dms.inst_id &&
        reform_info->reformer_id != g_dms.inst_id) {
        LOG_RUN_ERR("[DMS REFORM] node exit, reform fail during switchover, old primary node need restart "
                    "after reformer lock transfered, demote id:%u, reformer id:%u",
                    (uint32)share_info->demote_id, (uint32)reform_info->reformer_id);
        cm_exit(0);
    }
}
#endif