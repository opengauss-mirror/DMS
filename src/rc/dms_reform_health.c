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

void dms_reform_health_set_running(void)
{
    health_info_t *health_info = DMS_HEALTH_INFO;

    while (CM_TRUE) {
        if (health_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            health_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            break;
        }
        DMS_REFORM_LONG_SLEEP;
    }
    LOG_RUN_INF("[DMS REFORM]dms_reform_health running");
    health_info->thread_status = DMS_THREAD_STATUS_RUNNING;
}

void dms_reform_health_set_pause(void)
{
    health_info_t *health_info = DMS_HEALTH_INFO;
    CM_ASSERT(health_info->thread_status == DMS_THREAD_STATUS_RUNNING);

    LOG_RUN_INF("[DMS REFORM]dms_reform_health pausing");
    health_info->thread_status = DMS_THREAD_STATUS_PAUSING;

    while (health_info->thread_status != DMS_THREAD_STATUS_PAUSED) {
        DMS_REFORM_LONG_SLEEP;
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
static bool32 dms_reform_cmp_online_status(uint8 *online_status, uint64 *online_times)
{
    health_info_t *health_info = DMS_HEALTH_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    uint64 list_online_cache = 0;
    bool32 in_list_cache = CM_FALSE;

    dms_reform_list_to_bitmap(&list_online_cache, &share_info->list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_cache = bitmap64_exist(&list_online_cache, i);
        if (!in_list_cache) {
            continue;
        }
        if (health_info->online_status[i] > online_status[i]) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), status cache: %d, current: %d",
                i, health_info->online_status[i], online_status[i]);
            return CM_FALSE;
        } else {
            health_info->online_status[i] = online_status[i];
        }

        // for switchover, not need to use online_times to judge
        if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
            continue;
        }
        if (online_times[i] != health_info->online_times[i]) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), time cache: %llu, current: %llu",
                        i, health_info->online_times[i], online_times[i]);
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
    uint8 online_status[DMS_MAX_INSTANCES] = { 0 };
    uint64 online_times[DMS_MAX_INSTANCES] = { 0 };
    instance_list_t list_online;
    instance_list_t list_offline;

    if (!DMS_IS_REFORMER || !reform_info->build_complete || reform_info->maintain) {
        return CM_TRUE;
    }

    if (dms_reform_get_list_from_cm(&list_online, &list_offline) != DMS_SUCCESS) {
        return CM_TRUE;
    }

    if (dms_reform_cmp_list_online(&list_online) != CM_TRUE) {
        return CM_FALSE;
    }

    if (dms_reform_get_online_status(online_status, online_times, reform_ctx->sess_health) != DMS_SUCCESS) {
        return CM_TRUE;
    }

    return dms_reform_cmp_online_status(online_status, online_times);
}

static void dms_reform_health_handle_fail(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
#ifdef OPENGAUSS
    reform_info->reform_fail = CM_TRUE;
#else
    uint64 time_now = (uint64)g_timer()->now;
    if (time_now - reform_info->proc_time > DMS_MAX_FAIL_TIME * MICROSECS_PER_SECOND) {
        LOG_RUN_ERR("[DMS REFORM]dms_reform_proc is inactive for %d seconds, exit", DMS_MAX_FAIL_TIME);
        cm_exit(0);
    } else {
        reform_info->reform_fail = CM_TRUE;
    }
#endif
}

static void dms_reform_health_check(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

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
    cm_set_thread_name("reform_health");
    health_info_t *health_info = DMS_HEALTH_INFO;
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    LOG_RUN_INF("[DMS REFORM]dms_reform_health thread started");
    while (!thread->closed) {
        if (health_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            health_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            DMS_REFORM_LONG_SLEEP;
            continue;
        }
        if (health_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_health paused");
            health_info->thread_status = DMS_THREAD_STATUS_PAUSED;
            continue;
        }
        if (health_info->thread_status == DMS_THREAD_STATUS_RUNNING) {
            dms_reform_health_check();
        }
    }
}
