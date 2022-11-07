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
 * dms_stat.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_stat.h"
#include "dms.h"

#ifdef __cplusplus
extern "C" {
#endif

dms_stat_t g_dms_stat;

void dms_begin_stat(uint32     sid, dms_wait_event_t event, bool32 immediate)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;
    if (stat->wait.is_waiting && event == stat->wait.event) {
        return;
    }

    stat->wait.is_waiting = CM_TRUE;
    stat->wait.event = event;
    stat->wait.usecs = 0;
    stat->wait.pre_spin_usecs = cm_total_spin_usecs();
    stat->wait.immediate = immediate;

    if (!immediate || !g_dms_stat.time_stat_enabled) {
        return;
    }

    (void)cm_gettimeofday(&stat->wait.begin_tv);
}

void dms_end_stat(uint32    sid)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;
    dms_end_stat_ex(sid, stat->wait.event);
}

void dms_end_stat_ex(uint32    sid, dms_wait_event_t event)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;

    if (!stat->wait.is_waiting) {
        return;
    }

    timeval_t tv_end;

    if (stat->wait.immediate && g_dms_stat.time_stat_enabled) {
        (void)cm_gettimeofday(&tv_end);
        stat->wait.usecs = (uint64)TIMEVAL_DIFF_US(&stat->wait.begin_tv, &tv_end);
    } else {
        stat->wait.usecs = cm_total_spin_usecs() - stat->wait.pre_spin_usecs;
    }

    stat->wait_time[event] += stat->wait.usecs;
    stat->wait_count[event]++;

    stat->wait.is_waiting = CM_FALSE;
}

DMS_DECLARE void dms_get_event(dms_wait_event_t event_type, unsigned long long *event_cnt,
    unsigned long long *event_time)
{
    unsigned long long cnt = 0;
    unsigned long long time = 0;

    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        cnt += stat->wait_count[event_type];
        time += stat->wait_time[event_type];
    }

    if (event_cnt) {
        *event_cnt = cnt;
    }

    if (event_time) {
        *event_time = time;
    }
}

DMS_DECLARE unsigned long long dms_get_stat(dms_sysstat_t stat_type)
{
    unsigned long long cnt = 0;

    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        cnt += stat->stat[stat_type];
    }

    return cnt;
}

DMS_DECLARE void dms_reset_stat(void)
{
    uint32 j;
    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        for (j = 0; j < (uint32)DMS_STAT_COUNT; j++) {
            stat->stat[j] = 0;
        }

        for (j = 0; j < (uint32)DMS_EVT_COUNT; j++) {
            stat->wait_time[j] = 0;
            stat->wait_count[j] = 0;
        }
    }
}

#ifdef __cplusplus
}
#endif

