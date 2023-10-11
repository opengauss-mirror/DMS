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
#include "dms_process.h"
#include "dms.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

dms_stat_t g_dms_stat;

void dms_begin_stat(uint32     sid, dms_wait_event_t event, bool32 immediate)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;
    uint32 curr_level = stat->level++;
    if (stat->level > DMS_STAT_MAX_LEVEL) {
        LOG_RUN_WAR("[DMS][dms_begin_stat]: stat level exceeds the upper limit, sid %u, current level %u",
            sid, curr_level);
        return;
    }

    stat->wait[curr_level].is_waiting = CM_TRUE;
    stat->wait[curr_level].event = event;
    stat->wait[curr_level].usecs = 0;
    stat->wait[curr_level].pre_spin_usecs = cm_total_spin_usecs();
    stat->wait[curr_level].immediate = immediate;
    LOG_DEBUG_INF("[DMS][dms_begin_stat]: stat event %u, immediate %d, sid %u, current level %u",
        event, immediate, sid, curr_level);

    if (!immediate || !g_dms_stat.time_stat_enabled) {
        return;
    }

    (void)cm_gettimeofday(&stat->wait[curr_level].begin_tv);
}

void dms_end_stat(uint32 sid)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;

    if (stat->level == 0) {
        LOG_RUN_ERR("[DMS][dms_end_stat]: stat level is already meet the low limit, sid %u", sid);
        return;
    } else if (stat->level > DMS_STAT_MAX_LEVEL) {
        uint32 curr_level = --stat->level;
        LOG_RUN_WAR("[DMS][dms_end_stat]: stat level exceeds the upper limit, sid %u, current level %u",
            sid, curr_level);
        return;
    }

    dms_end_stat_ex(sid, stat->wait[stat->level - 1].event);
}

void dms_end_stat_ex(uint32 sid, dms_wait_event_t event)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;

    uint32 curr_level = --stat->level;
    LOG_DEBUG_INF("[DMS][dms_end_stat_ex]: stat event %u, sid %u, current level %u", event, sid, curr_level);

    timeval_t tv_end;

    if (stat->wait[stat->level].immediate && g_dms_stat.time_stat_enabled) {
        (void)cm_gettimeofday(&tv_end);
        stat->wait[stat->level].usecs = (uint64)TIMEVAL_DIFF_US(&stat->wait[stat->level].begin_tv, &tv_end);
    } else {
        stat->wait[stat->level].usecs = cm_total_spin_usecs() - stat->wait[stat->level].pre_spin_usecs;
    }

    stat->wait_time[event] += stat->wait[stat->level].usecs;
    stat->wait_count[event]++;

    stat->wait[stat->level].is_waiting = CM_FALSE;
}

DMS_DECLARE void dms_get_event(dms_wait_event_t event_type, unsigned long long *event_cnt,
    unsigned long long *event_time)
{
    unsigned long long cnt = 0;
    unsigned long long time = 0;

    SCRLockEvent event = dms_scrlock_events_adapt(event_type);
    if (g_dms.scrlock_ctx.enable && event != CM_INVALID_ID32) {
        dms_scrlock_get_event(event, &cnt, &time);
        if (event_cnt) {
            *event_cnt = cnt;
        }
        if (event_time) {
            *event_time = time;
        }
        return;
    }

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

DMS_DECLARE int dms_get_mes_wait_event(unsigned int cmd, unsigned long long *event_cnt, 
    unsigned long long *event_time) 
{
    if (cmd >= CM_MAX_MES_MSG_CMD) {
        return ERR_MES_CMD_TYPE_ERR;
    }
    mes_get_wait_event(cmd, event_cnt, event_time);
    return DMS_SUCCESS;
}

#ifdef __cplusplus
}
#endif

