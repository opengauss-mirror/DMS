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
 * dms_reform_judge_stat.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_judge_stat.h"
#include "dms.h"

reform_judge_stats_t g_judge_stats;

void dms_reform_judgement_stat_init(void)
{
    g_judge_stats.curr_index = 1;
    g_judge_stats.curr_pos = 0;
    g_judge_stats.start = CM_FALSE;
    GS_INIT_SPIN_LOCK(g_judge_stats.lock);
}

void dms_reform_judgement_stat_start(void)
{
    reform_judge_stat_t *stat = &g_judge_stats.stat[g_judge_stats.curr_pos];
    cm_spin_lock(&stat->lock, NULL);
    for (uint32 i = DMS_REFORM_JUDGE_START; i < DMS_REFORM_JUDGE_COUNT; i++) {
        stat->time[i] = 0;
    }
    stat->time[DMS_REFORM_JUDGE_START] = g_timer()->now;
    stat->index = g_judge_stats.curr_index;
    stat->desc[0] = 0;
    cm_spin_unlock(&stat->lock);
    g_judge_stats.start = CM_TRUE;
}

void dms_reform_judgement_stat_step(reform_judge_step_t step)
{
    if (!g_judge_stats.start) {
        return;
    }
    reform_judge_stat_t *stat = &g_judge_stats.stat[g_judge_stats.curr_pos];
    cm_spin_lock(&stat->lock, NULL);
    stat->time[step] = g_timer()->now;
    cm_spin_unlock(&stat->lock);
}

void dms_reform_judgement_stat_desc(char *desc)
{
    if (!g_judge_stats.start) {
        return;
    }
    reform_judge_stat_t *stat = &g_judge_stats.stat[g_judge_stats.curr_pos];
    cm_spin_lock(&stat->lock, NULL);
    errno_t ret = strcpy_s(stat->desc, CM_BUFLEN_32, desc);
    cm_spin_unlock(&stat->lock);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS REFORM]strcpy_s error");
    }
}

void dms_reform_judgement_stat_end(void)
{
    if (!g_judge_stats.start) {
        return;
    }
    reform_judge_stat_t *stat = &g_judge_stats.stat[g_judge_stats.curr_pos];
    cm_spin_lock(&stat->lock, NULL);
    stat->time[DMS_REFORM_JUDGE_END] = g_timer()->now;
    cm_spin_unlock(&stat->lock);

    cm_spin_lock(&g_judge_stats.lock, NULL);
    g_judge_stats.curr_pos = (g_judge_stats.curr_pos + 1) % DMS_REFORM_JUDGE_STAT_SIZE;
    g_judge_stats.curr_index++;
    cm_spin_unlock(&g_judge_stats.lock);
    g_judge_stats.start = CM_FALSE;
}

void dms_reform_judgement_stat_cancel(void)
{
    g_judge_stats.start = CM_FALSE;
}

void dms_reform_judgement_stat_fetch_prepare(unsigned int *curr_pos, unsigned int *curr_index)
{
    cm_spin_lock(&g_judge_stats.lock, NULL);
    *curr_pos = (g_judge_stats.curr_pos + DMS_REFORM_JUDGE_STAT_SIZE - 1) % DMS_REFORM_JUDGE_STAT_SIZE;
    *curr_index = g_judge_stats.curr_index - 1;
    cm_spin_unlock(&g_judge_stats.lock);
}

void dms_reform_judgement_stat_fetch(unsigned int curr_pos, unsigned int curr_index, unsigned int *eof,
    long long int *times, char *desc, int len)
{
    if (curr_pos >= DMS_REFORM_JUDGE_STAT_SIZE) {
        *eof = CM_TRUE;
        return;
    }
    reform_judge_stat_t *stat = &g_judge_stats.stat[curr_pos];
    cm_spin_lock(&stat->lock, NULL);
    if (stat->index > curr_index || stat->index == 0) {
        cm_spin_unlock(&stat->lock);
        *eof = CM_TRUE;
        return;
    }

    for (uint32 i = 0; i < DMS_REFORM_JUDGE_COUNT; i++) {
        times[i] = stat->time[i];
    }

    errno_t ret = strcpy_s(desc, len, stat->desc);
    cm_spin_unlock(&stat->lock);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS REFORM]strcpy_s error");
    }
}