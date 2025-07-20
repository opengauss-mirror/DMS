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
 * dms_reform_judge_stat.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_stat.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_JUDGE_STAT_H__
#define __DMS_REFORM_JUDGE_STAT_H__

#include "cm_timer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_reform_judge_step {
    DMS_REFORM_JUDGE_START = 0,
    DMS_REFORM_JUDGE_GET_LIST_ONLINE,
    DMS_REFORM_JUDGE_GET_LIST_STABLE,
    DMS_REFORM_JUDGE_CONNECT,
    DMS_REFORM_JUDGE_GET_ONLINE_STATUS,
    DMS_REFORM_JUDGE_CHECK_REMOTE,
    DMS_REFORM_JUDGE_REFRESH_REFORM_INFO,
    DMS_REFORM_JUDGE_SYNC_GCV,
    DMS_REFORM_JUDGE_REFRESH_MAP_INFO,
    DMS_REFORM_JUDGE_PROC,
    DMS_REFORM_JUDGE_SYNC_SHARE_INFO,
    DMS_REFORM_JUDGE_END,

    DMS_REFORM_JUDGE_COUNT
} reform_judge_step_t;

typedef struct st_reform_judge_stat {
    spinlock_t      lock;
    uint32          index;
    date_t          time[DMS_REFORM_JUDGE_COUNT];
    char            desc[CM_BUFLEN_32];
} reform_judge_stat_t;

#define DMS_REFORM_JUDGE_STAT_SIZE      1024
typedef struct st_reform_judge_stats {
    reform_judge_stat_t     stat[DMS_REFORM_JUDGE_STAT_SIZE];
    spinlock_t              lock;
    uint32                  curr_pos;
    uint32                  curr_index;
    bool32                  start;
} reform_judge_stats_t;

void dms_reform_judgement_stat_init(void);
void dms_reform_judgement_stat_start(void);
void dms_reform_judgement_stat_step(reform_judge_step_t step);
void dms_reform_judgement_stat_desc(char *desc);
void dms_reform_judgement_stat_cancel(void);
void dms_reform_judgement_stat_end(void);

#ifdef __cplusplus
}
#endif
#endif