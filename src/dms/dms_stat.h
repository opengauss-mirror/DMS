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
 * dms_stat.h
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_STAT_H__
#define __DMS_STAT_H__

#include "dms.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_STAT_MAX_LEVEL 5

typedef struct st_session_wait {
    bool32 is_waiting;
    dms_wait_event_t event;
    bool32 immediate;
    date_t begin_time;
    uint64 usecs;
    uint64 pre_spin_usecs;
    timeval_t begin_tv;
} session_wait_t;

typedef struct st_session_stat {
    uint64 stat[DMS_STAT_COUNT];
    uint64 wait_time[DMS_EVT_COUNT];
    uint64 wait_count[DMS_EVT_COUNT];

    session_wait_t wait[DMS_STAT_MAX_LEVEL];
    uint32 level;
} session_stat_t;

typedef struct st_dms_stat {
    bool32 time_stat_enabled;
    uint32 sess_cnt;
    session_stat_t *sess_stats;
} dms_stat_t;

extern dms_stat_t g_dms_stat;

#define DMS_STAT_INC_BUFFER_GETS(sess_id) \
    do { \
        session_stat_t *stat = g_dms_stat.sess_stats + (sess_id); \
        stat->stat[DMS_STAT_BUFFER_GETS]++; \
    }while (0)

#define DMS_STAT_INC_BUFFER_SENDS(sess_id) \
    do { \
        session_stat_t *stat = g_dms_stat.sess_stats + (sess_id); \
        stat->stat[DMS_STAT_BUFFER_SENDS]++; \
    }while (0)

#define DMS_STAT_INC_NET_TIME(sess_id, time) \
    do { \
        session_stat_t *stat = g_dms_stat.sess_stats + (sess_id); \
        stat->stat[DMS_STAT_NET_TIME] += (time); \
    }while (0)

#define DMS_GET_SESSION_STAT(sess_id) (g_dms_stat.sess_stats + (sess_id))

// add wait stack, then event can be nested, paramter of nested max is DMS_STAT_MAX_LEVEL
void dms_begin_stat(uint32     sid, dms_wait_event_t event, bool32 immediate);

// the event is still the same as specified by dms_begin_stat().
void dms_end_stat(uint32    sid);

// the event may change due to different code flows between dms_begin_stat() and dms_end_stat_ex().
// the new event is specified by the parameter of event.
void dms_end_stat_ex(uint32 sid, dms_wait_event_t event);


#ifdef __cplusplus
}
#endif

#endif /* __DMS_STAT_H__ */

