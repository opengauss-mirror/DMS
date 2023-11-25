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
#include "dms_api.h"
#include "cm_atomic.h"
#include "dms_msg.h"
#include "cm_error.h"

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

typedef struct st_dms_time_consume {
    uint64 time[MSG_CMD_CEIL];
    int64 count[MSG_CMD_CEIL];
    spinlock_t lock[MSG_CMD_CEIL];
} dms_time_consume_t;

extern dms_time_consume_t g_dms_time_consume;

typedef struct st_wait_cmd_desc {
    msg_command_t cmd;
    char name[DMS_MAX_NAME_LEN];
    char p1[DMS_MAX_NAME_LEN];
    char wait_class[DMS_MAX_NAME_LEN];
} wait_cmd_desc_t;

static inline uint64 dms_cm_get_time_usec(void)
{
    if (g_dms_stat.time_stat_enabled) {
        timeval_t now;
        (void)cm_gettimeofday(&now);
        uint64 now_usec = (uint64)now.tv_sec * MICROSECS_PER_SECOND + (uint64)now.tv_usec;
        return now_usec;
    }
    return 0;
}

static inline void dms_consume_with_time(uint32 cmd, uint64 start_time, int ret)
{
    if (start_time == 0 || !g_dms_stat.time_stat_enabled || ret != CM_SUCCESS) {
        return;
    }

    uint64 elapsed_time = dms_cm_get_time_usec() - start_time;
    cm_spin_lock(&(g_dms_time_consume.lock[cmd]), NULL);
    g_dms_time_consume.time[cmd] += elapsed_time;
    (void)cm_atomic_inc(&(g_dms_time_consume.count[cmd]));
    cm_spin_unlock(&(g_dms_time_consume.lock[cmd]));
    return;
}

#ifdef __cplusplus
}
#endif

#endif /* __DMS_STAT_H__ */

