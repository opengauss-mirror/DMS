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
 * dms_dynamic_trace.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_dynamic_trace.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_DYNAMIC_TRACE_H__
#define __DMS_DYNAMIC_TRACE_H__

#include "cm_types.h"
#include "cm_defs.h"
#include "dms_api.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_EVT_MAX_LEVEL 10
#define DMS_MAX_DYN_TRACE_SIZE SIZE_K(2)
#define DMS_DYN_TRACE_HEADER_SZ 256
#define DMS_SID_IS_VALID(sid) (sid >= 0 && sid < g_dms_dyn_trc.sess_cnt)

typedef struct st_dms_event_trc {
    bool32 is_waiting;
    dms_wait_event_t event;
    date_t begin_time;
    uint64 usecs;
    uint64 pre_spin_usecs;
    timeval_t begin_tv;
} dms_event_trc_t;

typedef struct st_dms_sess_dyn_trc {
    dms_event_trc_t wait[DMS_EVT_MAX_LEVEL];
    uint32 level;
    char trc_buf[DMS_MAX_DYN_TRACE_SIZE];
    uint32 trc_len;
    char trc_dump_flag;
} dms_sess_dyn_trc_t;

typedef struct st_dms_dyn_trc {
    bool32 dyn_trc_enabled;
    bool32 reform_trc_enabled;
    uint32 sess_cnt;
    dms_sess_dyn_trc_t *sess_dyn_trc;
    uint32 sess_iterator;
    bool8 inited;
} dms_dyn_trc_t;

extern dms_dyn_trc_t g_dms_dyn_trc;

void dms_set_is_reform_thrd(bool32 is_rfm);
char* dms_get_event_desc(dms_wait_event_t event);
void dms_set_tls_sid(int32 sid);
int32 dms_get_tls_sid();

int dms_init_dynamic_trace(dms_profile_t *dms_profile);
void dms_uninit_dynamic_trace();
void dms_dyn_trc_begin(uint32 sid, dms_wait_event_t event);
void dms_dyn_trc_end(uint32 sid);
void dms_dyn_trc_end_ex(uint32 sid, dms_wait_event_t event);
void dms_dynamic_trace_fmt_cache(int log_type, int log_level, const char *code_file_name,
    unsigned int code_line_num, const char *module_name, const char *format, ...);

static inline bool8 dms_dyn_trc_inited()
{
    return g_dms_dyn_trc.inited && g_dms_dyn_trc.sess_dyn_trc && g_dms_dyn_trc.dyn_trc_enabled;
}

static inline void dms_dynamic_trace_reset(dms_sess_dyn_trc_t* sess_dyn_trc)
{
    sess_dyn_trc->trc_dump_flag = CM_FALSE;
    sess_dyn_trc->trc_len = 0;
    sess_dyn_trc->trc_buf[0] = '\0';
}

#define DMS_DYN_TRC_RETURN_IF_UNINITED()    \
    do {                                    \
        if (!dms_dyn_trc_inited()) {        \
            return;                         \
        }                                   \
    } while (0)

#define DMS_DYN_TRC_RETURN_IF_INVLD_SESS()                              \
    do {                                                                \
        if (!dms_dyn_trc_is_tracing()) {                                \
            return;                                                     \
        }                                                               \
    } while (0)
    

#ifdef __cplusplus
}
#endif

#endif /* __DMS_DYNAMIC_TRACE_H__ */