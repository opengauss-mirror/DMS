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
 * dms_dynamic_trace.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_dynamic_trace.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_dynamic_trace.h"
#include "dms_reform.h"
#include "dms_process.h"
#include "dms_error.h"
#include "cm_thread.h"
#include "cm_timer.h"

#ifdef __cplusplus
extern "C" {
#endif


dms_dyn_trc_t g_dms_dyn_trc;
thread_local_var int32 tls_sid = -1;
thread_local_var int32 is_reform_thrd = -1;

void dms_set_is_reform_thrd(bool32 is_rfm)
{
    is_reform_thrd = (int32)is_rfm;
}

static inline bool32 dms_is_reform_thread()
{
    return is_reform_thrd > 0;
}

void dms_set_tls_sid(int32 sid)
{
    tls_sid = sid;
}

int32 dms_get_tls_sid()
{
    return tls_sid;
}

static char* g_wait_event_dsc[] = {
    [DMS_EVT_DCS_REQ_MASTER4PAGE_1WAY] = __TO_STR(DMS_EVT_DCS_REQ_MASTER4PAGE_1WAY),
    [DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY] = __TO_STR(DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY),
    [DMS_EVT_DCS_REQ_MASTER4PAGE_3WAY] = __TO_STR(DMS_EVT_DCS_REQ_MASTER4PAGE_3WAY),
    [DMS_EVT_DCS_REQ_MASTER4PAGE_TRY] = __TO_STR(DMS_EVT_DCS_REQ_MASTER4PAGE_TRY),
    [DMS_EVT_DCS_REQ_OWNER4PAGE] = __TO_STR(DMS_EVT_DCS_REQ_OWNER4PAGE),
    [DMS_EVT_DCS_RELEASE_OWNER] = __TO_STR(DMS_EVT_DCS_RELEASE_OWNER),
    [DMS_EVT_DCS_INVLDT_SHARE_COPY_REQ] = __TO_STR(DMS_EVT_DCS_INVLDT_SHARE_COPY_REQ),
    [DMS_EVT_DCS_INVLDT_SHARE_COPY_PROCESS] = __TO_STR(DMS_EVT_DCS_INVLDT_SHARE_COPY_PROCESS),
    [DMS_EVT_DCS_TRANSFER_PAGE_LATCH] = __TO_STR(DMS_EVT_DCS_TRANSFER_PAGE_LATCH),
    [DMS_EVT_DCS_TRANSFER_PAGE_FLUSHLOG] = __TO_STR(DMS_EVT_DCS_TRANSFER_PAGE_FLUSHLOG),
    [DMS_EVT_DCS_TRANSFER_PAGE] = __TO_STR(DMS_EVT_DCS_TRANSFER_PAGE),
    [DMS_EVT_PCR_REQ_BTREE_PAGE] = __TO_STR(DMS_EVT_PCR_REQ_BTREE_PAGE),
    [DMS_EVT_PCR_REQ_HEAP_PAGE] = __TO_STR(DMS_EVT_PCR_REQ_HEAP_PAGE),
    [DMS_EVT_PCR_REQ_MASTER] = __TO_STR(DMS_EVT_PCR_REQ_MASTER),
    [DMS_EVT_PCR_REQ_OWNER] = __TO_STR(DMS_EVT_PCR_REQ_OWNER),
    [DMS_EVT_PCR_CHECK_CURR_VISIBLE] = __TO_STR(DMS_EVT_PCR_CHECK_CURR_VISIBLE),
    [DMS_EVT_TXN_REQ_INFO] = __TO_STR(DMS_EVT_TXN_REQ_INFO),
    [DMS_EVT_TXN_REQ_SNAPSHOT] = __TO_STR(DMS_EVT_TXN_REQ_SNAPSHOT),
    [DMS_EVT_QUERY_OWNER_ID] = __TO_STR(DMS_EVT_QUERY_OWNER_ID),
    [DMS_EVT_LATCH_X] = __TO_STR(DMS_EVT_LATCH_X),
    [DMS_EVT_LATCH_S] = __TO_STR(DMS_EVT_LATCH_S),
    [DMS_EVT_LATCH_X_REMOTE] = __TO_STR(DMS_EVT_LATCH_X_REMOTE),
    [DMS_EVT_LATCH_S_REMOTE] = __TO_STR(DMS_EVT_LATCH_S_REMOTE),
    [DMS_EVT_ONDEMAND_REDO] = __TO_STR(DMS_EVT_ONDEMAND_REDO),
    [DMS_EVT_PAGE_STATUS_INFO] = __TO_STR(DMS_EVT_PAGE_STATUS_INFO),
    [DMS_EVT_OPENGAUSS_SEND_XMIN] = __TO_STR(DMS_EVT_OPENGAUSS_SEND_XMIN),
    [DMS_EVT_DCS_REQ_CREATE_XA_RES] = __TO_STR(DMS_EVT_DCS_REQ_CREATE_XA_RES),
    [DMS_EVT_DCS_REQ_DELETE_XA_RES] = __TO_STR(DMS_EVT_DCS_REQ_DELETE_XA_RES),
    [DMS_EVT_DCS_REQ_XA_OWNER_ID] = __TO_STR(DMS_EVT_DCS_REQ_XA_OWNER_ID),
    [DMS_EVT_DCS_REQ_XA_IN_USE] = __TO_STR(DMS_EVT_DCS_REQ_XA_IN_USE),
    [DMS_EVT_DCS_REQ_END_XA] = __TO_STR(DMS_EVT_DCS_REQ_END_XA),
    [DMS_EVT_PROC_GENERIC_REQ] = __TO_STR(DMS_EVT_PROC_GENERIC_REQ),
    [DMS_EVT_DCS_CLAIM_OWNER] = __TO_STR(DMS_EVT_DCS_CLAIM_OWNER),
    [DMS_EVT_PROC_REFORM_REQ] = __TO_STR(DMS_EVT_PROC_REFORM_REQ),
};

char* dms_get_event_desc(dms_wait_event_t event)
{
    if (event >= DMS_EVT_COUNT) {
        return "INVLD_EVT_DESC";
    }

    char* desc = g_wait_event_dsc[event];
    if (desc == NULL || strlen(desc) == 0) {
        return "INVLD_EVT_DESC";
    }

    return desc;
}

static void dms_dyn_log_trace_dump(uint32 sid, dms_wait_event_t event)
{
    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
    bool8 event_ended = (sess_trc->level == 0);
    bool8 rfm_proc_evt = (event == DMS_EVT_PROC_REFORM_REQ);
    bool8 evt_errored = sess_trc->trc_dump_flag;

    if (!event_ended) {
        return;
    }

    if (rfm_proc_evt) {
        LOG_DMS_REFORM_TRACE(sess_trc->trc_buf, sess_trc->trc_len);
    }

    if (evt_errored) {
        sess_trc->trc_buf[sess_trc->trc_len++] = '\n';
        LOG_DMS_EVENT_TRACE(sess_trc->trc_buf, sess_trc->trc_len);
    }

    dms_dynamic_trace_reset(sess_trc);
}

static int dms_dynamic_trace_dump_iterator_inner(char** sess_trc_buf, unsigned char* ended)
{
    if (g_dms_dyn_trc.sess_iterator >= g_dms_dyn_trc.sess_cnt || !g_dms_dyn_trc.inited) {
        g_dms_dyn_trc.sess_iterator = 0;
        *ended = CM_TRUE;
        return DMS_SUCCESS;
    }

    *ended = CM_FALSE;
    dms_sess_dyn_trc_t *sess_trc = &g_dms_dyn_trc.sess_dyn_trc[g_dms_dyn_trc.sess_iterator];
    g_dms_dyn_trc.sess_iterator++;

    if (sess_trc->wait[0].is_waiting) {
        *sess_trc_buf = sess_trc->trc_buf;
        return DMS_SUCCESS;
    }

    return DMS_ERROR;
}

static unsigned char dms_dyn_trc_no_logs()
{
    return CM_FALSE;
}

static int dms_dyn_trc_init_trace_cb(dms_profile_t *dms_profile)
{
    if (dms_profile->enable_dyn_trace) {
        if (dms_profile->enable_reform_trace) {
            cm_register_dyn_trc_cbs(dms_dynamic_trace_fmt_cache, dms_dyn_trc_set_dump_flag, dms_dyn_trc_trace_reform);
        } else {
            cm_register_dyn_trc_cbs(dms_dynamic_trace_fmt_cache, dms_dyn_trc_set_dump_flag, dms_dyn_trc_no_logs);
        }
    } else {
        dms_profile->enable_reform_trace = CM_FALSE;
        cm_register_dyn_trc_cbs(NULL, NULL, NULL);
    }
    
    return DMS_SUCCESS;
}

/* for openGauss trc logger is inited in dms_init_logger */
static int dms_dyn_trc_init_logger(dms_profile_t *dms_profile)
{
#ifndef OPENGAUSS
    dms_reset_error();
    errno_t ret;
    log_param_t *log_param = cm_log_param_instance();
    log_param->log_backup_file_count = DMS_LOG_BACKUP_FILE_COUNT;
    log_param->audit_backup_file_count = DMS_LOG_BACKUP_FILE_COUNT;
    log_param->max_log_file_size = DMS_MAX_LOG_FILE_SIZE;
    log_param->max_audit_file_size = DMS_MAX_LOG_FILE_SIZE;

    const int file_perm = 600;
    const int path_perm = 700;
    cm_log_set_file_permissions(file_perm);
    cm_log_set_path_permissions(path_perm);
    (void)cm_set_log_module_name("DMS", sizeof("DMS"));
    ret = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, "DMS");
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, dms_profile->gsdb_home);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }

    CM_RETURN_IFERR(dms_dyn_trc_init_logger_handle());
#endif
    return DMS_SUCCESS;
}

int dms_init_dynamic_trace(dms_profile_t *dms_profile)
{
    g_dms_dyn_trc.dyn_trc_enabled = dms_profile->enable_dyn_trace;
    g_dms_dyn_trc.reform_trc_enabled = dms_profile->enable_dyn_trace && dms_profile->enable_reform_trace;
    g_dms_dyn_trc.sess_cnt = dms_profile->work_thread_cnt +
    dms_profile->channel_cnt + dms_profile->max_session_cnt;
    g_dms_dyn_trc.sess_iterator = 0;
    size_t size = g_dms_dyn_trc.sess_cnt * sizeof(dms_sess_dyn_trc_t);

    g_dms_dyn_trc.sess_dyn_trc = (dms_sess_dyn_trc_t *)dms_malloc(NULL, size);
    if (g_dms_dyn_trc.sess_dyn_trc == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    int ret = memset_s(g_dms_dyn_trc.sess_dyn_trc, size, 0, size);
    DMS_SECUREC_CHECK(ret);

    CM_RETURN_IFERR(dms_dyn_trc_init_logger(dms_profile));
    CM_RETURN_IFERR(dms_dyn_trc_init_trace_cb(dms_profile));
    g_dms_dyn_trc.inited = CM_TRUE;

    char date[CM_MAX_TIME_STRLEN];
    char buf[DMS_DYN_TRACE_HEADER_SZ];
    (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
    int len = snprintf_s(buf, DMS_DYN_TRACE_HEADER_SZ, DMS_DYN_TRACE_HEADER_SZ - 1,
        "\n%s>[DMS DYNAMIC TRACE]inited, reform trace=%hhu, overall trace=%hhu\n",
        date, dms_profile->enable_reform_trace, dms_profile->enable_dyn_trace);
    LOG_DMS_EVENT_TRACE(buf, len);
    return DMS_SUCCESS;
}

void dms_uninit_dynamic_trace()
{
    g_dms_dyn_trc.inited = CM_FALSE;
    DMS_FREE_PROT_PTR(g_dms_dyn_trc.sess_dyn_trc);
}

void dms_dyn_trc_begin(uint32 sid, dms_wait_event_t event)
{
    DMS_DYN_TRC_RETURN_IF_UNINITED();
    int32 curr_sid = dms_get_tls_sid();
    if (curr_sid == -1 || sid != (int32)curr_sid) {
        LOG_RUN_INF("[DMS][TRC]: thread binds new session, sid=%u", sid);
        dms_set_tls_sid((int32)sid);
    }

    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
    uint32 curr_level = sess_trc->level++;
    CM_ASSERT(sess_trc->level <= DMS_EVT_MAX_LEVEL);
    if (sess_trc->level > DMS_STAT_MAX_LEVEL) {
        LOG_RUN_WAR("[DMS][TRC]: stat level > upper limit, sid %u, currlevel %u",
            sid, curr_level);
        return;
    }

    sess_trc->wait[curr_level].is_waiting = CM_TRUE;
    sess_trc->wait[curr_level].event = event;
    char *evt_desc = dms_get_event_desc(event);
    (void)cm_gettimeofday(&sess_trc->wait[curr_level].begin_tv);
    if (event != DMS_EVT_PROC_REFORM_REQ) {
        LOG_DYN_TRC_INF("[DMS][TRC %u-%u]%s", sid, curr_level, evt_desc);
    }
}

void dms_dyn_trc_end_ex(uint32 sid, dms_wait_event_t event)
{
    DMS_DYN_TRC_RETURN_IF_UNINITED();
    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
    if (sess_trc->level == 0) {
        return;
    }

    uint32 curr_level = --sess_trc->level;
    if (event != DMS_EVT_PROC_REFORM_REQ) {
        LOG_DYN_TRC_INF("[DMS][TRC EVT %u-%u]END", sid, curr_level);
    }

    timeval_t tv_end;
    if (g_dms_dyn_trc.dyn_trc_enabled) {
        (void)cm_gettimeofday(&tv_end);
        sess_trc->wait[sess_trc->level].usecs =
            (uint64)TIMEVAL_DIFF_US(&sess_trc->wait[sess_trc->level].begin_tv, &tv_end);
    }

    sess_trc->wait[sess_trc->level].is_waiting = CM_FALSE;
    dms_dyn_log_trace_dump(sid, event);
}

void dms_dyn_trc_end(uint32 sid)
{
    DMS_DYN_TRC_RETURN_IF_UNINITED();
    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
    if (sess_trc->level == 0) {
        return;
    }
    CM_ASSERT(sess_trc->level <= DMS_EVT_MAX_LEVEL);
    if (sess_trc->level > DMS_STAT_MAX_LEVEL) {
        uint32 curr_level = --sess_trc->level;
        LOG_RUN_WAR("[DMS][TRC]level exceeds limit, sid=%u level=%u",
            sid, curr_level);
        return;
    }

    dms_dyn_trc_end_ex(sid, sess_trc->wait[sess_trc->level - 1].event);
}

void dms_dynamic_trace_cache_inner(dms_log_level_t log_level, char *buf_text, uint32 buf_size, bool8 is_head)
{
    int32 sid = dms_get_tls_sid();
    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;

    if (dms_is_reform_thread()) {
        MEMS_RETVOID_IFERR(strncat_s(sess_trc->trc_buf, DMS_MAX_DYN_TRACE_SIZE, buf_text, buf_size));
        sess_trc->trc_len += buf_size;
        if (!is_head) {
            LOG_DMS_REFORM_TRACE(buf_text, buf_size);
            dms_dynamic_trace_reset(sess_trc);
        }
        return;
    }

    if (log_level == DMS_LOG_LEVEL_ERROR) {
        dms_dyn_trc_set_dump_flag(CM_TRUE);
    }

    if (sess_trc->trc_len + buf_size >= DMS_MAX_DYN_TRACE_SIZE) {
        LOG_DMS_EVENT_TRACE_INHIBIT(LOG_INHIBIT_LEVEL3, DMS_MAX_DYN_TRC_WARN_BUF, DMS_MAX_DYN_TRC_WARN_SZ);
        LOG_DMS_EVENT_TRACE_INHIBIT(LOG_INHIBIT_LEVEL3, sess_trc->trc_buf, sess_trc->trc_len);
        dms_dynamic_trace_reset(sess_trc);
    }
    MEMS_RETVOID_IFERR(strncat_s(sess_trc->trc_buf, DMS_MAX_DYN_TRACE_SIZE, buf_text, buf_size));
    sess_trc->trc_len += buf_size;
}

static void dms_cache_trace_log_head(char *buf, uint32 buf_size, dms_log_level_t log_level, const char *module_name)
{
    char date[CM_MAX_TIME_STRLEN];
    text_t fmt_text;
    text_t date_text;
    date_text.str = date;
    date_text.len = 0;
    int len;
    int tz;
    int32 curr_sid = dms_get_tls_sid();
    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + curr_sid;
    bool is_reform_proc_log =
        (curr_sid != CM_INVALID_ID32 && sess_trc->wait[0].event == DMS_EVT_PROC_REFORM_REQ);

    if (dms_is_reform_thread() || is_reform_proc_log) {
        (void)cm_date2str(g_timer()->now, "yyyy-mm-dd hh24:mi:ss.ff3", date, CM_MAX_TIME_STRLEN);
        tz = g_timer()->tz;
        if (tz >= 0) {
            len = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC+%d %s|%s|%u>",
                tz, date, module_name, cm_get_current_thread_id());
        } else {
            len = snprintf_s(buf, (size_t)buf_size, CM_MAX_LOG_HEAD_LENGTH - 1, "UTC%d %s|%s|%u>",
                tz, date, module_name, cm_get_current_thread_id());
        }
        if (SECUREC_UNLIKELY(len == -1)) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, len);
            return;
        }
        dms_dynamic_trace_cache_inner(log_level, buf, len, CM_TRUE);
    } else {
        /* "yyyy-mm-dd" and cm_get_current_thread_id is ommitted for space and perf reasons */
        cm_str2text("hh24:mi:ss.ff3", &fmt_text);
        (void)cm_date2text_ex(g_timer()->now, &fmt_text, 0, &date_text, CM_MAX_TIME_STRLEN);
        date_text.str[date_text.len] = '>';
        date_text.len++;

        dms_dynamic_trace_cache_inner(log_level, date_text.str, date_text.len, CM_TRUE);
    }
}

/*
 * DMS side trace
 * cost:
 * for reform log, 2 snprintf_s(building loghead and content) + 2 strncat(loghead and content dms trace call)
 * for other event log, 1 snprintf_s(and content) + 2 strncat(loghead and content dms trace call)
 * file name and line num is not printed for performance.
 */
void dms_dynamic_trace_fmt_cache(int log_type, int log_level, const char *code_file_name,
    unsigned int code_line_num, const char *module_name, const char *format, ...)
{
    DMS_DYN_TRC_RETURN_IF_INVLD_SESS();
    char log_head[CM_MAX_LOG_HEAD_LENGTH];
    char log_body[CM_MAX_LOG_CONTENT_LENGTH];
    va_list args;

    va_start(args, format);
    dms_cache_trace_log_head(log_head, CM_MAX_LOG_HEAD_LENGTH, log_level, module_name);
    int len = vsnprintf_s(log_body, CM_MAX_LOG_CONTENT_LENGTH, CM_MAX_LOG_CONTENT_LENGTH - 1, format, args);
    if (len == -1) {
        LOG_RUN_ERR("dms_dynamic_trace_fmt_cache failed to build trc log content");
    } else {
        log_body[len] = '\n';
        dms_dynamic_trace_cache_inner(log_level, log_body, len + 1, CM_FALSE);
    }
    va_end(args);
}

DMS_DECLARE unsigned char dms_dyn_trc_is_tracing()
{
    int32 sid = dms_get_tls_sid();
    if (!dms_dyn_trc_inited() || !DMS_SID_IS_VALID(sid)) {
        return CM_FALSE;
    }

    if (dms_is_reform_thread() && g_dms_dyn_trc.reform_trc_enabled) {
        return CM_TRUE;
    }

    dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
    return (sess_trc && sess_trc->wait[0].is_waiting);
}

DMS_DECLARE void dms_dyn_trc_set_dump_flag(bool8 has_err)
{
    DMS_DYN_TRC_RETURN_IF_UNINITED();
    int32 sid = dms_get_tls_sid();
    dms_sess_dyn_trc_t *sess_trc = NULL;
    if (DMS_SID_IS_VALID(sid) && g_dms_dyn_trc.sess_dyn_trc) {
        sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
        sess_trc->trc_dump_flag = has_err;
    }
}

DMS_DECLARE unsigned char dms_dyn_trc_trace_reform(void)
{
    return dms_is_reform_thread();
}

/* DB side trace */
DMS_DECLARE void dms_dynamic_trace_cache(unsigned int log_level, char *buf_text, unsigned int buf_size)
{
    DMS_DYN_TRC_RETURN_IF_INVLD_SESS();
    dms_dynamic_trace_cache_inner((dms_log_level_t)log_level, buf_text, buf_size, CM_FALSE);
}

/* DB side trace iterator for bbox dump */
DMS_DECLARE int dms_dynamic_trace_dump_iterator(char **sess_trc_buf, unsigned char* ended)
{
    return dms_dynamic_trace_dump_iterator_inner(sess_trc_buf, ended);
}

#ifdef __cplusplus
}
#endif