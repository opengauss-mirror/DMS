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
 * dms_smon.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_smon.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_smon.h"
#include "dms_dynamic_trace.h"
#include "cmpt_msg_mesi.h"
#include "drc_page.h"

bool32 dms_the_same_drc_req(drc_request_info_t *req1, drc_request_info_t *req2)
{
    if (req1->inst_id == req2->inst_id && req1->curr_mode == req2->curr_mode && req1->req_mode == req2->req_mode &&
        req1->sess_id == req2->sess_id && req1->ruid == req2->ruid &&
        req1->srsn == req2->srsn && req1->req_time == req2->req_time) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static int32 dms_smon_send_confirm_req(res_id_t *res_id, drc_request_info_t *cvt_req, uint64 *ruid)
{
    dms_confirm_cvt_req_t req;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_CONFIRM_CVT, 0,
        g_dms.inst_id, cvt_req->inst_id, ctx->smon_sid, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_confirm_cvt_req_t);
    req.res_type = res_id->type;
    req.cvt_mode = cvt_req->req_mode;
    errno_t err = memcpy_s(req.resid, DMS_RESID_SIZE, res_id->data, res_id->len);
    DMS_SECUREC_CHECK(err);

    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_CONFIRM_CVT, MSG_REQ_CONFIRM_CVT);
    int ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS]dms_smon_send_confirm_req send error, dst_id: %d", cvt_req->inst_id);
        *ruid = req.head.ruid;
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, req.head.cmd, req.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    *ruid = req.head.ruid;
    LOG_DEBUG_INF("[DMS]dms_smon_send_confirm_req send ok dst_id: %d", cvt_req->inst_id);
    return DMS_SUCCESS;
}

static void dms_smon_handle_ready_ack(dms_process_context_t *ctx,
    res_id_t *res_id, drc_request_info_t *cvt_req, dms_confirm_cvt_ack_t *ack)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);
    if (drc_enter(res_id->data, res_id->len, res_id->type, options, &drc) != DMS_SUCCESS || drc == NULL) {
        return;
    }

    if (!dms_the_same_drc_req(&drc->converting.req_info, cvt_req)) {
        drc_leave(drc, options);
        return;
    }

    bool32 has_edp = CM_FALSE;
    if (drc->owner != CM_INVALID_ID8) {
        has_edp = bitmap64_exist(&ack->edp_map, drc->owner);
    }
    claim_info_t claim_info;
    (void)dms_set_claim_info(&claim_info, DRC_DATA(drc), drc->len, drc->type, cvt_req->inst_id,
        ack->lock_mode, (bool8)has_edp, ack->lsn, cvt_req->sess_id, DMS_SESSION_NORMAL, cvt_req->srsn);

    cvt_info_t cvt_info;
    drc_convert_page_owner(drc, &claim_info, &cvt_info);
    LOG_DEBUG_INF("[DMS][%s][dms_smon_handle_ready_ack]: mode=%d, owner=%d, copy_insts=%llu",
        cm_display_resid(res_id->data, res_id->type), drc->lock_mode, drc->owner, drc->copy_insts);
    drc_leave(drc, options);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(claim_info.resid, claim_info.res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(ctx, cvt_info.resid, cvt_info.len, cvt_info.res_type,
            cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_FALSE, cvt_info.seq, &cvt_info.req_info);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(ctx, cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
            return;
        }
    }
    dms_handle_cvt_info(ctx, &cvt_info);
}

static void dms_smon_handle_cancel_ack(dms_process_context_t *ctx, res_id_t *res_id,
    drc_request_info_t *cvt_req)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);
    if (drc_enter(res_id->data, res_id->len, res_id->type, options, &drc) != DMS_SUCCESS || drc == NULL) {
        return;
    }

    if (!dms_the_same_drc_req(&drc->converting.req_info, cvt_req)) {
        drc_leave(drc, options);
        return;
    }

    cvt_info_t cvt_info;
    cvt_info.invld_insts = 0;
    cvt_info.req_id = CM_INVALID_ID8;

    (void)drc_cancel_converting(drc, cvt_req, &cvt_info);
    drc_leave(drc, options);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu", cm_display_resid(res_id->data, res_id->type),
            cvt_info.invld_insts);
        int32 ret = dms_invalidate_share_copy(ctx, cvt_info.resid, cvt_info.len, cvt_info.res_type,
            cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_FALSE, cvt_info.seq, &cvt_info.req_info);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(ctx, cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
            return;
        }
    }
    dms_handle_cvt_info(ctx, &cvt_info);
}

static void dms_smon_handle_confirm_ack(uint64 ruid, res_id_t *res_id, drc_request_info_t *cvt_req)
{
    dms_message_t msg = { 0 };
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    int32 ret = mfc_get_response(ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: wait ack timeout, src_id=%u, src_sid=%u, dst_id=%u",
            cm_display_resid(res_id->data, res_id->type), "CONFIRM CVT", (uint32)g_dms.inst_id,
            (uint32)ctx->smon_sid, (uint32)cvt_req->inst_id);
        return;
    }
    dms_confirm_cvt_ack_t ack = *(dms_confirm_cvt_ack_t *)msg.buffer;
    mfc_release_response(&msg);

    LOG_DEBUG_INF("[DMS][%s] recv confirm ack [result:%u edp_map:%llu lsn:%llu]",
        cm_display_resid(res_id->data, res_id->type), (uint32)ack.result, ack.edp_map, ack.lsn);

    dms_process_context_t proc_ctx;
    proc_ctx.inst_id = (uint8)g_dms.inst_id;
    proc_ctx.sess_id = DRC_RES_CTX->smon_sid;
    proc_ctx.db_handle = DRC_RES_CTX->smon_handle;

    if (ack.result == CONFIRM_READY) {
        dms_smon_handle_ready_ack(&proc_ctx, res_id, cvt_req, &ack);
        return;
    }

    if (ack.result == CONFIRM_CANCEL) {
        dms_smon_handle_cancel_ack(&proc_ctx, res_id, cvt_req);
    }
}

static void dms_smon_confirm_converting(res_id_t *res_id)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);
    int ret = drc_enter(res_id->data, res_id->len, res_id->type, options, &drc);
    if (ret != DMS_SUCCESS || drc == NULL) {
        return;
    }

    if (drc->converting.req_info.inst_id == CM_INVALID_ID8) {
        drc_leave(drc, options);
        return;
    }
    drc_request_info_t cvt_req = drc->converting.req_info;
    drc_leave(drc, options);

    LOG_DEBUG_WAR("[DMS][%s] start confirm converting [inst:%u sid:%u ruid:%llu req_mode:%u]",
        cm_display_resid(res_id->data, res_id->type), (uint32)cvt_req.inst_id,
        (uint32)cvt_req.sess_id, cvt_req.ruid, (uint32)cvt_req.req_mode);

    uint64 ruid;
    if (dms_smon_send_confirm_req(res_id, &cvt_req, &ruid) != DMS_SUCCESS) {
        return;
    }

    dms_smon_handle_confirm_ack(ruid, res_id, &cvt_req);
}

static void dms_event_trace_monitor(void)
{
    char buf[DMS_DYN_TRACE_HEADER_SZ];
    int len = 0;
    for (int sid = 0; sid < g_dms_stat.sess_cnt; sid++) {
        if (!dms_dyn_trc_inited() || !DMS_SID_IS_VALID(sid)) {
            return;
        }
        dms_sess_dyn_trc_t *sess_trc = g_dms_dyn_trc.sess_dyn_trc + sid;
        if (sess_trc->wait[0].is_waiting) {
            timeval_t begin = sess_trc->wait[0].begin_tv;
            timeval_t end;
            (void)cm_gettimeofday(&end);
            if ((uint64)TIMEVAL_DIFF_US(&begin, &end) >= DMS_EVENT_MONITOR_TIMEOUT && sess_trc->trc_len > 0) {
                char endstr[CM_MAX_TIME_STRLEN];
                char beginstr[CM_MAX_TIME_STRLEN];
                date_t begin_dt = cm_timeval2date(begin);
                date_t end_dt = cm_timeval2date(end);
                (void)cm_date2str(begin_dt, "yyyy-mm-dd hh24:mi:ss.ff3", beginstr, CM_MAX_TIME_STRLEN);
                (void)cm_date2str(end_dt, "yyyy-mm-dd hh24:mi:ss.ff3", endstr, CM_MAX_TIME_STRLEN);
                len = snprintf_s(buf, DMS_DYN_TRACE_HEADER_SZ, DMS_DYN_TRACE_HEADER_SZ - 1,
                    "[DYN TRC WARN]HANG DETECTED sid=%d evt=%s begin=%s curr=%s trc:\n",
                    sid, dms_get_event_desc(sess_trc->wait[0].event), beginstr, endstr);
                sess_trc->trc_buf[sess_trc->trc_len++] = '\n';
                LOG_DMS_EVENT_TRACE(buf, len);
                LOG_DMS_EVENT_TRACE(sess_trc->trc_buf, sess_trc->trc_len);
            }
        }
    }
}

void dms_smon_entry(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    res_id_t res_id;
    date_t begin = cm_clock_monotonic_now();
    date_t end;

    DRC_RES_CTX->smon_handle = g_dms.callback.get_db_handle(&DRC_RES_CTX->smon_sid, DMS_SESSION_TYPE_NONE);
    cm_panic_log(DRC_RES_CTX->smon_handle != NULL, "alloc db handle failed");
    mes_block_sighup_signal();

    while (!thread->closed) {
        end = cm_clock_monotonic_now();
        if ((end - begin) >= DMS_EVENT_MONITOR_INTERVAL) {
            begin = end;
            dms_event_trace_monitor();
        }
        if (cm_chan_recv_timeout(DRC_RES_CTX->chan, (void *)&res_id, DMS_MSG_SLEEP_TIME) != CM_SUCCESS) {
            continue;
        }
        dms_smon_confirm_converting(&res_id);
    }
}
