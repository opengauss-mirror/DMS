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
 * dcs_cr_page.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_cr_page.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_cr_page.h"
#include "dcs_page.h"
#include "dcs_msg.h"
#include "drc_res_mgr.h"
#include "dms_error.h"
#include "dms_msg_command.h"
#include "dms_msg_protocol.h"
#include "dms_stat.h"
#include "dms_dynamic_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENGAUSS
static int dcs_send_pcr_ack(dms_process_context_t *ctx, msg_pcr_request_t *request, char *page, bool8 *fb_mark)
{
    int ret;
    msg_pcr_ack_t msg;

    dms_init_ack_head(&request->head, &msg.head, MSG_ACK_CR_PAGE,
        (uint16)(sizeof(msg_pcr_ack_t) + g_dms.page_size), ctx->sess_id);
    msg.head.src_inst = ctx->inst_id;
    CM_ASSERT(request->head.dst_inst == ctx->inst_id);
    msg.force_cvt = request->force_cvt;
    if (fb_mark != NULL) {
        msg.head.size += (uint16)g_dms.page_size;
    }

    LOG_DEBUG_INF("[PCR][%s][send pcr ack] cr_type %u src_inst %u src_sid %u dst_inst %u dst_sid %u force_cvt %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, (uint32)msg.head.src_inst,
        (uint32)msg.head.src_sid, (uint32)msg.head.dst_inst,
        (uint32)msg.head.dst_sid, (uint32)msg.force_cvt);

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_CR_PAGE, MSG_ACK_CR_PAGE);
    if (fb_mark == NULL) {
        ret = mfc_send_data3(&msg.head, sizeof(msg_pcr_ack_t), page);
    } else {
        ret = mfc_send_data4(&msg.head, sizeof(msg_pcr_ack_t), page, g_dms.page_size, fb_mark, g_dms.page_size);
    }

    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, msg.head.cmd, msg.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_send_pcr_request(dms_process_context_t *ctx, msg_pcr_request_t *request, uint8 dst_id)
{
    int ret = DMS_SUCCESS;
    request->head.dst_inst = dst_id;

    LOG_DEBUG_INF("[PCR][%s][send pcr request] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u force_cvt %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)request->head.src_inst, (uint32)request->head.src_sid, (uint32)dst_id, (uint32)request->force_cvt);

    if (dst_id == request->head.src_inst) {
        ret = mfc_send_response(&request->head);
    } else {
        ret = mfc_forward_request(&request->head);
    }
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, request->head.cmd, request->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_send_txn_wait(dms_process_context_t *ctx, msg_pcr_request_t *request, char *wxid)
{
    msg_txn_wait_t msg ;
    dms_init_ack_head(&request->head, &msg.head, MSG_ACK_TXN_WAIT, sizeof(msg_txn_wait_t), ctx->sess_id);
    msg.head.src_inst = ctx->inst_id;
    CM_ASSERT(request->head.dst_inst == ctx->inst_id);
    errno_t err = memcpy_sp(msg.wxid, DMS_XID_SIZE, wxid, DMS_XID_SIZE);
    DMS_SECUREC_CHECK(err);

    LOG_DEBUG_INF("[PCR][%s][send txn wait] wxid %s src_inst %u src_sid %u dst_inst %u dst_sid %u",
        cm_display_pageid(request->pageid), cm_display_xid(wxid), (uint32)msg.head.src_inst,
        (uint32)msg.head.src_sid, (uint32)msg.head.dst_inst, (uint32)msg.head.dst_sid);

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_TXN_WAIT, MSG_ACK_TXN_WAIT);
    int ret = mfc_send_data(&msg.head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, msg.head.cmd, msg.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static void dcs_init_pcr_assist(dms_cr_assist_t *pcr, void *handle, uint64 query_scn,
    uint32 ssn, char *cr_page, char *xid, char *pageid, char *rowid)
{
    errno_t ret = memset_s(pcr, sizeof(dms_cr_assist_t), 0, sizeof(dms_cr_assist_t));
    DMS_SECUREC_CHECK(ret);
    pcr->handle = handle;
    pcr->query_scn = query_scn;
    pcr->ssn = ssn;
    pcr->page = cr_page;
    ret = memcpy_s(pcr->curr_xid, DMS_XID_SIZE, xid, DMS_XID_SIZE);
    DMS_SECUREC_CHECK(ret);
    if (pageid != NULL) {
        ret = memcpy_s(pcr->page_id, DMS_PAGEID_SIZE, pageid, DMS_PAGEID_SIZE);
        DMS_SECUREC_CHECK(ret);
    }
    if (rowid != NULL) {
        ret = memcpy_s(pcr->rowid, DMS_ROWID_SIZE, rowid, DMS_ROWID_SIZE);
        DMS_SECUREC_CHECK(ret);
    }
}

static int dcs_handle_pcr_result(dms_process_context_t *ctx,
    msg_pcr_request_t *request, dms_cr_assist_t *pcr)
{
    int ret = DMS_SUCCESS;
    /* 
     * send message according to CR construct result
     */
    switch (pcr->status) {
        case DMS_CR_STATUS_ALL_VISIBLE:
            ret = dcs_send_pcr_ack(ctx, request, pcr->page, (bool8 *)pcr->fb_mark);
            break;
        case DMS_CR_STATUS_PENDING_TXN:
            ret = dcs_send_txn_wait(ctx, request, pcr->wxid);
            break;
        case DMS_CR_STATUS_OTHER_NODE_INVISIBLE_TXN:
            ret = dcs_send_pcr_request(ctx, request, pcr->relay_inst);
            break;
        case DMS_CR_STATUS_ABORT:
            ret = DMS_ERROR;
            break;
        case DMS_CR_STATUS_DB_NOT_READY:
            LOG_DEBUG_INF("[DCS]dcs_handle_pcr_result, db is not ready");
            ret = DMS_SUCCESS;
            break;
        case DMS_CR_STATUS_INVISIBLE_TXN:
            /* it's impossible here, because local invisible transaction has been rollbacked */
            /* fall-through */
        default:
            cm_panic_log(0, "invalid consistent-read construct status: %d", pcr->status);
            break;
    }
    return ret;
}

static int dcs_heap_construct_cr_page(dms_process_context_t *ctx, msg_pcr_request_t *request)
{
    char *cr_page = NULL;
    bool8 *fb_mark = NULL;
    dms_cr_assist_t pcr;

    cr_page = (char *)((char *)request + sizeof(msg_pcr_request_t));
    if (request->head.size > sizeof(msg_pcr_request_t) + g_dms.page_size) {
        if (request->head.size < sizeof(msg_pcr_request_t) + 2 * g_dms.page_size) {
            DMS_THROW_ERROR(ERRNO_DMS_MES_INVALID_MSG);
            return ERRNO_DMS_MES_INVALID_MSG;
        }
        fb_mark = (bool8 *)((char *)request + sizeof(msg_pcr_request_t) + g_dms.page_size);
    }

    dcs_init_pcr_assist(&pcr, ctx->db_handle, request->query_scn, request->ssn, cr_page,
        request->xid, request->pageid, NULL);
    pcr.fb_mark = (char *)fb_mark;
    if (g_dms.callback.heap_construct_cr_page(&pcr) != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    return dcs_handle_pcr_result(ctx, request, &pcr);
}

static int dcs_btree_construct_cr_page(dms_process_context_t *ctx, msg_pcr_request_t *request)
{
    errno_t ret;
    msg_index_pcr_request_t *index_pcr_req = (msg_index_pcr_request_t *)request;
    char *cr_page = (char *)((char *)request + sizeof(msg_index_pcr_request_t));

    dms_cr_assist_t pcr;
    dcs_init_pcr_assist(&pcr, ctx->db_handle, index_pcr_req->pcr_request.query_scn,
        index_pcr_req->pcr_request.ssn, cr_page, index_pcr_req->pcr_request.xid,
        index_pcr_req->pcr_request.pageid, NULL);
    ret = memcpy_s(pcr.entry, DMS_PAGEID_SIZE, index_pcr_req->entry, DMS_PAGEID_SIZE);
    DMS_SECUREC_CHECK(ret);
    ret = memcpy_s(pcr.profile, DMS_INDEX_PROFILE_SIZE, index_pcr_req->profile, DMS_INDEX_PROFILE_SIZE);
    DMS_SECUREC_CHECK(ret);

    if (g_dms.callback.btree_construct_cr_page(&pcr) != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    return dcs_handle_pcr_result(ctx, request, &pcr);
}

static void dcs_handle_pcr_request(dms_process_context_t *ctx, dms_message_t *msg)
{
    int ret = DMS_SUCCESS;
    const char *err_msg = NULL;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(msg, (uint32)sizeof(msg_pcr_request_t), CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);

    uint32 total_size = request->cr_type == CR_TYPE_HEAP ? sizeof(msg_pcr_request_t) : sizeof(msg_index_pcr_request_t);
    total_size += g_dms.page_size;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(msg, total_size, CM_TRUE);

    if (request->cr_type == CR_TYPE_HEAP) {
        LOG_DEBUG_INF("[DCS][dcs_handle_pcr_request]:src_inst=%d, dst_inst=%d, src_sid=%u, dst_sid=%u, cr_type=%s, "
            "force_cvt=%d, ssn=%u, query_scn=%llu, pageid=%s, xid=%s", (int32)request->head.src_inst,
            (int32)request->head.dst_inst, (uint32)request->head.src_sid, (uint32)request->head.dst_sid,
            "heap", (int32)request->force_cvt, (uint32)request->ssn, (uint64)request->query_scn,
            cm_display_pageid(request->pageid), cm_display_xid(request->xid));
    } else {
        LOG_DEBUG_INF("[DCS][dcs_handle_pcr_request]:src_inst=%d, dst_inst=%d, src_sid=%u, dst_sid=%u, cr_type=%s, "
            "force_cvt=%d, ssn=%u, query_scn=%llu, pageid=%s, xid=%s, entry=%s", (int32)request->head.src_inst,
            (int32)request->head.dst_inst, (uint32)request->head.src_sid, (uint32)request->head.dst_sid,
            "heap", (int32)request->force_cvt, (uint32)request->ssn, (uint64)request->query_scn,
            cm_display_pageid(request->pageid), cm_display_xid(request->xid),
            cm_display_pageid(((msg_index_pcr_request_t *)request)->entry));
    }

    /*
     * NOTE:
     * synchronize SCN before construct CR page is vitally important here,
     * it decides whether cross-instance-read is consistent-read or not!
     */
    g_dms.callback.update_global_scn(ctx->db_handle, request->query_scn);

    switch (request->cr_type) {
        case CR_TYPE_HEAP:
            ret = dcs_heap_construct_cr_page(ctx, request);
            err_msg = "failed to construct heap CR page";
            break;
        case CR_TYPE_BTREE:
            ret = dcs_btree_construct_cr_page(ctx, request);
            err_msg = "failed to construct btree CR page";
            break;
        default:
            cm_send_error_msg(msg->head, ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "capability not support");
            break;
    }

    if (ret != DMS_SUCCESS) {
        cm_send_error_msg(msg->head, ret, (char *)err_msg);
    }
}
#endif

void dcs_proc_pcr_request(dms_process_context_t *process_ctx, dms_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        LOG_DEBUG_ERR("PCR should not process req as ack any more!");
        return;
    }

    dcs_handle_pcr_request(process_ctx, recv_msg);
#endif
}

static int dcs_init_pcr_request(msg_pcr_request_t *request, dms_context_t *dms_ctx, dms_cr_t *dms_cr, cr_type_t type)
{
    int ret;
    request->cr_type = type;

    ret = memcpy_sp(request->pageid, DMS_PAGEID_SIZE, dms_ctx->resid, DMS_PAGEID_SIZE);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    g_dms.callback.get_xid_from_cr_cursor(dms_cr->cr_cursor, request->xid);

    request->query_scn = dms_cr->query_scn;
    request->ssn = dms_cr->ssn;
    request->force_cvt = 0;
    request->sess_type = dms_ctx->sess_type;

    return DMS_SUCCESS;
}

static int dcs_proc_msg_req_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, dms_message_t *message)
{
    CM_CHK_PROC_MSG_SIZE(message, (uint32)sizeof(msg_pcr_request_t), CM_FALSE);
    msg_pcr_request_t *reply = (msg_pcr_request_t *)(message->buffer);
    uint32 head_size = (reply->cr_type != CR_TYPE_BTREE) ? sizeof(msg_pcr_request_t) : sizeof(msg_index_pcr_request_t);

    CM_CHK_PROC_MSG_SIZE(message, (uint32)(head_size + g_dms.page_size), CM_FALSE);
    char *recv_page = (char *)reply + head_size;
    int ret = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }
    if (dms_cr->fb_mark != NULL) {
        CM_CHK_PROC_MSG_SIZE(message, (uint32)(head_size + 2 * g_dms.page_size), CM_FALSE);
        bool8 *fb_mark = (bool8*)(message->buffer + head_size + g_dms.page_size);
        ret = memcpy_sp((char*)dms_cr->fb_mark, g_dms.page_size, (char*)fb_mark, g_dms.page_size);
        if (ret != EOK) {
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
            return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
        }
    }
    if (reply->force_cvt) {
        g_dms.callback.set_page_force_request(dms_ctx->db_handle, reply->pageid);
    }
    return DMS_SUCCESS;
}

static int dcs_proc_msg_ack_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, dms_message_t *message)
{
    CM_CHK_PROC_MSG_SIZE(message, (uint32)(sizeof(msg_pcr_ack_t) + g_dms.page_size), CM_FALSE);
    msg_pcr_ack_t *ack = (msg_pcr_ack_t *)(message->buffer);
    char *recv_page = (char *)ack + sizeof(msg_pcr_ack_t);
    int ret = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }
    if (dms_cr->fb_mark != NULL) {
        CM_CHK_PROC_MSG_SIZE(message, (uint32)(sizeof(msg_pcr_ack_t) + 2 * g_dms.page_size), CM_FALSE);
        bool8 *fb_mark = (bool8*)(message->buffer + sizeof(msg_pcr_ack_t) + g_dms.page_size);
        ret = memcpy_sp((char*)dms_cr->fb_mark, g_dms.page_size, (char*)fb_mark, g_dms.page_size);
        if (ret != EOK) {
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
            return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
        }
    }
    if (ack->force_cvt) {
        g_dms.callback.set_page_force_request(dms_ctx->db_handle, dms_ctx->resid);
    }

    return DMS_SUCCESS;
}

static inline int dcs_proc_msg_ack_txn_wait(dms_cr_t *dms_cr, dms_message_t *message)
{
    CM_CHK_PROC_MSG_SIZE(message, (uint32)(sizeof(dms_message_head_t) + DMS_XID_SIZE), CM_FALSE);

    char *wxid = g_dms.callback.get_wxid_from_cr_cursor(dms_cr->cr_cursor);
    int ret = memcpy_sp(wxid, DMS_XID_SIZE, DMS_MESSAGE_BODY(message), DMS_XID_SIZE);
    DMS_SECUREC_CHECK(ret);

    return DMS_SUCCESS;
}

static int dcs_pcr_process_message(dms_context_t *dms_ctx, dms_cr_t *dms_cr, dms_message_t *message)
{
    dms_message_head_t *dms_head = get_dms_head(message);
    switch (dms_head->cmd) {
        case MSG_REQ_CR_PAGE: {
            dms_cr->status = DMS_CR_STATUS_INVISIBLE_TXN;
            dms_cr->phase = DMS_CR_PHASE_CONSTRUCT;
            return dcs_proc_msg_req_cr_page(dms_ctx, dms_cr, message);
        }
        case MSG_ACK_CR_PAGE: {
            dms_cr->status = DMS_CR_STATUS_ALL_VISIBLE;
            dms_cr->phase = DMS_CR_PHASE_DONE;
            return dcs_proc_msg_ack_cr_page(dms_ctx, dms_cr, message);
        }
        case MSG_ACK_TXN_WAIT: {
            dms_cr->status = DMS_CR_STATUS_PENDING_TXN;
            dms_cr->phase = DMS_CR_PHASE_TRY_READ_PAGE;
            return dcs_proc_msg_ack_txn_wait(dms_cr, message);
        }
        case MSG_ACK_ERROR:
            dms_cr->status = DMS_CR_STATUS_ABORT; 
            cm_print_error_msg_and_throw_error(message->buffer);
            return ERRNO_DMS_COMMON_MSG_ACK;
        case MSG_ACK_GRANT_OWNER: {
            dms_cr->phase = DMS_CR_PHASE_READ_PAGE;
            dms_ask_res_ack_ld_t *ack = (dms_ask_res_ack_ld_t *)(message->buffer);
            g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
            break;
        }
        case MSG_ACK_ALREADY_OWNER: {
            dms_cr->phase = DMS_CR_PHASE_READ_PAGE;
            dms_already_owner_ack_t *ack = (dms_already_owner_ack_t *)(message->buffer);
            g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
            break;
        }
        case MSG_REQ_ASK_MASTER_FOR_CR_PAGE:
            dms_cr->phase = DMS_CR_PHASE_CHECK_MASTER;
            break;
        default:
            dms_cr->status = DMS_CR_STATUS_ABORT;
            break;
    }

    return DMS_SUCCESS;
}

static int dcs_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dest_id, msg_pcr_request_t *request,
    uint32 head_size, bool8 for_heap)
{
    int ret;
    dms_message_t message;

    dms_wait_event_t evt = for_heap ? DMS_EVT_PCR_REQ_HEAP_PAGE : DMS_EVT_PCR_REQ_BTREE_PAGE;
    dms_dyn_trc_begin(dms_ctx->sess_id, evt);
    LOG_DYN_TRC_INF("[RCRP][%s]cr_type %u qscn %llu qssn %u srcid %u ssid %u dstid %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)dms_ctx->inst_id, (uint32)dms_ctx->sess_id, (uint32)dest_id);

    for (;;) {
        dms_begin_stat(dms_ctx->sess_id, evt, CM_TRUE);
        DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_CR_PAGE, MSG_REQ_CR_PAGE);
        if (dms_cr->fb_mark == NULL) {
            ret = mfc_send_data3(&request->head, head_size, dms_cr->page);
        } else {
            ret = mfc_send_data4(&request->head, head_size, dms_cr->page, g_dms.page_size, dms_cr->fb_mark,
                g_dms.page_size);
        }
        if (ret != DMS_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        ret = mfc_get_response(request->head.ruid, &message, DMS_WAIT_MAX_TIME);
        if (ret != DMS_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_dyn_trc_end(dms_ctx->sess_id);
        dms_end_stat(dms_ctx->sess_id);

        ret = dcs_pcr_process_message(dms_ctx, dms_cr, &message);
        mfc_release_response(&message);
        return ret;
    }

    /* error occurs, we want to retry in DB layer, so return success to DB, should judge status in state machine */
    dms_cr->status = DMS_CR_STATUS_DB_NOT_READY;
    LOG_DYN_TRC_WAR("[RCRP][%s]qscn=%llu qssn=%u srcid=%u ssid=%u dstid=%u, failed retry",
        cm_display_pageid(request->pageid), request->query_scn, request->ssn,
        (uint32)dms_ctx->inst_id, (uint32)dms_ctx->sess_id, (uint32)dest_id);

    cm_sleep(DMS_MSG_RETRY_TIME);
    dms_dyn_trc_end(dms_ctx->sess_id);

    return DMS_SUCCESS;
}

static int dcs_heap_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dest_id)
{
    msg_pcr_request_t request;
    int ret;

    DMS_INIT_MESSAGE_HEAD(&request.head, MSG_REQ_CR_PAGE, 0, dms_ctx->inst_id, dest_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.size = (uint16)(sizeof(msg_pcr_request_t) + g_dms.page_size);
    if (dms_cr->fb_mark != NULL) {
        request.head.size += (uint16)g_dms.page_size;
    }
    ret = dcs_init_pcr_request(&request, dms_ctx, dms_cr, CR_TYPE_HEAP);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dcs_request_cr_page(dms_ctx, dms_cr, dest_id, &request, sizeof(msg_pcr_request_t), CM_TRUE);
    dms_inc_msg_stat(dms_ctx->sess_id, DMS_STAT_ASK_CR_PAGE, DRC_RES_PAGE_TYPE, ret);

    return ret;
}

int dms_forward_heap_cr_page_request(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id)
{
    dms_reset_error();
    return dcs_heap_request_cr_page(dms_ctx, dms_cr, (uint8)dst_inst_id);
}

static int dcs_index_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dest_id)
{
    msg_index_pcr_request_t msg;
    msg_pcr_request_t *request = &msg.pcr_request;
    int ret = DMS_SUCCESS;

    DMS_INIT_MESSAGE_HEAD(&request->head, MSG_REQ_CR_PAGE, 0, dms_ctx->inst_id, dest_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    request->head.size = (uint16)(sizeof(msg_index_pcr_request_t) + g_dms.page_size);

    ret = dcs_init_pcr_request(request, dms_ctx, dms_cr, CR_TYPE_BTREE);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    g_dms.callback.get_entry_pageid_from_cr_cursor(dms_cr->cr_cursor, msg.entry);
    g_dms.callback.get_index_profile_from_cr_cursor(dms_cr->cr_cursor, msg.profile);
    ret = dcs_request_cr_page(dms_ctx, dms_cr, dest_id, request, sizeof(msg_index_pcr_request_t), CM_FALSE);
    dms_inc_msg_stat(dms_ctx->sess_id, DMS_STAT_ASK_CR_PAGE, DRC_RES_PAGE_TYPE, ret);

    return ret;
}

int dms_forward_btree_cr_page_request(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id)
{
    dms_reset_error();
    return dcs_index_request_cr_page(dms_ctx, dms_cr, (uint8)dst_inst_id);
}

#ifndef OPENGAUSS
static void dcs_send_already_owner(dms_process_context_t *ctx, dms_message_t *msg)
{
    dms_already_owner_ack_t ack;

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_ALREADY_OWNER, MSG_ACK_ALREADY_OWNER);
    dms_init_ack_head(msg->head, &ack.head, MSG_ACK_ALREADY_OWNER, sizeof(dms_already_owner_ack_t), ctx->sess_id);
#ifndef OPENGAUSS
    ack.scn = (ctx->db_handle != NULL) ? g_dms.callback.get_global_scn(ctx->db_handle) : 0;
#endif

    (void)mfc_send_data(&ack.head);
}

static void dcs_send_grant_owner(dms_process_context_t *ctx, dms_message_t *msg)
{
    dms_ask_res_ack_ld_t ack;

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_GRANT_OWNER, MSG_ACK_GRANT_OWNER);
    dms_init_ack_head(msg->head, &ack.head, MSG_ACK_GRANT_OWNER, sizeof(dms_ask_res_ack_ld_t), ctx->sess_id);
#ifndef OPENGAUSS
    ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
    ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
#endif
    ack.master_grant = CM_TRUE;
    ack.node_count = 0;

    (void)mfc_send_data(&ack.head);
}

static void dcs_route_pcr_request_owner(dms_process_context_t *ctx, msg_pcr_request_t *request, uint8 owner_id)
{
    uint64 ruid = request->head.ruid;
    /* head size should use original value */
    uint32 send_proto_ver = dms_get_forward_request_proto_version(owner_id, request->head.msg_proto_ver);
    DMS_INIT_MESSAGE_HEAD2(&request->head, MSG_REQ_ASK_OWNER_FOR_CR_PAGE, 0, request->head.src_inst, owner_id,
        request->head.src_sid, CM_INVALID_ID16, send_proto_ver, request->head.size);

    request->head.dst_inst = owner_id;
    request->head.dst_sid = CM_INVALID_ID16;
    request->head.ruid = ruid;

    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_ASK_OWNER_FOR_CR_PAGE, MSG_REQ_ASK_OWNER_FOR_CR_PAGE);
    /* askowner wouldn't be sending req as ack to src_inst as outer func has judget */
    (void)mfc_forward_request(&request->head);
}

/* pcr am */
static int dcs_pcr_reroute_request(const dms_process_context_t *ctx, msg_pcr_request_t *request, bool32 *local_route)
{
    uint8 master_id;

    int ret = drc_get_page_master_id(request->pageid, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    // current instance is master, route in caller
    if (master_id == ctx->inst_id) {
        *local_route = CM_TRUE;
        return DMS_SUCCESS;
    }

    /* ruid remains the same to be relayed to new master */
    uint64 ruid = request->head.ruid;
    /* head size should use original value */
    uint32 send_proto_ver = dms_get_forward_request_proto_version(master_id, request->head.msg_proto_ver);
    DMS_INIT_MESSAGE_HEAD2(&request->head, MSG_REQ_ASK_MASTER_FOR_CR_PAGE, 0, request->head.src_inst, master_id,
        request->head.src_sid, CM_INVALID_ID16, send_proto_ver, request->head.size);
    request->head.ruid = ruid;

    LOG_DEBUG_INF("[PCR][%s][reroute request] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u ruid %llu",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)request->head.src_inst, (uint32)request->head.src_sid, (uint32)master_id, (uint64)request->head.ruid);

    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_ASK_MASTER_FOR_CR_PAGE, MSG_REQ_ASK_MASTER_FOR_CR_PAGE);
    if (master_id == request->head.src_inst) {
        ret = mfc_send_response(&request->head);
    } else {
        ret = mfc_forward_request(&request->head);
    }
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, request->head.cmd, request->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}
#endif

static inline void dcs_read_page_init(dms_read_page_assist_t *assist, char *pageid, dms_page_latch_mode_t mode,
    uint8 options, uint64 query_scn, uint16 read_num)
{
    assist->pageid = pageid;
    assist->query_scn = query_scn;
    assist->mode = mode;
    assist->options = options;
    assist->try_edp = (query_scn == CM_INVALID_ID64 ? CM_FALSE : CM_TRUE);
    assist->read_num = read_num;
}

#ifndef OPENGAUSS
static int dcs_proc_heap_pcr_construct(dms_process_context_t *ctx, msg_pcr_request_t *request, bool32 *local_route)
{
    dms_read_page_assist_t assist;
    msg_pcr_request_t *new_req = NULL;
    char *page = NULL;
    uint32 cr_version = 0;
    int ret;

    *local_route = CM_FALSE;
    // prevent depletion of mes_task_proc
    if (!dms_drc_accessible(DRC_RES_PAGE_TYPE)) {
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    dcs_read_page_init(&assist, request->pageid, DMS_PAGE_LATCH_MODE_S, DMS_ENTER_PAGE_NORMAL, request->query_scn, 1);
    if (g_dms.callback.read_page(ctx->db_handle, &assist, &page, &cr_version) != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_READ_PAGE);
        return ERRNO_DMS_CALLBACK_READ_PAGE;
    }

    // page owner has changed, request master to start the next round construct
    if (page == NULL) {
        return dcs_pcr_reroute_request(ctx, request, local_route);
    }

    // use the received request to generate new request to construct CR page
    new_req = (msg_pcr_request_t *)g_dms.callback.mem_alloc(ctx->db_handle,
        sizeof(msg_pcr_request_t) + 2 * g_dms.page_size);
    if (new_req == NULL) {
        g_dms.callback.leave_page(ctx->db_handle, CM_FALSE, cr_version);
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_STACK_PUSH);
        return ERRNO_DMS_CALLBACK_STACK_PUSH;
    }
    *new_req = *(msg_pcr_request_t *)request;
    new_req->head.cmd = MSG_REQ_CR_PAGE;
    new_req->head.size = (uint16)(sizeof(msg_pcr_request_t) + 2 * g_dms.page_size);

    ret = memcpy_sp((char *)new_req + sizeof(msg_pcr_request_t), g_dms.page_size, page, g_dms.page_size);
    if (ret != EOK) {
        g_dms.callback.mem_free(ctx->db_handle, new_req);
        g_dms.callback.leave_page(ctx->db_handle, CM_FALSE, cr_version);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(new_req->pageid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    g_dms.callback.leave_page(ctx->db_handle, CM_FALSE, cr_version);

    /* sync scn before construct CR page */
    g_dms.callback.update_global_scn(ctx->db_handle, request->query_scn);

    ret = dcs_heap_construct_cr_page(ctx, new_req);

    g_dms.callback.mem_free(ctx->db_handle, new_req);

    return ret;
}

static void dcs_handle_pcr_req_master(dms_process_context_t *ctx, dms_message_t *msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(msg, (uint32)sizeof(msg_pcr_request_t), CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);
    uint8 owner_id;
    bool32 local_route = CM_TRUE;
    int ret;

    LOG_DEBUG_INF("[DCS][dcs_handle_pcr_req_master]:src_inst=%d, dst_inst=%d, src_sid=%u, dst_sid=%u, cr_type=%s, "
        "force_cvt=%d, ssn=%u, query_scn=%llu, pageid=%s, xid=%s", (int32)request->head.src_inst,
        (int32)request->head.dst_inst, (uint32)request->head.src_sid, (uint32)request->head.dst_sid,
        (request->cr_type == CR_TYPE_HEAP) ? "heap" : "btree", (int32)request->force_cvt,
        (uint32)request->ssn, (uint64)request->query_scn, cm_display_pageid(request->pageid),
        cm_display_xid(request->xid));

    while (local_route) {
        ret = drc_get_page_owner_id(CM_INVALID_ID8, request->pageid, request->sess_type, &owner_id);
        if (ret != DMS_SUCCESS) {
            cm_send_error_msg(msg->head, ret, "construct heap page failed");
            break;
        }

        if (owner_id == CM_INVALID_ID8) {
            dcs_send_grant_owner(ctx, msg);
            break;
        }

        if (owner_id == msg->head->src_inst) {
            dcs_send_already_owner(ctx, msg);
            break;
        }

        if (owner_id != ctx->inst_id) {
            dcs_route_pcr_request_owner(ctx, request, owner_id);
            break;
        }

        local_route = CM_FALSE;
        if (request->cr_type == CR_TYPE_HEAP) {
            ret = dcs_proc_heap_pcr_construct(ctx, request, &local_route);
            if (ret != DMS_SUCCESS) {
                cm_send_error_msg(msg->head, ret, "construct heap page failed");
            }
        } else {
            cm_send_error_msg(msg->head, ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "NOT SUPPORT CAPABILITY");
        }
    }
}
#endif

void dcs_proc_pcr_req_master(dms_process_context_t *process_ctx, dms_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        LOG_DEBUG_ERR("PCR should not process req as ack anymore!");
        recv_msg->head->dst_sid = recv_msg->head->src_sid;
        dms_proc_msg_ack(process_ctx, recv_msg);
        return;
    }

    dcs_handle_pcr_req_master(process_ctx, recv_msg);
#endif
}

void dcs_proc_pcr_req_owner(dms_process_context_t *process_ctx, dms_message_t *recv_msg)
{
#ifndef OPENGAUSS
    CM_CHK_PROC_MSG_SIZE_NO_ERR(recv_msg, (uint32)sizeof(msg_pcr_request_t), CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(recv_msg->buffer);
    bool32 local_route = CM_FALSE;
    int ret;

    LOG_DEBUG_INF("[DCS][dcs_handle_pcr_req_owner]:src_inst=%d, dst_inst=%d, src_sid=%u, dst_sid=%u, cr_type=%s, "
        "force_cvt=%d, ssn=%u, query_scn=%llu, pageid=%s, xid=%s", (int32)request->head.src_inst,
        (int32)request->head.dst_inst, (uint32)request->head.src_sid, (uint32)request->head.dst_sid,
        (request->cr_type == CR_TYPE_HEAP) ? "heap" : "btree", (int32)request->force_cvt,
        (uint32)request->ssn, (uint64)request->query_scn, cm_display_pageid(request->pageid),
        cm_display_xid(request->xid));

    if (request->cr_type == CR_TYPE_HEAP) {
        ret = dcs_proc_heap_pcr_construct(process_ctx, request, &local_route);
        if (ret != DMS_SUCCESS) {
            cm_send_error_msg(recv_msg->head, ret, "construct heap page failed");
        }
    } else {
        cm_send_error_msg(recv_msg->head, ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "NOT SUPPORT CAPABILITY");
    }

    if (local_route) {
        LOG_DEBUG_INF("[DCS][dcs_proc_pcr_req_owner] local route");
        dcs_handle_pcr_req_master(process_ctx, recv_msg);
    }
#endif
}

#ifndef OPENGAUSS
static int dcs_send_check_visible_ack(dms_process_context_t *ctx, msg_cr_check_t *check, bool8 is_found)
{
    msg_cr_check_ack_t msg;

    dms_init_ack_head2(&msg.head, MSG_ACK_CHECK_VISIBLE, 0, (uint8)ctx->inst_id, check->head.src_inst,
        (uint16)ctx->sess_id, check->head.src_sid, check->head.msg_proto_ver);
    msg.head.ruid = check->head.ruid;
    msg.head.size = (uint16)sizeof(msg_cr_check_ack_t);
    msg.is_found = is_found;

    LOG_DEBUG_INF("[PCR][%s][send check visible ack] is_found %u "
        "src_inst %u src_sid %u dst_inst %u dst_sid %u",
        cm_display_rowid(check->rowid), (uint32)is_found, (uint32)ctx->inst_id, ctx->sess_id,
        (uint32)check->head.src_inst, (uint32)check->head.src_sid);

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_CHECK_VISIBLE, MSG_ACK_CHECK_VISIBLE);
    int ret = mfc_send_data(&msg.head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, msg.head.cmd, msg.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_send_check_visible(dms_process_context_t *ctx, msg_cr_check_t *check, uint8 dst_id)
{
    int ret = DMS_SUCCESS;
    check->head.dst_inst = dst_id;

    LOG_DEBUG_INF("[PCR][%s][send check visible] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_rowid(check->rowid), check->query_scn, check->ssn, (uint32)check->head.src_inst,
        (uint32)check->head.src_sid, (uint32)dst_id);

    if (dst_id == check->head.src_inst) {
        ret = mfc_send_response(&check->head);
    } else {
        ret = mfc_forward_request(&check->head);
    }
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, check->head.cmd, check->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_heap_check_visible(dms_process_context_t *ctx, msg_cr_check_t *check)
{
    int ret;
    char *page = (char *)check + sizeof(msg_cr_check_t);
    bool32 is_found = CM_TRUE;
    dms_cr_assist_t pcr;
    dcs_init_pcr_assist(&pcr, ctx->db_handle, check->query_scn, check->ssn, page, check->xid, NULL, check->rowid);
    pcr.check_restart = CM_FALSE;
    pcr.check_found = &is_found;

    g_dms.callback.update_global_scn(ctx->db_handle, check->query_scn);
    ret = g_dms.callback.check_heap_page_visible(&pcr);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    switch (pcr.status) {
        case DMS_CR_STATUS_ALL_VISIBLE:
        case DMS_CR_STATUS_INVISIBLE_TXN:
            ret = dcs_send_check_visible_ack(ctx, check, (bool8)(*pcr.check_found));
            break;
        case DMS_CR_STATUS_OTHER_NODE_INVISIBLE_TXN:
            ret = dcs_send_check_visible(ctx, check, pcr.relay_inst);
            break;
        case DMS_CR_STATUS_DB_NOT_READY:
            LOG_DEBUG_INF("[DCS]dcs_heap_check_visible, db is not ready");
            break;
        case DMS_CR_STATUS_PENDING_TXN:
            /* DMS_CR_STATUS_PENDING_TXN will be ignored in check_heap_page_visible callback function */
            /* fall-through */
        default:
            cm_panic_log(0, "Invalid CR status for heap visible check: %d", pcr.status);
            break;
    }
    return ret;
}
#endif

void dcs_proc_check_visible(dms_process_context_t *process_ctx, dms_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        LOG_DEBUG_ERR("PCR should not process req as ack anymore!");
        recv_msg->head->dst_sid = recv_msg->head->src_sid;
        dms_proc_msg_ack(process_ctx, recv_msg);
        return;
    }

    CM_CHK_PROC_MSG_SIZE_NO_ERR(recv_msg, (uint32)(sizeof(msg_cr_check_t) + g_dms.page_size), CM_TRUE);
    int ret = dcs_heap_check_visible(process_ctx, (msg_cr_check_t *)(recv_msg->buffer));
    if (ret != DMS_SUCCESS) {
        cm_send_error_msg(recv_msg->head, ret, "check heap page visible failed");
    }
#endif
}

static inline void dcs_get_msg_cmd_by_cr_status(dms_cr_phase_t cr_phase, msg_command_t *msg_cmd,
    const char **log_info, dms_stat_cmd_e *stat_cmd)
{
    switch (cr_phase) {
        case DMS_CR_PHASE_REQ_MASTER:
            *msg_cmd = MSG_REQ_ASK_MASTER_FOR_CR_PAGE;
            *stat_cmd = DMS_STAT_ASK_MASTER_CR_PAGE;
            *log_info = "master";
            break;
        case DMS_CR_PHASE_REQ_OWNER:
            *msg_cmd = MSG_REQ_ASK_OWNER_FOR_CR_PAGE;
            *stat_cmd = DMS_STAT_ASK_OWNER_CR_PAGE;
            *log_info = "owner";
            break;
        default:
            *msg_cmd = MSG_CMD_CEIL;
            CM_ASSERT(0);
            break;
    }
}

int dms_request_heap_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id)
{
    dms_reset_error();
    msg_pcr_request_t request;
    dms_message_t message;
    int ret;
    msg_command_t msg_cmd;
    const char *log_info = NULL;
    dms_stat_cmd_e stat_cmd = DMS_STAT_CMD_COUNT;

    dcs_get_msg_cmd_by_cr_status(dms_cr->phase, &msg_cmd, &log_info, &stat_cmd);

    DMS_INIT_MESSAGE_HEAD(&request.head, msg_cmd, 0, dms_ctx->inst_id, dst_inst_id, dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.size = (uint16)sizeof(msg_pcr_request_t);
    ret = dcs_init_pcr_request(&request, dms_ctx, dms_cr, CR_TYPE_HEAP);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    LOG_DEBUG_INF("[PCR][%s][request %s] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request.pageid), log_info, (uint32)CR_TYPE_HEAP, request.query_scn, request.ssn,
        (uint32)dms_ctx->inst_id, dms_ctx->sess_id, (uint32)dst_inst_id);

    for (;;) {
        dms_wait_event_t event = (dms_cr->phase == DMS_CR_PHASE_REQ_MASTER)
            ? DMS_EVT_PCR_REQ_MASTER : DMS_EVT_PCR_REQ_OWNER;
        dms_begin_stat(dms_ctx->sess_id, event, CM_TRUE);

        if (mfc_send_data(&request.head) != CM_SUCCESS) {
            dms_inc_msg_stat(dms_ctx->sess_id, stat_cmd, DRC_RES_PAGE_TYPE, CM_ERROR);
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        if (mfc_get_response(request.head.ruid, &message, DMS_WAIT_MAX_TIME) != CM_SUCCESS) {
            dms_inc_msg_stat(dms_ctx->sess_id, stat_cmd, DRC_RES_PAGE_TYPE, CM_ERROR);
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_end_stat(dms_ctx->sess_id);
        session_stat_t *stat = DMS_GET_SESSION_STAT(dms_ctx->sess_id);
        stat->stat[DMS_STAT_NET_TIME] += stat->wait[stat->level].usecs;

        ret = dcs_pcr_process_message(dms_ctx, dms_cr, &message);
        if (ret != DMS_SUCCESS) {
            dms_inc_msg_stat(dms_ctx->sess_id, stat_cmd, DRC_RES_PAGE_TYPE, ret);
            mfc_release_response(&message);
            return ret;
        }

        dms_inc_msg_stat(dms_ctx->sess_id, stat_cmd, DRC_RES_PAGE_TYPE, ret);
        mfc_release_response(&message);
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[PCR][%s][request %s failed] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request.pageid), log_info, (uint32)CR_TYPE_HEAP, request.query_scn, request.ssn,
        dms_ctx->inst_id, dms_ctx->sess_id, (uint32)dst_inst_id);

    dms_cr->phase = DMS_CR_PHASE_CHECK_MASTER;
    cm_sleep(DMS_MSG_RETRY_TIME);

    return DMS_SUCCESS;
}

int dms_cr_check_master(dms_context_t *dms_ctx, unsigned int *dst_inst_id, dms_cr_phase_t *cr_phase)
{
    dms_reset_error();
    uint8 master_id, owner_id;

    CM_ASSERT(*cr_phase == DMS_CR_PHASE_CHECK_MASTER);

    int ret = drc_get_page_master_id(dms_ctx->resid, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        ret = drc_get_page_owner_id(CM_INVALID_ID8, dms_ctx->resid, dms_ctx->sess_type, &owner_id);
        if (ret != DMS_SUCCESS) {
            return ret;
        }

        if (owner_id == CM_INVALID_ID8 || owner_id == dms_ctx->inst_id) {
            *cr_phase = DMS_CR_PHASE_READ_PAGE;
        } else {
            *dst_inst_id = owner_id;
            *cr_phase = DMS_CR_PHASE_REQ_OWNER;
        }
    } else {
        *dst_inst_id = master_id;
        *cr_phase = DMS_CR_PHASE_REQ_MASTER;
    }

    return DMS_SUCCESS;
}

static int dcs_proc_check_current_visible(dms_cr_t *dms_cr, dms_message_t *msg, bool8 *is_empty_itl,
    unsigned char *is_found)
{
    char *recv_page = NULL;
    dms_message_head_t *dms_head = get_dms_head(msg);
    switch (dms_head->cmd) {
        case MSG_ACK_CHECK_VISIBLE:
            CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(msg_cr_check_ack_t), CM_FALSE);
            *is_found = *(bool8 *)DMS_MESSAGE_BODY(msg);
            *is_empty_itl = CM_TRUE;
            return DMS_SUCCESS;
        case MSG_ACK_ERROR:
            cm_print_error_msg_and_throw_error(msg->buffer);
            return ERRNO_DMS_COMMON_MSG_ACK;
        case MSG_REQ_CHECK_VISIBLE: {
            CM_CHK_PROC_MSG_SIZE(msg, (uint32)(sizeof(msg_cr_check_t) + g_dms.page_size), CM_FALSE);
            msg_cr_check_t *check = (msg_cr_check_t *)(msg->buffer);
            recv_page = (char *)check + sizeof(msg_cr_check_t);
            errno_t err = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
            DMS_SECUREC_CHECK(err);
            return DMS_SUCCESS;
        }
        default:
            DMS_THROW_ERROR(ERRNO_DMS_CMD_INVALID, dms_head->cmd);
            return ERRNO_DMS_CMD_INVALID;
    }
}

static inline void dcs_init_msg_cr_check(msg_cr_check_t *check, dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dst_id)
{
    DMS_INIT_MESSAGE_HEAD(&check->head, MSG_REQ_CHECK_VISIBLE, 0, dms_ctx->inst_id, dst_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    check->head.size = (uint16)(sizeof(msg_cr_check_t) + g_dms.page_size);
    check->query_scn = dms_cr->query_scn;
    check->ssn = dms_cr->ssn;
    g_dms.callback.get_xid_from_cr_cursor(dms_cr->cr_cursor, check->xid);
    g_dms.callback.get_rowid_from_cr_cursor(dms_cr->cr_cursor, check->rowid);
}

int dms_check_current_visible(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id,
    unsigned char *is_empty_itl, unsigned char *is_found)
{
    dms_reset_error();
    msg_cr_check_t check;
    dms_message_t message;
    int ret = DMS_SUCCESS;

    dcs_init_msg_cr_check(&check, dms_ctx, dms_cr, (uint8)dst_inst_id);

    LOG_DEBUG_INF("[PCR][%s][check current visible] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_rowid(check.rowid), check.query_scn, check.ssn, (uint32)check.head.src_inst,
        (uint32)check.head.src_sid, (uint32)dst_inst_id);

    for (;;) {
        dms_begin_stat(dms_ctx->sess_id, DMS_EVT_PCR_CHECK_CURR_VISIBLE, CM_TRUE);
        DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_CHECK_VISIBLE, MSG_REQ_CHECK_VISIBLE);
        if (mfc_send_data3(&check.head, sizeof(msg_cr_check_t), dms_cr->page) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        if (mfc_get_response(check.head.ruid, &message, DMS_WAIT_MAX_TIME) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_end_stat(dms_ctx->sess_id);

        ret = dcs_proc_check_current_visible(dms_cr, &message, is_empty_itl, is_found);

        mfc_release_response(&message);
        return ret;
    }

    LOG_DEBUG_ERR("[PCR][%s][check current visible failed] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u, ret:%d",
        cm_display_rowid(check.rowid), check.query_scn, check.ssn, (uint32)check.head.src_inst,
        (uint32)check.head.src_sid, (uint32)dst_inst_id, ret);
    DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
    return DMS_ERROR;
}

#ifdef __cplusplus
}
#endif