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
#include "dms_msg.h"
#include "dms_stat.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OPENGAUSS
static int dcs_send_pcr_ack(dms_process_context_t *ctx, msg_pcr_request_t *request, char *page, bool8 *fb_mark)
{
    int ret;
    msg_pcr_ack_t msg;

    mfc_init_ack_head(&request->head, &msg.head, MSG_ACK_CR_PAGE,
        (uint16)(sizeof(msg_pcr_ack_t) + g_dms.page_size), ctx->sess_id);
    msg.head.src_inst = ctx->inst_id;
    CM_ASSERT(request->head.dst_inst == ctx->inst_id);
    msg.force_cvt = request->force_cvt;
    if (fb_mark != NULL) {
        msg.head.size += (uint16)g_dms.page_size;
    }

    LOG_DEBUG_INF("[PCR][%s][send pcr ack] cr_type %u src_inst %u src_sid %u dst_inst %u dst_sid %u force_cvt %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, (uint32)msg.head.src_inst,
        (uint32)msg.head.src_sid, (uint32)msg.head.dst_inst, (uint32)msg.head.dst_sid, (uint32)msg.force_cvt);

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
    request->head.dst_inst = dst_id;

    LOG_DEBUG_INF("[PCR][%s][send pcr request] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u force_cvt %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)request->head.src_inst, (uint32)request->head.src_sid, (uint32)dst_id, (uint32)request->force_cvt);

    int ret = mfc_send_data(&request->head);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, request->head.cmd, request->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_send_txn_wait(dms_process_context_t *ctx, msg_pcr_request_t *request, char *wxid)
{
    msg_txn_wait_t msg ;
    mfc_init_ack_head(&request->head, &msg.head, MSG_ACK_TXN_WAIT, sizeof(msg_txn_wait_t), ctx->sess_id);
    msg.head.src_inst = ctx->inst_id;
    CM_ASSERT(request->head.dst_inst == ctx->inst_id);
    errno_t err = memcpy_sp(msg.wxid, DMS_XID_SIZE, wxid, DMS_XID_SIZE);
    DMS_SECUREC_CHECK(err);

    LOG_DEBUG_INF("[PCR][%s][send txn wait] wxid %s src_inst %u src_sid %u dst_inst %u dst_sid %u",
        cm_display_pageid(request->pageid), cm_display_xid(wxid), (uint32)msg.head.src_inst, (uint32)msg.head.src_sid,
        (uint32)msg.head.dst_inst, (uint32)msg.head.dst_sid);

    int ret = mfc_send_data(&msg.head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, msg.head.cmd, msg.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}
#endif

static inline uint8 dcs_get_inst_id(void *db_handle, void *cr_cursor, uint32 curr_inst_id)
{
    uint8 inst_id = g_dms.callback.get_instid_of_xid_from_cr_cursor(db_handle, cr_cursor);
    if (inst_id == curr_inst_id) {
        return inst_id;
    }

    return drc_get_deposit_id(inst_id);
}

#ifndef OPENGAUSS
static int dcs_construct_cr_page(dms_process_context_t *ctx, msg_pcr_request_t *request, void *cr_cursor,
    void *cr_page, bool8 *fb_mark)
{
    uint8 inst_id;
    bool8 is_empty_txn_list;
    bool8 exist_waiting_txn;
    int ret = DMS_SUCCESS;

    for (;;) {
        if (request->cr_type == CR_TYPE_HEAP) {
            ret = g_dms.callback.get_heap_invisible_txn_list(ctx->db_handle, cr_cursor, cr_page,
                &is_empty_txn_list, &exist_waiting_txn);
        } else {
            ret = g_dms.callback.get_index_invisible_txn_list(ctx->db_handle, cr_cursor, cr_page,
                &is_empty_txn_list, &exist_waiting_txn);
        }

        if (ret != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST, ret);
            ret = ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST;
            break;
        }

        if (is_empty_txn_list) {
            ret = dcs_send_pcr_ack(ctx, request, (char *)cr_page, fb_mark);
            break;
        }

        if (exist_waiting_txn) {
            ret = dcs_send_txn_wait(ctx, request, g_dms.callback.get_wxid_from_cr_cursor(cr_cursor));
            break;
        }

        inst_id = dcs_get_inst_id(ctx->db_handle, cr_cursor, ctx->inst_id);
        if (inst_id == ctx->inst_id) {
            if (request->cr_type == CR_TYPE_HEAP) {
                ret = g_dms.callback.reorganize_heap_page_with_undo(ctx->db_handle, cr_cursor, cr_page, fb_mark);
            } else {
                ret = g_dms.callback.reorganize_index_page_with_undo(ctx->db_handle, cr_cursor, cr_page);
            }
            if (ret != DMS_SUCCESS) {
                DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO, ret);
                ret = ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO;
                break;
            }
        } else {
            ret = dcs_send_pcr_request(ctx, request, inst_id);
            break;
        }
    }
    return ret;
}

static int dcs_heap_construct_cr_page(dms_process_context_t *ctx, msg_pcr_request_t *request)
{
    bool8 *fb_mark = NULL;
    void *cr_page = (void *)((char *)request + sizeof(msg_pcr_request_t));
    if (request->head.size > sizeof(msg_pcr_request_t) + g_dms.page_size) {
        if (request->head.size < sizeof(msg_pcr_request_t) + 2 * g_dms.page_size) {
            DMS_THROW_ERROR(ERRNO_DMS_MES_INVALID_MSG);
            return ERRNO_DMS_MES_INVALID_MSG;
        }
        fb_mark = (bool8 *)((char *)request + sizeof(msg_pcr_request_t) + g_dms.page_size);
    }

    void *cr_cursor = g_dms.callback.stack_push_cr_cursor(ctx->db_handle);
    if (cr_cursor == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR);
        return ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR;
    }

    int ret = g_dms.callback.init_heap_cr_cursor(
        cr_cursor, request->pageid, request->xid, request->query_scn, request->ssn);
    if (ret != DMS_SUCCESS) {
        g_dms.callback.stack_pop_cr_cursor(ctx->db_handle);
        return ret;
    }

    ret = dcs_construct_cr_page(ctx, request, cr_cursor, cr_page, fb_mark);
    g_dms.callback.stack_pop_cr_cursor(ctx->db_handle);
    return ret;
}

static int dcs_btree_construct_cr_page(dms_process_context_t *ctx, msg_pcr_request_t *request)
{
    msg_index_pcr_request_t *index_pcr_req = (msg_index_pcr_request_t *)request;
    void *cr_page = (void *)((char *)request + sizeof(msg_index_pcr_request_t));

    void *cr_cursor = g_dms.callback.stack_push_cr_cursor(ctx->db_handle);
    if (cr_cursor == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR);
        return ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR;
    }

    g_dms.callback.init_index_cr_cursor(cr_cursor, request->pageid, request->xid, request->query_scn, request->ssn,
        index_pcr_req->entry, index_pcr_req->profile);

    int ret = dcs_construct_cr_page(ctx, request, cr_cursor, cr_page, NULL);
    g_dms.callback.stack_pop_cr_cursor(ctx->db_handle);
    return ret;
}

static void dcs_handle_pcr_request(dms_process_context_t *ctx, mes_message_t *msg)
{
    int ret;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(msg, (uint32)sizeof(msg_pcr_request_t), CM_FALSE, CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);
    
    uint32 total_size = request->cr_type == CR_TYPE_HEAP ? sizeof(msg_pcr_request_t) : sizeof(msg_index_pcr_request_t);
    total_size += g_dms.page_size;
    CM_CHK_RECV_MSG_SIZE_NO_ERR(msg, total_size, CM_FALSE, CM_TRUE);

    /* sync scn before construct cr page */
    g_dms.callback.update_global_scn(ctx->db_handle, request->query_scn);

    if (request->cr_type == CR_TYPE_HEAP) {
        ret = dcs_heap_construct_cr_page(ctx, request);
        if (ret != DMS_SUCCESS) {
            cm_send_error_msg(msg->head, ret, "failed to construct heap cr page");
        }
    } else if (request->cr_type == CR_TYPE_BTREE) {
        ret = dcs_btree_construct_cr_page(ctx, request);
        if (ret != DMS_SUCCESS) {
            cm_send_error_msg(msg->head, ret, "failed to construct btree cr page");
        }
    } else {
        cm_send_error_msg(msg->head, ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "capability not support");
    }
}
#endif

void dcs_proc_pcr_request(dms_process_context_t *process_ctx, mes_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        recv_msg->head->dst_sid = recv_msg->head->src_sid;
        dms_proc_msg_ack(process_ctx, recv_msg);
        return;
    }

    dcs_handle_pcr_request(process_ctx, recv_msg);
#endif
    mfc_release_message_buf(recv_msg);
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

static int dcs_proc_msg_req_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, mes_message_t *message)
{
    CM_CHK_RECV_MSG_SIZE(message, (uint32)sizeof(msg_pcr_request_t), CM_FALSE, CM_FALSE);
    msg_pcr_request_t *reply = (msg_pcr_request_t *)(message->buffer);
    uint32 head_size = (reply->cr_type != CR_TYPE_BTREE) ? sizeof(msg_pcr_request_t) : sizeof(msg_index_pcr_request_t);

    CM_CHK_RECV_MSG_SIZE(message, (uint32)(head_size + g_dms.page_size), CM_FALSE, CM_FALSE);
    char *recv_page = (char *)reply + head_size;
    int ret = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }
    if (dms_cr->fb_mark != NULL) {
        CM_CHK_RECV_MSG_SIZE(message, (uint32)(head_size + 2 * g_dms.page_size), CM_FALSE, CM_FALSE);
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

static int dcs_proc_msg_ack_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, mes_message_t *message)
{
    CM_CHK_RECV_MSG_SIZE(message, (uint32)(sizeof(msg_pcr_ack_t) + g_dms.page_size), CM_FALSE, CM_FALSE);
    msg_pcr_ack_t *ack = (msg_pcr_ack_t *)(message->buffer);
    char *recv_page = (char *)ack + sizeof(msg_pcr_ack_t);
    int ret = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }
    if (dms_cr->fb_mark != NULL) {
        CM_CHK_RECV_MSG_SIZE(message, (uint32)(sizeof(msg_pcr_ack_t) + 2 * g_dms.page_size), CM_FALSE, CM_FALSE);
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

static inline int dcs_proc_msg_ack_txn_wait(dms_cr_t *dms_cr, mes_message_t *message)
{
    CM_CHK_RECV_MSG_SIZE(message, (uint32)(sizeof(mes_message_head_t) + DMS_XID_SIZE), CM_FALSE, CM_FALSE);
    char *wxid = g_dms.callback.get_wxid_from_cr_cursor(dms_cr->cr_cursor);
    int ret = memcpy_sp(wxid, DMS_XID_SIZE, MES_MESSAGE_BODY(message), DMS_XID_SIZE);
    DMS_SECUREC_CHECK(ret);

    return DMS_SUCCESS;
}

static int dcs_pcr_process_message(dms_context_t *dms_ctx, dms_cr_t *dms_cr, mes_message_t *message,
    dms_cr_status_t *cr_status, bool8 *is_empty_txn_list, bool8 *exist_waiting_txn)
{
    *exist_waiting_txn = CM_FALSE;
    *is_empty_txn_list = CM_FALSE;
    switch (message->head->cmd) {
        case MSG_REQ_CR_PAGE: {
            *cr_status = DMS_CR_CONSTRUCT;
            return dcs_proc_msg_req_cr_page(dms_ctx, dms_cr, message);
        }
        case MSG_ACK_CR_PAGE: {
            *is_empty_txn_list = CM_TRUE;
            *cr_status = DMS_CR_PAGE_VISIBLE;
            return dcs_proc_msg_ack_cr_page(dms_ctx, dms_cr, message);
        }
        case MSG_ACK_TXN_WAIT: {
            *exist_waiting_txn = CM_TRUE;
            *cr_status = DMS_CR_TRY_READ;
            return dcs_proc_msg_ack_txn_wait(dms_cr, message);
        }
        case MSG_ACK_ERROR:
            cm_print_error_msg(message->buffer);
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(message->buffer) + sizeof(msg_error_t)));
            return ERRNO_DMS_COMMON_MSG_ACK;
        case MSG_ACK_GRANT_OWNER:
        case MSG_ACK_ALREADY_OWNER:
            *cr_status = DMS_CR_LOCAL_READ;
            break;
        case MSG_REQ_ASK_MASTER_FOR_CR_PAGE:
            *cr_status = DMS_CR_CHECK_MASTER;
            break;
        default:
            break;
    }

    return DMS_SUCCESS;
}

static int dcs_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dst_id, msg_pcr_request_t *request,
    uint32 head_size, bool8 *is_empty_txn_list, bool8 *exist_waiting_txn, bool8 for_heap)
{
    int ret;
    mes_message_t message;
    dms_cr_status_t cr_status;

    LOG_DEBUG_INF("[PCR][%s][request cr page] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)dms_ctx->inst_id, (uint32)dms_ctx->sess_id, (uint32)dst_id);

    dms_wait_event_t evt = for_heap ? DMS_EVT_PCR_REQ_HEAP_PAGE : DMS_EVT_PCR_REQ_BTREE_PAGE;

    for (;;) {
        dms_begin_stat(dms_ctx->sess_id, evt, CM_TRUE);

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

        ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &message, DCS_CR_REQ_TIMEOUT);
        if (ret != DMS_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_end_stat(dms_ctx->sess_id);

        ret = dcs_pcr_process_message(dms_ctx, dms_cr, &message, &cr_status, is_empty_txn_list, exist_waiting_txn);
        mfc_release_message_buf(&message);
        return ret;
    }

    LOG_DEBUG_INF("[PCR][%s][request cr page failed] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)dms_ctx->inst_id, (uint32)dms_ctx->sess_id, (uint32)dst_id);

    cm_sleep(DMS_MSG_RETRY_TIME);

    return DMS_SUCCESS;
}

static int dcs_heap_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dst_id, bool8 *is_empty_txn_list,
    bool8 *exist_waiting_txn)
{
    msg_pcr_request_t request;
    int ret;

    DMS_INIT_MESSAGE_HEAD(&request.head, MSG_REQ_CR_PAGE, 0, dms_ctx->inst_id, dst_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
    request.head.size = (uint16)(sizeof(msg_pcr_request_t) + g_dms.page_size);
    if (dms_cr->fb_mark != NULL) {
        request.head.size += (uint16)g_dms.page_size;
    }
    ret = dcs_init_pcr_request(&request, dms_ctx, dms_cr, CR_TYPE_HEAP);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return dcs_request_cr_page(dms_ctx, dms_cr, dst_id, &request, sizeof(msg_pcr_request_t),
        is_empty_txn_list, exist_waiting_txn, CM_TRUE);
}

int dms_construct_heap_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr)
{
    dms_reset_error();
    uint8 inst_id;
    bool8 is_empty_txn_list;
    bool8 exist_waiting_txn;
    int ret;

    for (;;) {
        ret = g_dms.callback.get_heap_invisible_txn_list(dms_ctx->db_handle, dms_cr->cr_cursor, dms_cr->page,
            &is_empty_txn_list, &exist_waiting_txn);
        if (ret != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST, ret);
            return ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST;
        }

        if (is_empty_txn_list || exist_waiting_txn) {
            return DMS_SUCCESS;
        }

        inst_id = dcs_get_inst_id(dms_ctx->db_handle, dms_cr->cr_cursor, dms_ctx->inst_id);
        if (inst_id == dms_ctx->inst_id) {
            ret = g_dms.callback.reorganize_heap_page_with_undo(dms_ctx->db_handle, dms_cr->cr_cursor, dms_cr->page,
                dms_cr->fb_mark);
            if (ret != DMS_SUCCESS) {
                DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO, ret);
                return ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO;
            }
        } else {
            ret = dcs_heap_request_cr_page(dms_ctx, dms_cr, inst_id, &is_empty_txn_list, &exist_waiting_txn);
            if (ret != DMS_SUCCESS) {
                return ret;
            }

            if (is_empty_txn_list || exist_waiting_txn) {
                return DMS_SUCCESS;
            }
        }
    }
}

static int dcs_index_request_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dst_id, bool8 *is_empty_txn_list,
    bool8 *exist_waiting_txn)
{
    msg_index_pcr_request_t msg;
    msg_pcr_request_t *request = &msg.pcr_request;
    int ret = DMS_SUCCESS;

    DMS_INIT_MESSAGE_HEAD(&request->head, MSG_REQ_CR_PAGE, 0, dms_ctx->inst_id, dst_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    request->head.rsn = mfc_get_rsn(dms_ctx->sess_id);
    request->head.size = (uint16)(sizeof(msg_index_pcr_request_t) + g_dms.page_size);

    ret = dcs_init_pcr_request(request, dms_ctx, dms_cr, CR_TYPE_BTREE);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    g_dms.callback.get_entry_pageid_from_cr_cursor(dms_cr->cr_cursor, msg.entry);
    g_dms.callback.get_index_profile_from_cr_cursor(dms_cr->cr_cursor, msg.profile);
    return dcs_request_cr_page(dms_ctx, dms_cr, dst_id, request, sizeof(msg_index_pcr_request_t),
        is_empty_txn_list, exist_waiting_txn, CM_FALSE);
}

int dms_construct_index_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr)
{
    dms_reset_error();
    uint8 inst_id;
    bool8 is_empty_txn_list;
    bool8 exist_waiting_txn;
    int ret;

    for (;;) {
        ret = g_dms.callback.get_index_invisible_txn_list(dms_ctx->db_handle, dms_cr->cr_cursor, dms_cr->page,
            &is_empty_txn_list, &exist_waiting_txn);
        if (ret != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST, ret);
            return ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST;
        }

        if (is_empty_txn_list || exist_waiting_txn) {
            return DMS_SUCCESS;
        }

        inst_id = dcs_get_inst_id(dms_ctx->db_handle, dms_cr->cr_cursor, dms_ctx->inst_id);
        if (inst_id == dms_ctx->inst_id) {
            ret = g_dms.callback.reorganize_index_page_with_undo(dms_ctx->db_handle, dms_cr->cr_cursor, dms_cr->page);
            if (ret != DMS_SUCCESS) {
                DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO, ret);
                return ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO;
            }
        } else {
            ret = dcs_index_request_cr_page(dms_ctx, dms_cr, inst_id, &is_empty_txn_list, &exist_waiting_txn);
            if (ret != DMS_SUCCESS) {
                return ret;
            }

            if (is_empty_txn_list || exist_waiting_txn) {
                return DMS_SUCCESS;
            }
        }
    }
}

#ifndef OPENGAUSS
static void dcs_send_already_owner(dms_process_context_t *ctx, mes_message_t *msg)
{
    mes_message_head_t head;

    mfc_init_ack_head(msg->head, &head, MSG_ACK_ALREADY_OWNER, sizeof(mes_message_head_t), ctx->sess_id);

    (void)mfc_send_data(&head);
}

static void dcs_send_grant_owner(dms_process_context_t *ctx, mes_message_t *msg)
{
    mes_message_head_t head;

    mfc_init_ack_head(msg->head, &head, MSG_ACK_GRANT_OWNER, sizeof(mes_message_head_t), ctx->sess_id);

    (void)mfc_send_data(&head);
}

static void dcs_route_pcr_request_owner(dms_process_context_t *ctx, msg_pcr_request_t *request, uint8 owner_id)
{
    DMS_INIT_MESSAGE_HEAD(&request->head, MSG_REQ_ASK_OWNER_FOR_CR_PAGE, 0, request->head.src_inst, owner_id,
        request->head.src_sid, CM_INVALID_ID16);

    request->head.dst_inst = owner_id;
    request->head.dst_sid = CM_INVALID_ID16;

    (void)mfc_send_data(&request->head);
}

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

    DMS_INIT_MESSAGE_HEAD(&request->head, MSG_REQ_ASK_MASTER_FOR_CR_PAGE, 0, request->head.src_inst, master_id,
        request->head.src_sid, CM_INVALID_ID16);

    LOG_DEBUG_INF("[PCR][%s][reroute request] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request->pageid), (uint32)request->cr_type, request->query_scn, request->ssn,
        (uint32)request->head.src_inst, (uint32)request->head.src_sid, (uint32)master_id);

    ret = mfc_send_data(&request->head);
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
    assist->try_edp = CM_FALSE;
    assist->read_num = read_num;
}

#ifndef OPENGAUSS
static int dcs_proc_heap_pcr_construct(dms_process_context_t *ctx, msg_pcr_request_t *request, bool32 *local_route)
{
    dms_read_page_assist_t assist;
    msg_pcr_request_t *new_req = NULL;
    char *page = NULL;
    int ret;

    *local_route = CM_FALSE;
    dcs_read_page_init(&assist, request->pageid, DMS_PAGE_LATCH_MODE_S, DMS_ENTER_PAGE_NORMAL, request->query_scn, 1);

    if (g_dms.callback.read_page(ctx->db_handle, &assist, &page) != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_READ_PAGE);
        return ERRNO_DMS_CALLBACK_READ_PAGE;
    }

    // page owner has changed, request master to start the next round construct
    if (page == NULL) {
        return dcs_pcr_reroute_request(ctx, request, local_route);
    }

    // use the received request to generate new request to construct CR page
    new_req = (msg_pcr_request_t *)g_dms.callback.mem_alloc(ctx->db_handle,
        sizeof(msg_pcr_request_t) + g_dms.page_size);
    if (new_req == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_STACK_PUSH);
        return ERRNO_DMS_CALLBACK_STACK_PUSH;
    }
    *new_req = *(msg_pcr_request_t *)request;
    new_req->head.cmd = MSG_REQ_CR_PAGE;
    new_req->head.size = (uint16)(sizeof(msg_pcr_request_t) + g_dms.page_size);

    ret = memcpy_sp((char *)new_req + sizeof(msg_pcr_request_t), g_dms.page_size, page, g_dms.page_size);
    if (ret != EOK) {
        g_dms.callback.mem_free(ctx->db_handle, new_req);
        g_dms.callback.leave_page(ctx->db_handle, CM_FALSE);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(new_req->pageid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    g_dms.callback.leave_page(ctx->db_handle, CM_FALSE);

    /* sync scn before construct CR page */
    g_dms.callback.update_global_scn(ctx->db_handle, request->query_scn);

    ret = dcs_heap_construct_cr_page(ctx, new_req);

    g_dms.callback.mem_free(ctx->db_handle, new_req);

    return ret;
}

static void dcs_handle_pcr_req_master(dms_process_context_t *ctx, mes_message_t *msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(msg, (uint32)sizeof(msg_pcr_request_t), CM_FALSE, CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(msg->buffer);
    uint8 owner_id;
    bool32 local_route = CM_TRUE;
    int ret;

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

void dcs_proc_pcr_req_master(dms_process_context_t *process_ctx, mes_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        recv_msg->head->dst_sid = recv_msg->head->src_sid;
        dms_proc_msg_ack(process_ctx, recv_msg);
        return;
    }

    dcs_handle_pcr_req_master(process_ctx, recv_msg);
#endif
    mfc_release_message_buf(recv_msg);
}


void dcs_proc_pcr_req_owner(dms_process_context_t *process_ctx, mes_message_t *recv_msg)
{
#ifndef OPENGAUSS
    CM_CHK_RECV_MSG_SIZE_NO_ERR(recv_msg, (uint32)sizeof(msg_pcr_request_t), CM_TRUE, CM_TRUE);
    msg_pcr_request_t *request = (msg_pcr_request_t *)(recv_msg->buffer);
    bool32 local_route = CM_FALSE;
    int ret;

    if (request->cr_type == CR_TYPE_HEAP) {
        ret = dcs_proc_heap_pcr_construct(process_ctx, request, &local_route);
        if (ret != DMS_SUCCESS) {
            cm_send_error_msg(recv_msg->head, ret, "construct heap page failed");
        }
    } else {
        cm_send_error_msg(recv_msg->head, ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "NOT SUPPORT CAPABILITY");
    }

    if (local_route) {
        dcs_handle_pcr_req_master(process_ctx, recv_msg);
    }
#endif
    mfc_release_message_buf(recv_msg);
}

#ifndef OPENGAUSS
static int dcs_send_check_visible_ack(dms_process_context_t *ctx, msg_cr_check_t *check, bool8 is_found)
{
    msg_cr_check_ack_t msg;

    DMS_INIT_MESSAGE_HEAD(&msg.head, MSG_ACK_CHECK_VISIBLE, 0, ctx->inst_id, check->head.src_inst,
        ctx->sess_id, check->head.src_sid);
    msg.head.rsn = check->head.rsn;
    msg.head.size = (uint16)sizeof(msg_cr_check_ack_t);
    msg.is_found = is_found;

    LOG_DEBUG_INF("[PCR][%s][send check visible ack] is_found %u "
        "src_inst %u src_sid %u dst_inst %u dst_sid %u",
        cm_display_rowid(check->rowid), (uint32)is_found, (uint32)ctx->inst_id, ctx->sess_id,
        (uint32)check->head.src_inst, (uint32)check->head.src_sid);

    int ret = mfc_send_data(&msg.head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, msg.head.cmd, msg.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_send_check_visible(dms_process_context_t *ctx, msg_cr_check_t *check, uint8 dst_id)
{
    check->head.dst_inst = dst_id;

    LOG_DEBUG_INF("[PCR][%s][send check visible] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_rowid(check->rowid), check->query_scn, check->ssn, (uint32)check->head.src_inst,
        (uint32)check->head.src_sid, (uint32)dst_id);

    int ret = mfc_send_data(&check->head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, check->head.cmd, check->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

static int dcs_heap_check_visible(dms_process_context_t *ctx, msg_cr_check_t *check)
{
    char *page = (char *)check + sizeof(msg_cr_check_t);
    bool8 is_found = CM_TRUE;
    uint8 inst_id;
    bool8 is_empty_txn_list;
    bool8 exist_waiting_txn;
    int ret;

    void *cr_cursor = g_dms.callback.stack_push_cr_cursor(ctx->db_handle);
    if (cr_cursor == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR);
        return ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR;
    }

    g_dms.callback.init_check_cr_cursor(cr_cursor, check->rowid, check->xid, check->query_scn, check->ssn);

    for (;;) {
        ret = g_dms.callback.get_heap_invisible_txn_list(ctx->db_handle, cr_cursor, page,
            &is_empty_txn_list, &exist_waiting_txn);
        if (ret != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST, ret);
            ret = ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST;
            break;
        }

        if (is_empty_txn_list) {
            ret = dcs_send_check_visible_ack(ctx, check, is_found);
            break;
        }

        inst_id = dcs_get_inst_id(ctx->db_handle, cr_cursor, ctx->inst_id);
        if (inst_id == ctx->inst_id) {
            ret = g_dms.callback.check_heap_page_visible_with_udss(ctx->db_handle, cr_cursor, page, &is_found);
            if (ret != DMS_SUCCESS) {
                DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO, ret);
                ret = ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO;
                break;
            }

            if (!is_found) {
                ret = dcs_send_check_visible_ack(ctx, check, is_found);
                break;
            }
        } else {
            ret = dcs_send_check_visible(ctx, check, inst_id);
            break;
        }
    }

    g_dms.callback.stack_pop_cr_cursor(ctx->db_handle);

    return ret;
}
#endif

void dcs_proc_check_visible(dms_process_context_t *process_ctx, mes_message_t *recv_msg)
{
#ifndef OPENGAUSS
    if (recv_msg->head->src_inst == process_ctx->inst_id) {
        recv_msg->head->dst_sid = recv_msg->head->src_sid;
        dms_proc_msg_ack(process_ctx, recv_msg);
        return;
    }

    CM_CHK_RECV_MSG_SIZE_NO_ERR(recv_msg, (uint32)(sizeof(msg_cr_check_t) + g_dms.page_size), CM_TRUE, CM_TRUE);
    int ret = dcs_heap_check_visible(process_ctx, (msg_cr_check_t *)(recv_msg->buffer));
    if (ret != DMS_SUCCESS) {
        cm_send_error_msg(recv_msg->head, ret, "check heap page visible failed");
    }
#endif
    mfc_release_message_buf(recv_msg);
}

static inline void dcs_get_msg_cmd_by_cr_status(dms_cr_status_t cr_status, msg_command_t *msg_cmd,
    const char **log_info)
{
    if (cr_status == DMS_CR_REQ_MASTER) {
        *msg_cmd = MSG_REQ_ASK_MASTER_FOR_CR_PAGE;
        *log_info = "master";
    } else if (cr_status == DMS_CR_REQ_OWNER) {
        *msg_cmd = MSG_REQ_ASK_OWNER_FOR_CR_PAGE;
        *log_info = "owner";
    } else {
        *msg_cmd = MSG_CMD_CEIL;
        CM_ASSERT(0);
    }
}

int dms_specify_instance_construct_heap_cr_page(dms_context_t *dms_ctx, dms_cr_t *dms_cr, unsigned int dst_inst_id,
    dms_cr_status_t *cr_status)
{
    dms_reset_error();
    msg_pcr_request_t request;
    mes_message_t message;
    int ret;
    bool8 is_empty_txn_list;
    bool8 exist_waiting_txn;
    msg_command_t msg_cmd;
    const char *log_info = NULL;

    dcs_get_msg_cmd_by_cr_status(*cr_status, &msg_cmd, &log_info);

    DMS_INIT_MESSAGE_HEAD(&request.head, msg_cmd, 0, dms_ctx->inst_id, dst_inst_id, dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
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
        dms_wait_event_t event = (*cr_status == DMS_CR_REQ_MASTER) ? DMS_EVT_PCR_REQ_MASTER : DMS_EVT_PCR_REQ_OWNER;
        dms_begin_stat(dms_ctx->sess_id, event, CM_TRUE);

        if (mfc_send_data(&request.head) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        if (mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &message, DCS_CR_REQ_TIMEOUT) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_end_stat(dms_ctx->sess_id);
        session_stat_t *stat = DMS_GET_SESSION_STAT(dms_ctx->sess_id);
        stat->stat[DMS_STAT_NET_TIME] += stat->wait[stat->level].usecs;

        ret = dcs_pcr_process_message(dms_ctx, dms_cr, &message, cr_status, &is_empty_txn_list, &exist_waiting_txn);
        if (ret != DMS_SUCCESS) {
            mfc_release_message_buf(&message);
            return ret;
        }

        mfc_release_message_buf(&message);
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[PCR][%s][request %s failed] cr_type %u query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_pageid(request.pageid), log_info, (uint32)CR_TYPE_HEAP, request.query_scn, request.ssn,
        dms_ctx->inst_id, dms_ctx->sess_id, (uint32)dst_inst_id);

    *cr_status = DMS_CR_CHECK_MASTER;
    cm_sleep(DMS_MSG_RETRY_TIME);

    return DMS_SUCCESS;
}

int dms_cr_check_master(dms_context_t *dms_ctx, unsigned int *dst_inst_id, dms_cr_status_t *cr_status)
{
    dms_reset_error();
    uint8 master_id, owner_id;

    CM_ASSERT(*cr_status == DMS_CR_CHECK_MASTER);

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
            *cr_status = DMS_CR_LOCAL_READ;
        } else {
            *dst_inst_id = owner_id;
            *cr_status = DMS_CR_REQ_OWNER;
        }
    } else {
        *dst_inst_id = master_id;
        *cr_status = DMS_CR_REQ_MASTER;
    }

    return DMS_SUCCESS;
}

static int dcs_proc_check_current_visible(dms_cr_t *dms_cr, mes_message_t *msg, bool8 *is_empty_itl,
    unsigned char *is_found)
{
    char *recv_page = NULL;
    switch (msg->head->cmd) {
        case MSG_ACK_CHECK_VISIBLE:
            CM_CHK_RECV_MSG_SIZE(msg, (uint32)sizeof(msg_cr_check_ack_t), CM_FALSE, CM_FALSE);
            *is_found = *(bool8 *)MES_MESSAGE_BODY(msg);
            *is_empty_itl = CM_TRUE;
            return DMS_SUCCESS;
        case MSG_ACK_ERROR:
            cm_print_error_msg(msg->buffer);
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(msg->buffer) + sizeof(msg_error_t)));
            return ERRNO_DMS_COMMON_MSG_ACK;
        case MSG_REQ_CHECK_VISIBLE: {
            CM_CHK_RECV_MSG_SIZE(msg, (uint32)(sizeof(msg_cr_check_t) + g_dms.page_size), CM_FALSE, CM_FALSE);
            msg_cr_check_t *check = (msg_cr_check_t *)(msg->buffer);
            recv_page = (char *)check + sizeof(msg_cr_check_t);
            errno_t err = memcpy_sp(dms_cr->page, g_dms.page_size, recv_page, g_dms.page_size);
            DMS_SECUREC_CHECK(err);
            return DMS_SUCCESS;
        }
        default:
            DMS_THROW_ERROR(ERRNO_DMS_CMD_INVALID, msg->head->cmd);
            return ERRNO_DMS_CMD_INVALID;
    }
}

static inline void dcs_init_msg_cr_check(msg_cr_check_t *check, dms_context_t *dms_ctx, dms_cr_t *dms_cr, uint8 dst_id)
{
    DMS_INIT_MESSAGE_HEAD(&check->head, MSG_REQ_CHECK_VISIBLE, 0, dms_ctx->inst_id, dst_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    check->head.rsn = mfc_get_rsn(dms_ctx->sess_id);
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
    mes_message_t message;
    int ret;

    dcs_init_msg_cr_check(&check, dms_ctx, dms_cr, (uint8)dst_inst_id);

    LOG_DEBUG_INF("[PCR][%s][check current visible] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_rowid(check.rowid), check.query_scn, check.ssn, (uint32)check.head.src_inst,
        (uint32)check.head.src_sid, (uint32)dst_inst_id);

    for (;;) {
        dms_begin_stat(dms_ctx->sess_id, DMS_EVT_PCR_CHECK_CURR_VISIBLE, CM_TRUE);

        if (mfc_send_data3(&check.head, sizeof(msg_cr_check_t), dms_cr->page) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        if (mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &message, DCS_CR_REQ_TIMEOUT) != CM_SUCCESS) {
            dms_end_stat(dms_ctx->sess_id);
            break;
        }

        dms_end_stat(dms_ctx->sess_id);

        ret = dcs_proc_check_current_visible(dms_cr, &message, is_empty_itl, is_found);

        mfc_release_message_buf(&message);
        return ret;
    }

    LOG_DEBUG_ERR("[PCR][%s][check current visible failed] query_scn %llu query_ssn %u "
        "src_inst %u src_sid %u dst_inst %u",
        cm_display_rowid(check.rowid), check.query_scn, check.ssn, (uint32)check.head.src_inst,
        (uint32)check.head.src_sid, (uint32)dst_inst_id);
    return DMS_ERROR;
}

#ifdef __cplusplus
}
#endif