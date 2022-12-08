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
 * dcs_smon.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_smon.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_smon.h"
#include "dms_errno.h"
#include "dms_log.h"
#include "dms_mfc.h"

#ifndef OPENGAUSS
static void dcs_proc_smon_get_sid(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
    int ret = CM_SUCCESS;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint16));
    uint16 sid;

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }
    head = (mes_message_head_t *)send_msg;

    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DLOCK_INFO, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;
    mfc_release_message_buf(receive_msg);

    // must be local rmid, and check session not in INACTIVE
    sid = g_dms.callback.get_sid_by_rmid(ctx->db_handle, rmid); // ss_get_sid_by_rmid
    *((uint16 *)(send_msg + sizeof(mes_message_head_t))) = sid;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process sid message from instance(%u), rmid(%u) sid(%u) ret(%d) failed",
            (uint32)head->dst_inst, (uint32)rmid, (uint32)sid, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] process sid message from instance(%u), rmid(%u) sid(%u)", (uint32)head->dst_inst,
        (uint32)rmid, (uint32)sid);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    return;
}

static void dcs_proc_smon_get_txn_dlock(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + DMS_SMON_DLOCK_MSG_MAX_LEN);
    char *ss_lock;

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }

    head = (mes_message_head_t *)send_msg;

    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DLOCK_INFO, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;

    ss_lock = (char *)(send_msg + sizeof(mes_message_head_t));
    // must be local rmid
    g_dms.callback.get_txn_dlock_by_rmid(ctx->db_handle, rmid, ss_lock, DMS_SMON_DLOCK_MSG_MAX_LEN);
    mfc_release_message_buf(receive_msg);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process txn dead lock message from instance(%u), rmid(%u) ret(%d) failed",
            (uint32)head->dst_inst, (uint32)rmid, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] process txn dead lock message from instance(%u), rmid(%u)", (uint32)head->dst_inst,
        (uint32)rmid);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    return;
}

static void dcs_proc_smon_get_rowid(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + DMS_ROWID_SIZE);
    char *rowid;

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }

    head = (mes_message_head_t *)send_msg;

    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DLOCK_INFO, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;

    rowid = (char *)(send_msg + sizeof(mes_message_head_t));
    // must be local rmid
    g_dms.callback.get_rowid_by_rmid(ctx->db_handle, rmid, rowid);
    mfc_release_message_buf(receive_msg);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process sid message from instance(%u), rmid(%u) ret(%d) failed", (uint32)head->dst_inst,
            (uint32)rmid, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    LOG_DEBUG_INF("[SMON] process row id message from instance(%u), rmid(%u)", (uint32)head->dst_inst, (uint32)rmid);
    return;
}
#endif

void dcs_proc_smon_dlock_msg(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    uint32 total_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(uint16));
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE, CM_TRUE);
    uint32 type = *(uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    switch (type) {
        case DMS_SMON_REQ_SID_BY_RMID:
            dcs_proc_smon_get_sid(ctx, receive_msg);
            break;
        case DMS_SMON_REQ_DLOCK_BY_RMID:
            dcs_proc_smon_get_txn_dlock(ctx, receive_msg);
            break;
        case DMS_SMON_REQ_ROWID_BY_RMID:
            dcs_proc_smon_get_rowid(ctx, receive_msg);
            break;
        default:
            cm_panic(0);
    }
#endif
}

void dcs_proc_process_get_itl_lock(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(mes_message_head_t) + DMS_XID_SIZE), CM_TRUE, CM_TRUE);
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + DMS_SMON_ILOCK_MSG_MAX_LEN);

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DEADLOCK_ITL, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;

    char *xid = (char *)(receive_msg->buffer + sizeof(mes_message_head_t));
    char *ilock = (char *)(send_msg + sizeof(mes_message_head_t));
    g_dms.callback.get_itl_lock_by_xid(ctx->db_handle, xid, ilock, DMS_SMON_ILOCK_MSG_MAX_LEN);
    mfc_release_message_buf(receive_msg);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process itl lock message from instance(%u),ret(%d) failed", (uint32)head->dst_inst, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] processitl lock lock message from instance(%u)", (uint32)head->dst_inst);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
#endif
    return;
}

void dcs_proc_smon_deadlock_sql(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    status_t ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(uint16)), CM_TRUE, CM_TRUE);
    uint16 sid = *(uint16 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    char *sql_str = (char *)g_dms.callback.mem_alloc(ctx->db_handle, DMS_SMON_MAX_SQL_LEN);
    if (sql_str == NULL) {
        mfc_release_message_buf(receive_msg);
        return;
    }

    g_dms.callback.get_sql_from_session(ctx->db_handle, sid, sql_str, DMS_SMON_MAX_SQL_LEN);
    uint32 sql_len = (uint32)strlen(sql_str) + 1;

    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + sql_len);
    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        g_dms.callback.mem_free(ctx->db_handle, sql_str);
        return;
    }

    head = (mes_message_head_t *)send_msg;

    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DEADLOCK_SQL, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;
    mfc_release_message_buf(receive_msg);

    *(uint32 *)(send_msg + sizeof(mes_message_head_t)) = sql_len;
    if (sql_len != 1) {
        char *dest = (char *)(send_msg + sizeof(mes_message_head_t) + sizeof(uint32));
        int32 retMemcpy = memcpy_s(dest, sql_len, sql_str, sql_len);
        if (SECUREC_UNLIKELY(retMemcpy != EOK)) {
            g_dms.callback.mem_free(ctx->db_handle, send_msg);
            g_dms.callback.mem_free(ctx->db_handle, sql_str);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, retMemcpy);
            return;
        }
    }

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process dead lock sql message from instance(%u), sid(%u) failed", (uint32)head->dst_inst,
            (uint32)sid);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        g_dms.callback.mem_free(ctx->db_handle, sql_str);
        return;
    }

    LOG_DEBUG_INF("[SMON] process dead lock sql message from instance(%u), sid(%u)", (uint32)head->dst_inst,
        (uint32)sid);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    g_dms.callback.mem_free(ctx->db_handle, sql_str);
#endif
    return;
}

void dcs_proc_smon_check_tlock_status(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    uint32 total_size = (uint32)(sizeof(mes_message_head_t) + sizeof(dcs_check_tlock_status_t));
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE, CM_TRUE);

    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + sizeof(bool32));
    bool32 in_use = CM_FALSE;
    dcs_check_tlock_status_t *check_tlock =
        (dcs_check_tlock_status_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 type = check_tlock->type;
    uint16 sid = check_tlock->sid;
    uint64 tableid = check_tlock->table_id;
    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DEADLOCK_CHECK_STATUS, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;

    // must be local
    g_dms.callback.check_tlock_status(ctx->db_handle, type, sid, tableid, &in_use);

    *((bool32 *)(send_msg + sizeof(mes_message_head_t))) = in_use;
    mfc_release_message_buf(receive_msg);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON]process check_tlock_status message from instance(%u) sid(%u) tableid(%llu) ret(%d) failed",
            (uint32)head->dst_inst, (uint32)sid, tableid, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] process check_tlock_status message from instance(%u) sid(%u) tableid(%llu) in_use(%u)",
        (uint32)head->dst_inst, (uint32)sid, tableid, in_use);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
#endif
    return;
}

void dcs_proc_smon_table_lock_by_tid(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    int ret;
    uint32 count = 0;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;

    uint32 mes_size = 0;

    uint32 total_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(uint64));
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE, CM_TRUE);

    uint32 type = *(uint32 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint64 table_id = *(uint64 *)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint32));
    mes_size = DMS_SMON_TLOCK_MSG_MAX_LEN * MAX_TABLE_LOCK_NUM;
    char *rsp = (char *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (rsp == NULL) {
        mfc_release_message_buf(receive_msg);
        return;
    }

    g_dms.callback.get_tlock_by_tid(ctx->db_handle, table_id, type, rsp, mes_size, &count);
    mes_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + DMS_SMON_TLOCK_MSG_MAX_LEN * count);
    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        g_dms.callback.mem_free(ctx->db_handle, rsp);
        return;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_MSG, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;
    mfc_release_message_buf(receive_msg);

    *(uint32 *)(send_msg + sizeof(mes_message_head_t)) = count;
    if (count != 0) {
        char *dest = (char *)(send_msg + sizeof(mes_message_head_t) + sizeof(uint32));
        int32 retMemcpy =
            memcpy_s((char *)dest, count * DMS_SMON_TLOCK_MSG_MAX_LEN, rsp, count * DMS_SMON_TLOCK_MSG_MAX_LEN);
        if (SECUREC_UNLIKELY(retMemcpy != EOK)) {
            g_dms.callback.mem_free(ctx->db_handle, send_msg);
            g_dms.callback.mem_free(ctx->db_handle, rsp);
            CM_THROW_ERROR(ERR_SYSTEM_CALL, retMemcpy);
            return;
        }
    }

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process wait tlocks message from instance(%u) table_id(%llu) count(%u) failed, ret(%d)",
            (uint32)head->dst_inst, table_id, count, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        g_dms.callback.mem_free(ctx->db_handle, rsp);
        return;
    }

    LOG_DEBUG_INF("[SMON] process wait tlocks message from instance(%u) table_id(%llu) count(%u)",
        (uint32)head->dst_inst, table_id, count);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    g_dms.callback.mem_free(ctx->db_handle, rsp);
#endif
    return;
}

void dcs_proc_smon_table_lock_by_rm(dms_process_context_t *ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(dcs_req_tlock_t)), CM_TRUE,
        CM_TRUE);
    dcs_req_tlock_t *req_tlock = (dcs_req_tlock_t *)(receive_msg->buffer + sizeof(mes_message_head_t));
    uint32 type = req_tlock->type;
    uint16 sid = req_tlock->sid;
    uint16 rmid = req_tlock->rmid;
    uint32 mes_size = (uint32)(sizeof(mes_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN);

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        mfc_release_message_buf(receive_msg);
        return;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_RM, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)mes_size;
    head->rsn = receive_msg->head->rsn;
    mfc_release_message_buf(receive_msg);

    char *tlock = (char *)(send_msg + sizeof(mes_message_head_t));
    g_dms.callback.get_tlock_by_rm(ctx->db_handle, sid, rmid, type, tlock, DMS_SMON_TLOCK_MSG_MAX_LEN);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process get tlock message from instance(%u) rmid(%u) sid(%u) ret(%d) failed",
            (uint32)head->dst_inst, (uint32)rmid, (uint32)sid, ret);
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] process get tlock message from instance(%u) rmid(%u) sid(%u), ret(%d)",
        (uint32)head->dst_inst, (uint32)rmid, (uint32)sid, ret);
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
#endif
    return;
}


int dms_smon_request_ss_lock_msg(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short rmid,
    dms_smon_req_type_t type, char *rsp_content, unsigned int rsp_size)
{
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(uint16));
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DLOCK_INFO, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id, CM_INVALID_ID16);
    *((uint32 *)(send_msg + sizeof(mes_message_head_t))) = (uint32)type;
    *((uint16 *)(send_msg + sizeof(mes_message_head_t) + sizeof(uint32))) = rmid;

    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)type, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DLOCK_INFO, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)type, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DLOCK_INFO, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&recv_msg, (uint32)(sizeof(mes_message_head_t) + rsp_size), CM_TRUE, CM_FALSE);
    MEMS_RETURN_IFERR(memcpy_s((char *)rsp_content, rsp_size, recv_msg.buffer + sizeof(mes_message_head_t), rsp_size));
    mfc_release_message_buf(&recv_msg);
    LOG_DEBUG_INF("[SMON] request dead lock message to instance(%u), type(%u) rmid(%u)", (uint32)dst_inst, (uint32)type,
        (uint32)rmid);
    return CM_SUCCESS;
}

int dms_smon_request_itl_lock_msg(dms_context_t *dms_ctx, unsigned char dst_inst, char xid[DMS_XID_SIZE], char *ilock,
    unsigned int ilock_len)
{
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + DMS_XID_SIZE);
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };
    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_ITL, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    char *dest = (char *)(send_msg + sizeof(mes_message_head_t));
    int32 retMemcpy = memcpy_s(dest, DMS_XID_SIZE, xid, DMS_XID_SIZE);
    if (SECUREC_UNLIKELY(retMemcpy != EOK)) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, retMemcpy);
        return CM_ERROR;
    }

    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request itl lock message to instance(%u)  errcode(%d) failed", (uint32)dst_inst, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_ITL, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive itl lock message to instance(%u) errcode(%d) failed", (uint32)dst_inst, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_ITL, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }
    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_ASSERT(ilock_len >= DMS_SMON_ILOCK_MSG_MAX_LEN);
    CM_CHK_RECV_MSG_SIZE(&recv_msg,
        (uint32)(sizeof(mes_message_head_t) + DMS_SMON_ILOCK_MSG_MAX_LEN), CM_TRUE, CM_FALSE);
    MEMS_RETURN_IFERR(
        memcpy_s((char *)ilock, ilock_len, recv_msg.buffer + sizeof(mes_message_head_t), DMS_SMON_ILOCK_MSG_MAX_LEN));
    mfc_release_message_buf(&recv_msg);
    LOG_DEBUG_INF("[SMON] request itl lock message to instance(%u)", (uint32)dst_inst);
    return CM_SUCCESS;
}

int dms_smon_request_sql_from_sid(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid, char *sql_str,
    unsigned int sql_str_len)
{
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + sizeof(uint16));
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_SQL, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    *((uint16 *)(send_msg + sizeof(mes_message_head_t))) = sid;
    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request dead lock sql message to instance(%u) failed, sid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)sid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_SQL, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive dead lock sql message to instance(%u) failed, sid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)sid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_SQL, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&recv_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(uint32)), CM_TRUE, CM_FALSE);
    uint32 len = *(uint32 *)(recv_msg.buffer + sizeof(mes_message_head_t));
    if (len != 0) {
        CM_CHK_RECV_MSG_SIZE(&recv_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + len), CM_TRUE, CM_FALSE);
        CM_ASSERT(sql_str_len >= len);
        MEMS_RETURN_IFERR(
            memcpy_s(sql_str, sql_str_len, recv_msg.buffer + sizeof(mes_message_head_t) + sizeof(uint32), len));
    }

    mfc_release_message_buf(&recv_msg);
    LOG_DEBUG_INF("[SMON] request dead lock sql message to instance(%u), sid(%u), len(%u)", (uint32)dst_inst,
        (uint32)sid, len);
    return CM_SUCCESS;
}

int dms_smon_check_tlock_status(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid,
    unsigned long long table_id, dms_smon_check_tlock_type_t type, unsigned int *in_use)
{
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + sizeof(dcs_check_tlock_status_t));
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_CHECK_STATUS, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);
    dcs_check_tlock_status_t *check_tlock = (dcs_check_tlock_status_t *)(send_msg + sizeof(mes_message_head_t));
    check_tlock->type = type;
    check_tlock->sid = sid;
    check_tlock->table_id = table_id;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request check tlock status message to instance(%u) sid(%u) tableid(%llu) errcode(%d) ",
            (uint32)dst_inst, (uint32)sid, table_id, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_CHECK_STATUS, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] recv check tlock status message to instance(%u) sid(%u) tableid(%llu) errcode(%d) ",
            (uint32)dst_inst, (uint32)sid, table_id, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_CHECK_STATUS, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&recv_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(bool32)), CM_TRUE, CM_FALSE);
    *in_use = *(bool32 *)(recv_msg.buffer + sizeof(mes_message_head_t));
    mfc_release_message_buf(&recv_msg);

    LOG_DEBUG_INF("[SMON] check tlock status message to instance(%u) sid(%u) tableid(%llu) status(%u) ",
        (uint32)dst_inst, (uint32)sid, table_id, *in_use);
    return CM_SUCCESS;
}

int dms_smon_request_table_lock_by_tid(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned long long table_id,
    dms_smon_req_tlock_type_t type, char *rsp, unsigned int rsp_len, unsigned int *tlock_cnt)
{
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };
    *tlock_cnt = 0;
    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + sizeof(uint32) + sizeof(uint64));

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_TID, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);

    *((uint32 *)(send_msg + sizeof(mes_message_head_t))) = (uint32)type;
    *((uint64 *)(send_msg + sizeof(mes_message_head_t) + sizeof(uint32))) = table_id;
    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request table_lock_msg message to instance(%u) table_id(%llu) errcode(%d) failed",
            (uint32)dst_inst, table_id, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_TID, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive table_lock_msg message to instance(%u) table_id(%llu) errcode(%d) failed",
            (uint32)dst_inst, table_id, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_TID, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&recv_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(uint32)), CM_TRUE, CM_FALSE);
    *tlock_cnt = *(uint32 *)(recv_msg.buffer + sizeof(mes_message_head_t));
    if (*tlock_cnt != 0) {
        uint32 len = (uint32)(sizeof(mes_message_head_t) + sizeof(uint32) + (*tlock_cnt) * DMS_SMON_TLOCK_MSG_MAX_LEN);
        CM_CHK_RECV_MSG_SIZE(&recv_msg, len, CM_TRUE, CM_FALSE);
        CM_ASSERT(rsp_len >= (*tlock_cnt) * DMS_SMON_TLOCK_MSG_MAX_LEN);
        MEMS_RETURN_IFERR(memcpy_s(rsp, rsp_len, recv_msg.buffer + sizeof(mes_message_head_t) + sizeof(uint32),
            (*tlock_cnt) * DMS_SMON_TLOCK_MSG_MAX_LEN));
    }
    mfc_release_message_buf(&recv_msg);
    return CM_SUCCESS;
}

int dms_smon_request_table_lock_by_rm(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid,
    unsigned short rmid, dms_smon_req_rm_type_t type, char *tlock, unsigned int tlock_len)
{
    int ret;
    uint8 *send_msg = NULL;
    mes_message_head_t *head = NULL;
    mes_message_t recv_msg = { 0 };

    uint16 msg_size = (uint16)(sizeof(mes_message_head_t) + sizeof(dcs_req_tlock_t));
    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (mes_message_head_t *)send_msg;
    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_RM, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    head->size = msg_size;
    head->rsn = mes_get_rsn(dms_ctx->sess_id);

    dcs_req_tlock_t *req_tlock = (dcs_req_tlock_t *)(send_msg + sizeof(mes_message_head_t));
    req_tlock->rmid = rmid;
    req_tlock->sid = sid;
    req_tlock->type = type;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request get table lock rm message to instance(%u) sid(%u) rmid(%u) errcode(%d) failed",
            (uint32)dst_inst, (uint32)sid, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_RM, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive get table lock rm message to instance(%u) sid(%u) rmid(%u) errcode(%d) failed",
            (uint32)dst_inst, (uint32)sid, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_RM, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }
    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(recv_msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((msg_error_t *)(recv_msg.buffer) + sizeof(msg_error_t)));
        mfc_release_message_buf(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&recv_msg,
        (uint32)(sizeof(mes_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN), CM_TRUE, CM_FALSE);
    CM_ASSERT(tlock_len >= DMS_SMON_TLOCK_MSG_MAX_LEN);
    MEMS_RETURN_IFERR(
        memcpy_s((char *)tlock, tlock_len, recv_msg.buffer + sizeof(mes_message_head_t), DMS_SMON_TLOCK_MSG_MAX_LEN));
    mfc_release_message_buf(&recv_msg);
    return CM_SUCCESS;
}
