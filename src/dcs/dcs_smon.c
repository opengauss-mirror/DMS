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
#include "dms_error.h"
#include "dms_mfc.h"
#include "dms_msg_protocol.h"
#include "drc_res_mgr.h"
#include "dms_stat.h"
#include "cmpt_msg_cmd.h"
#include "cmpt_msg_lock.h"

#ifndef OPENGAUSS
#define CM_MAX_RMS 16320
static void dcs_proc_smon_get_sid(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint16));

    if (SECUREC_UNLIKELY(rmid >= CM_MAX_RMS)) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_PARAM_INVALID, "invalid rmid value");
        LOG_RUN_ERR("[SMON] proc get sid, the rmid %u is invalid", (uint32)rmid);
        return;
    }

    char *send_msg = (char *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    // must be local rmid, and check session not in INACTIVE
    uint16 sid = g_dms.callback.get_sid_by_rmid(ctx->db_handle, rmid);

    cm_ack_result_msg2(ctx, receive_msg, MSG_ACK_SMON_DLOCK_INFO, (char *)&sid, sizeof(uint16), send_msg);

    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    return;
}

static void dcs_proc_smon_get_txn_dlock(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(dms_message_head_t) + DMS_SMON_DLOCK_MSG_MAX_LEN);
    char ss_lock[DMS_SMON_DLOCK_MSG_MAX_LEN] = {0};

    if (SECUREC_UNLIKELY(rmid >= CM_MAX_RMS)) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_PARAM_INVALID, "invalid rmid value");
        LOG_RUN_ERR("[SMON] proc get txn dlock, the rmid %u is invalid", (uint32)rmid);
        return;
    }

    char *send_msg = (char *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    // must be local rmid
    g_dms.callback.get_txn_dlock_by_rmid(ctx->db_handle, rmid, ss_lock, DMS_SMON_DLOCK_MSG_MAX_LEN);

    cm_ack_result_msg2(ctx, receive_msg, MSG_ACK_SMON_DLOCK_INFO, ss_lock, DMS_SMON_DLOCK_MSG_MAX_LEN, send_msg);

    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    return;
}

static void dcs_proc_smon_get_rowid(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    uint16 rmid = *(uint16 *)(receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32));
    uint32 mes_size = (uint32)(sizeof(dms_message_head_t) + DMS_ROWID_SIZE);
    char rowid[DMS_ROWID_SIZE] = {0};

    if (SECUREC_UNLIKELY(rmid >= CM_MAX_RMS)) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_PARAM_INVALID, "invalid rmid value");
        LOG_RUN_ERR("[SMON] proc get rowid, the rmid %u is invalid", (uint32)rmid);
        return;
    }

    char *send_msg = (char *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    // must be local rmid
    g_dms.callback.get_rowid_by_rmid(ctx->db_handle, rmid, rowid);

    cm_ack_result_msg2(ctx, receive_msg, MSG_ACK_SMON_DLOCK_INFO, rowid, DMS_ROWID_SIZE, send_msg);

    g_dms.callback.mem_free(ctx->db_handle, send_msg);

    return;
}
#endif

void dcs_proc_smon_dlock_msg(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    /* pass */
#else
    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32) + sizeof(uint16));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE);
    uint32 type = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));
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
            CM_THROW_ERROR(ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "dlock msg type");
            LOG_RUN_ERR("invalid dlock msg type");
            break;
    }
#endif
}

void dcs_proc_process_get_itl_lock(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    return;
#endif
    char ilock[DMS_SMON_TLOCK_MSG_MAX_LEN] = {0};

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(dms_message_head_t) + DMS_XID_SIZE), CM_TRUE);
    uint32 mes_size = (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN);

    char *send_msg = (char *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    char *xid = (char *)(receive_msg->buffer + sizeof(dms_message_head_t));
    if (g_dms.callback.get_itl_lock_by_xid(ctx->db_handle, xid, ilock, DMS_SMON_TLOCK_MSG_MAX_LEN) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[SMON][get_itl_lock_by_xid] failed");
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_DCS_GET_TXN_INFO_FAILED, "get itl lock failed");
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    cm_ack_result_msg2(ctx, receive_msg, MSG_ACK_SMON_DEADLOCK_ITL, ilock, DMS_SMON_TLOCK_MSG_MAX_LEN, send_msg);

    g_dms.callback.mem_free(ctx->db_handle, send_msg);

    return;
}

void dcs_proc_smon_deadlock_sql(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    return;
#endif
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(uint16)), CM_TRUE);
    uint16 sid = *(uint16 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    if (SECUREC_UNLIKELY(sid >= DMS_CM_MAX_SESSIONS)) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_PARAM_INVALID, "invalid sid value");
        LOG_RUN_ERR("[SMON] proc dead lock sql, the sid %u is invalid", (uint32)sid);
        return;
    }
    uint32 body_max_len = sizeof(uint32) + DMS_SMON_MAX_SQL_LEN;
    char *body = (char *)g_dms.callback.mem_alloc(ctx->db_handle, body_max_len);
    if (body == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "mem alloc failed");
        return;
    }
    char *sql_str = body + sizeof(uint32);

    g_dms.callback.get_sql_from_session(ctx->db_handle, sid, sql_str, DMS_SMON_MAX_SQL_LEN);
    uint32 sql_len = (uint32)strlen(sql_str);
    *(uint32 *)body = sql_len;

    uint32 body_actual_len = sql_len + sizeof(uint32) + 1;
    char *ack_buf = (char *)g_dms.callback.mem_alloc(ctx->db_handle, sizeof(dms_message_head_t) + body_actual_len);
    if (ack_buf == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        g_dms.callback.mem_free(ctx->db_handle, body);
        return;
    }

    cm_ack_result_msg2(ctx, receive_msg, MSG_ACK_SMON_DEADLOCK_SQL, body, body_actual_len, ack_buf);

    g_dms.callback.mem_free(ctx->db_handle, ack_buf);
    g_dms.callback.mem_free(ctx->db_handle, body);
    return;
}

void dcs_proc_smon_tlock_by_rm(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    /* pass */
#else
    int ret;
    uint8 *send_msg = NULL;
    dms_message_head_t *head = NULL;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(dcs_req_tlock_by_rm_t)),
        CM_TRUE);
    dcs_req_tlock_by_rm_t *req_tlock = (dcs_req_tlock_by_rm_t *)(receive_msg->buffer + sizeof(dms_message_head_t));
    uint32 type = req_tlock->type;
    uint16 sid = req_tlock->sid;
    uint16 rmid = req_tlock->rmid;
    uint32 mes_size = (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN);

    if (SECUREC_UNLIKELY(sid >= DMS_CM_MAX_SESSIONS)) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_PARAM_INVALID, "invalid sid value");
        LOG_RUN_ERR("[SMON] proc table lock by rm, the sid %u is invalid", (uint32)sid);
        return;
    }

    send_msg = (uint8 *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    head = (dms_message_head_t *)send_msg;
    dms_init_ack_head2(head, MSG_ACK_SMON_TLOCK_BY_RM, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        (uint16)ctx->sess_id, receive_msg->head->src_sid, receive_msg->head->msg_proto_ver);
    head->size = (uint16)mes_size;
    head->ruid = receive_msg->head->ruid;

    char *tlock = (char *)(send_msg + sizeof(dms_message_head_t));
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
    dms_reset_error();
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(dms_message_head_t) + sizeof(uint32) + sizeof(uint16));
    dms_message_head_t *head = NULL;
    dms_message_t recv_msg = { 0 };

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (dms_message_head_t *)send_msg;
    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DLOCK_INFO, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id, CM_INVALID_ID16);
    *((uint32 *)(send_msg + sizeof(dms_message_head_t))) = (uint32)type;
    *((uint16 *)(send_msg + sizeof(dms_message_head_t) + sizeof(uint32))) = rmid;

    head->size = msg_size;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)type, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DLOCK_INFO, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_get_response(head->ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive dead lock message to instance(%u) failed, type(%u) rmid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)type, (uint32)rmid, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DLOCK_INFO, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&recv_msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&recv_msg, (uint32)(sizeof(dms_message_head_t) + rsp_size), CM_FALSE);
    errno_t err = memcpy_s((char *)rsp_content, rsp_size, recv_msg.buffer + sizeof(dms_message_head_t), rsp_size);
    if (err != EOK) {
        mfc_release_response(&recv_msg);
        LOG_DEBUG_ERR("[SMON] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }
    mfc_release_response(&recv_msg);
    LOG_DEBUG_INF("[SMON] request dead lock message to instance(%u), type(%u) rmid(%u)", (uint32)dst_inst, (uint32)type,
        (uint32)rmid);
    return CM_SUCCESS;
}

int dms_smon_request_itl_lock_msg(dms_context_t *dms_ctx, unsigned char dst_inst, char *xid, unsigned int xid_len,
    char *ilock, unsigned int ilock_len)
{
    dms_reset_error();
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(dms_message_head_t) + DMS_XID_SIZE);
    dms_message_head_t *head = NULL;
    dms_message_t recv_msg = { 0 };
    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (dms_message_head_t *)send_msg;

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_ITL, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    char *dest = (char *)(send_msg + sizeof(dms_message_head_t));
    int32 retMemcpy = memcpy_s(dest, DMS_XID_SIZE, xid, xid_len);
    if (SECUREC_UNLIKELY(retMemcpy != EOK)) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        CM_THROW_ERROR(ERR_SYSTEM_CALL, retMemcpy);
        return CM_ERROR;
    }

    head->size = msg_size;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request itl lock message to instance(%u)  errcode(%d) failed", (uint32)dst_inst, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_ITL, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_get_response(head->ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive itl lock message to instance(%u) errcode(%d) failed", (uint32)dst_inst, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_ITL, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&recv_msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_ASSERT(ilock_len >= DMS_SMON_TLOCK_MSG_MAX_LEN);
    CM_CHK_RESPONSE_SIZE(&recv_msg, (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN), CM_FALSE);
    errno_t err =
        memcpy_s((char *)ilock, ilock_len, recv_msg.buffer + sizeof(dms_message_head_t), DMS_SMON_TLOCK_MSG_MAX_LEN);
    if (err != EOK) {
        mfc_release_response(&recv_msg);
        LOG_DEBUG_ERR("[SMON] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }
    mfc_release_response(&recv_msg);
    LOG_DEBUG_INF("[SMON] request itl lock message to instance(%u)", (uint32)dst_inst);
    return CM_SUCCESS;
}

int dms_smon_request_sql_from_sid(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid, char *sql_str,
    unsigned int sql_str_len)
{
    dms_reset_error();
    int ret;
    uint8 *send_msg = NULL;
    uint16 msg_size = (uint16)(sizeof(dms_message_head_t) + sizeof(uint16));
    dms_message_head_t *head = NULL;
    dms_message_t recv_msg = { 0 };

    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (dms_message_head_t *)send_msg;
    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_DEADLOCK_SQL, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    *((uint16 *)(send_msg + sizeof(dms_message_head_t))) = sid;
    head->size = msg_size;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request dead lock sql message to instance(%u) failed, sid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)sid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_SQL, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_get_response(head->ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive dead lock sql message to instance(%u) failed, sid(%u) errcode(%d)",
            (uint32)dst_inst, (uint32)sid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_DEADLOCK_SQL, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&recv_msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&recv_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(uint32)), CM_FALSE);
    uint32 len = *(uint32 *)(recv_msg.buffer + sizeof(dms_message_head_t));
    if (len != 0) {
        CM_CHK_RESPONSE_SIZE(&recv_msg,
            (uint32)(sizeof(dms_message_head_t) + sizeof(uint32) + len), CM_FALSE);
        CM_ASSERT(sql_str_len >= len);
        errno_t err = memcpy_s(sql_str, sql_str_len,
            recv_msg.buffer + sizeof(dms_message_head_t) + sizeof(uint32), len);
        if (err != EOK) {
            mfc_release_response(&recv_msg);
            LOG_DEBUG_ERR("[SMON] memcpy_s failed, errno = %d", err);
            DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
            return ERRNO_DMS_SECUREC_CHECK_FAIL;
        }
    }

    mfc_release_response(&recv_msg);
    LOG_DEBUG_INF("[SMON] request dead lock sql message to instance(%u), sid(%u), len(%u)", (uint32)dst_inst,
        (uint32)sid, len);
    return CM_SUCCESS;
}

int dms_smon_req_tlock_by_rm(dms_context_t *dms_ctx, unsigned char dst_inst, unsigned short sid, unsigned short rmid,
    dms_smon_req_rm_type_t type, char *tlock, unsigned int tlock_len)
{
    dms_reset_error();
    int ret;
    uint8 *send_msg = NULL;
    dms_message_head_t *head = NULL;
    dms_message_t recv_msg = { 0 };

    uint16 msg_size = (uint16)(sizeof(dms_message_head_t) + sizeof(dcs_req_tlock_by_rm_t));
    send_msg = (uint8 *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    head = (dms_message_head_t *)send_msg;
    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_TLOCK_BY_RM, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id,
        CM_INVALID_ID16);
    head->size = msg_size;

    dcs_req_tlock_by_rm_t *req_tlock = (dcs_req_tlock_by_rm_t *)(send_msg + sizeof(dms_message_head_t));
    req_tlock->rmid = rmid;
    req_tlock->sid = sid;
    req_tlock->type = type;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[SMON] request get table lock rm message to instance(%u) sid(%u) rmid(%u) errcode(%d) failed",
            (uint32)dst_inst, (uint32)sid, (uint32)rmid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_SMON_TLOCK_BY_RM, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_get_response(head->ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] receive get table lock rm message to instance(%u) sid(%u) rmid(%u) errcode(%d) failed",
            (uint32)dst_inst, (uint32)sid, (uint32)rmid, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_SMON_TLOCK_BY_RM, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&recv_msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&recv_msg, (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN), CM_FALSE);
    CM_ASSERT(tlock_len >= DMS_SMON_TLOCK_MSG_MAX_LEN);
    errno_t err = memcpy_s((char *)tlock, tlock_len,
        recv_msg.buffer + sizeof(dms_message_head_t), DMS_SMON_TLOCK_MSG_MAX_LEN);
    if (err != EOK) {
        mfc_release_response(&recv_msg);
        LOG_DEBUG_ERR("[SMON] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }
    mfc_release_response(&recv_msg);
    return CM_SUCCESS;
}

void dcs_proc_smon_broadcast_req(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_message_head_t), CM_TRUE);
    uint32 output_msg_len = 0;
    uint32 msg_size = (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN * MAX_TABLE_LOCK_NUM);

    dms_message_head_t *ack_head = (dms_message_head_t *)g_dms.callback.mem_alloc(ctx->db_handle, msg_size);
    char *output_msg = (char *)ack_head + sizeof(dms_message_head_t);

    dms_message_head_t *head = (dms_message_head_t *)(receive_msg->buffer);
    LOG_DEBUG_INF("Receive smon broadcast, cmd: %d", head->cmd);
    char *data = receive_msg->buffer + sizeof(dms_message_head_t);
    uint32 len = (uint32)(head->size - sizeof(dms_message_head_t));
    dms_broadcast_context_t broad_ctx = {
        .data = data, .len = len, .output_msg = output_msg, .output_msg_len = &output_msg_len};
    int32 ret = g_dms.callback.process_broadcast(ctx->db_handle, &broad_ctx);
    if (output_msg_len != 0) {
        DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_BROADCAST_WITH_MSG, MSG_ACK_BROADCAST_WITH_MSG);
        dms_init_ack_head2(ack_head, MSG_ACK_BROADCAST_WITH_MSG, 0, receive_msg->head->dst_inst,
            receive_msg->head->src_inst, (uint16)ctx->sess_id, receive_msg->head->src_sid,
            receive_msg->head->msg_proto_ver);
        ack_head->size = (uint16)(sizeof(dms_message_head_t) + output_msg_len);
        ack_head->ruid = receive_msg->head->ruid;
        if (mfc_send_data(ack_head) != DMS_SUCCESS) {
            LOG_DEBUG_ERR("send result msg to instance %d failed.", receive_msg->head->src_inst);
        }
    } else {
        DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_BROADCAST, MSG_ACK_BROADCAST);
        cm_ack_result_msg(ctx, receive_msg, MSG_ACK_BROADCAST, ret);
    }
    g_dms.callback.mem_free(ctx->db_handle, ack_head);
    LOG_DEBUG_INF("Succeed to send ack to inst %u", receive_msg->head->src_inst);
}

void dcs_proc_smon_tlock_by_tid(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(dcs_req_tlock_by_tid_t)),
        CM_TRUE);
    dms_message_head_t *rev_head = (dms_message_head_t *)receive_msg->buffer;
    dcs_req_tlock_by_tid_t req = *(dcs_req_tlock_by_tid_t *)(receive_msg->buffer + sizeof(dms_message_head_t));
    uint32 msg_size = (uint32)(sizeof(dms_message_head_t) + DMS_SMON_TLOCK_MSG_MAX_LEN * MAX_TABLE_LOCK_NUM);

    LOG_DEBUG_INF("[DMS][dcs_proc_smon_tlock_by_tid]:src_instid=%d, src_sid=%d", rev_head->src_inst,
        rev_head->src_sid);

    char *send_msg = g_dms.callback.mem_alloc(ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }

    dms_message_head_t *snd_head = (dms_message_head_t *)send_msg;
    dms_init_ack_head(rev_head, snd_head, MSG_ACK_SMON_TLOCK_BY_TID, (uint16)msg_size, rev_head->src_sid);

    char *out_msg = (char *)(send_msg + sizeof(dms_message_head_t));
    int ret = g_dms.callback.get_tlock_by_tid(ctx->db_handle, req.tlock, out_msg);
    if (ret != DMS_SUCCESS) {
        g_dms.callback.mem_free(ctx->db_handle, send_msg);
        return;
    }

    ret = mfc_send_data(snd_head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process get tlock message from failed, ret = %d ", ret);
    }
    g_dms.callback.mem_free(ctx->db_handle, send_msg);
    return;
}

int dms_smon_req_tlock_by_tid(dms_context_t *dms_ctx, void *data, unsigned int len, unsigned int inst_id, char *stack,
    char *w_marks, unsigned int *valid_cnt)
{
    dms_reset_error();
    dms_message_head_t *head = NULL;
    uint64 ruid;
    int32 ret;
    char send_msg[sizeof(dms_message_head_t) + sizeof(dcs_req_tlock_by_tid_t)] = {0};

    head = (dms_message_head_t *)send_msg;
    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_SMON_TLOCK_BY_TID, 0, dms_ctx->inst_id, inst_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    head->size = (uint16)(sizeof(dms_message_head_t) + sizeof(dcs_req_tlock_by_tid_t));

    dcs_req_tlock_by_tid_t *req = (dcs_req_tlock_by_tid_t *)(&send_msg[sizeof(dms_message_head_t)]);
    DMS_SECUREC_CHECK(memcpy_sp(req->tlock, len, data, len));

    LOG_DEBUG_INF("[DMS][ASK TLOCK BY TID]: src_id=%u-%u, dst_inst=%u", dms_ctx->inst_id, dms_ctx->sess_id, inst_id);

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, head->cmd, head->dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    ruid = head->ruid;

    dms_message_t msg = {0};
    ret = mfc_get_response(ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][dms_smon_req_tlock_by_tid]: wait get tlock by tid ack timeout");
        return ret;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, msg.buffer + sizeof(msg_error_t));
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&msg, (uint32)sizeof(dms_message_head_t), CM_FALSE);
    char *recv_msg = msg.buffer + sizeof(dms_message_head_t);

    g_dms.callback.get_tlock_by_tid_ack(recv_msg, stack, w_marks, valid_cnt);
    mfc_release_response(&msg);
    return CM_SUCCESS;
}

typedef struct dms_send_req_and_handle_ack_ctx {
    uint16 req_msg_type;
    uint16 rsp_msg_type;
    uint16 msg_size;
    void *cookie;
    int (*build_req_msg_body)(void *cookie, void *req_msg);
    int (*check_and_handle_rsp_msg)(void *cookie, dms_message_t *rsp_msg);
    char *(*cookie_desp_or_null)(void *cookie);
} dms_send_req_and_handle_ack_ctx_t;

int dms_send_req_msg_and_recv_ack(dms_context_t *dms_ctx, unsigned char dst_inst,
    dms_send_req_and_handle_ack_ctx_t *ctx)
{
    dms_reset_error();
    int ret;
    dms_message_t recv_msg = { 0 };
    uint16 msg_size = ctx->msg_size;
    msg_command_t req_msg_type = ctx->req_msg_type;
    msg_command_t rsp_msg_type = ctx->rsp_msg_type;

    void *send_msg = (void *)g_dms.callback.mem_alloc(dms_ctx->db_handle, msg_size);
    if (send_msg == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    // build req msg head
    dms_message_head_t *head = (dms_message_head_t *)send_msg;
    DMS_INIT_MESSAGE_HEAD(head, req_msg_type, 0, g_dms.inst_id, dst_inst, dms_ctx->sess_id, CM_INVALID_ID16);
    head->size = msg_size;
    // build req msg body
    (void)ctx->build_req_msg_body(ctx->cookie, (void *)send_msg);

    // send msg
    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);
        LOG_DEBUG_ERR("[DMS] send request message to instance(%u), cookie(%s) errcode(%d) failed", (uint32)dst_inst,
            (ctx->cookie_desp_or_null == NULL ? "null" : ctx->cookie_desp_or_null(ctx->cookie)), ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, req_msg_type, dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    g_dms.callback.mem_free(dms_ctx->db_handle, send_msg);

    ret = mfc_get_response(head->ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DMS] receive response message from instance(%u) cookie(%s) errcode(%d) failed",
            (uint32)dst_inst, (ctx->cookie_desp_or_null == NULL ? "null" : ctx->cookie_desp_or_null(ctx->cookie)), ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, rsp_msg_type, dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&recv_msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }
    ret = ctx->check_and_handle_rsp_msg(ctx->cookie, &recv_msg);
    mfc_release_response(&recv_msg);
    return ret;
}

typedef struct st_dms_smon_alock_req_assist {
    alockid_t *alockid;
    char *result_buf;
    uint32 buf_len;
    uint32 *result_len;
} dms_smon_alock_req_assist_t;

char *dms_smon_alock_cookie_desp(void *cookie)
{
    dms_smon_alock_req_assist_t *user_data = cookie;
    return cm_display_alockid(user_data->alockid);
}

int dms_build_smon_alock_req_msg_body(void *cookie, void *req_msg)
{
    dms_smon_alock_req_assist_t *user_data = cookie;
    dms_smon_deadlock_alock_req_t *req = (dms_smon_deadlock_alock_req_t *)req_msg;
    errno_t err = memcpy_s(&req->alockid, sizeof(alockid_t), user_data->alockid, sizeof(alockid_t));
    DMS_SECUREC_CHECK(err);
    return DMS_SUCCESS;
}

int dms_check_and_handle_alock_rsp_msg(void *cookie, dms_message_t *recv_msg)
{
    dms_smon_alock_req_assist_t *user_data = cookie;
    CM_CHK_RESPONSE_SIZE2(recv_msg, sizeof(dms_smon_deadlock_alock_rsp_t), CM_FALSE);
    dms_smon_deadlock_alock_rsp_t *rsp = (dms_smon_deadlock_alock_rsp_t *)recv_msg->buffer;
    *user_data->result_len = rsp->data_size;
    if (rsp->data_size != 0) {
        uint32 len = rsp->data_size + (uint32)sizeof(dms_smon_deadlock_alock_rsp_t);
        CM_CHK_RESPONSE_SIZE2(recv_msg, len, CM_FALSE);
        CM_ASSERT(user_data->buf_len >= rsp->data_size);
        errno_t err = memcpy_s(user_data->result_buf, user_data->buf_len, rsp->data, rsp->data_size);
        if (err != EOK) {
            LOG_DEBUG_ERR("[SMON] memcpy_s failed, errno = %d", err);
            DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
            return ERRNO_DMS_SECUREC_CHECK_FAIL;
        }
    }
    return DMS_SUCCESS;
}

int dms_smon_deadlock_get_alock_info_by_drid(dms_context_t *dms_ctx, unsigned char dst_inst, alockid_t *alockid,
    char *res_buf, unsigned int buf_len, unsigned int *res_len)
{
    dms_smon_alock_req_assist_t user_data = {
        .alockid = alockid,
        .result_buf = res_buf,
        .buf_len = buf_len,
        .result_len = res_len
    };

    dms_send_req_and_handle_ack_ctx_t msg_proc_ctx = {
        .req_msg_type = MSG_REQ_SMON_ALOCK_BY_DRID,
        .rsp_msg_type = MSG_ACK_SMON_ALOCK_BY_DRID,
        .msg_size = (uint16)sizeof(dms_smon_deadlock_alock_req_t),
        .cookie = (void *)&user_data,
        .build_req_msg_body = dms_build_smon_alock_req_msg_body,
        .check_and_handle_rsp_msg = dms_check_and_handle_alock_rsp_msg,
        .cookie_desp_or_null = dms_smon_alock_cookie_desp,
    };
    return dms_send_req_msg_and_recv_ack(dms_ctx, dst_inst, &msg_proc_ctx);
}
#define DMS_MAX_DEADLOCK_ALOCK_MES_SIZE SIZE_K(32)
void dcs_proc_smon_alock_by_drid(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    /* pass */
#else
    int ret;
    dms_smon_deadlock_alock_rsp_t *rsp_msg = NULL;
    dms_message_head_t *head = NULL;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_smon_deadlock_alock_req_t), CM_TRUE);
    dms_smon_deadlock_alock_req_t *req = (dms_smon_deadlock_alock_req_t *)receive_msg->buffer;
    uint32 mes_size = DMS_MAX_DEADLOCK_ALOCK_MES_SIZE;

    rsp_msg = (dms_smon_deadlock_alock_rsp_t *)g_dms.callback.mem_alloc(ctx->db_handle, mes_size);
    if (rsp_msg == NULL) {
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_ALLOC_FAILED, "alloc memory failed");
        return;
    }
    head = &rsp_msg->head;
    dms_init_ack_head2(head, MSG_ACK_SMON_ALOCK_BY_DRID, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, (uint16)ctx->sess_id, receive_msg->head->src_sid,
        receive_msg->head->msg_proto_ver);
    head->size = (uint16)mes_size;
    head->ruid = receive_msg->head->ruid;
    uint16 rsp_head_size = (uint16)sizeof(dms_smon_deadlock_alock_rsp_t);
    uint32 buf_len = mes_size - rsp_head_size;
    uint32 info_len = 0;
    ret = g_dms.callback.get_alock_wait_info(ctx->db_handle, (char *)&req->alockid, rsp_msg->data, buf_len, &info_len);
    rsp_msg->ret_code = (uint32)ret;
    rsp_msg->data_size = info_len;
    head->size = rsp_head_size + (uint16)rsp_msg->data_size;

    ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[SMON] process get alock wait info message from instance(%u) sid(%u) lockid(%s) ret(%d) failed",
            (uint32)head->dst_inst, (uint32)req->head.src_inst, cm_display_alockid(&req->alockid), ret);
        g_dms.callback.mem_free(ctx->db_handle, rsp_msg);
        return;
    }

    LOG_DEBUG_INF("[SMON] process get alock wait info message from instance(%u) sid(%u) lockid(%s) ret(%d)",
        (uint32)head->dst_inst, (uint32)req->head.src_inst, cm_display_alockid(&req->alockid), ret);
    g_dms.callback.mem_free(ctx->db_handle, rsp_msg);

#endif
    return;
}