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
 * dcs_tran.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_tran.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_tran.h"
#include "dcs_msg.h"
#include "dms.h"
#include "dms_msg.h"
#include "drc.h"
#include "drc_tran.h"
#include "dms_stat.h"
#include "dms_log.h"

int dms_request_opengauss_lock_buffer(dms_context_t *dms_ctx, int buffer, unsigned char mode,
    unsigned char *lw_lock_mode)
{
    msg_opengauss_lock_buffer_ctx_t lock_ctx;
    mes_message_head_t *head = &lock_ctx.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_LOCK_BUFFER, 0, (uint8)dms_ctx->inst_id,
        (uint8)xid_ctx->inst_id, (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    lock_ctx.buffer = buffer;
    lock_ctx.lock_mode = mode;

    head->size = (uint16)sizeof(msg_opengauss_lock_buffer_ctx_t);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%hhu) failed, cmd(%d) rsn(%u) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_LOCK_BUFFER, head->rsn, ret);
        return ret;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%hhu) failed, cmd(%d) rsn(%u) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_LOCK_BUFFER, head->rsn, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    if (lw_lock_mode != NULL) {
        CM_CHK_RECV_MSG_SIZE(&receive_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(bool8)), CM_TRUE, CM_FALSE);
        *lw_lock_mode = *(unsigned char *)(receive_msg.buffer + sizeof(mes_message_head_t));
    }
    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_lock_buffer_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    mfc_release_message_buf(receive_msg);
}

int dms_request_opengauss_txn_status(dms_context_t *dms_ctx, unsigned char request, unsigned char *result)
{
    msg_opengauss_txn_status_request_t status_req;
    mes_message_head_t *head = &status_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_TXN_STATUS, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    status_req.xid = xid_ctx->xid;
    status_req.request_type = request;

    head->size = (uint16)sizeof(msg_opengauss_txn_status_request_t);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_STATUS, head->rsn, (uint32)ret);
        return ret;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_STATUS, head->rsn, (uint32)ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RECV_MSG_SIZE(&receive_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(bool8)), CM_TRUE, CM_FALSE);
    *result = *(bool8 *)(receive_msg.buffer + sizeof(mes_message_head_t));
    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_txn_status_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    mes_message_head_t *req_head = receive_msg->head;
    mes_message_head_t ack_head;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_txn_status_request_t), CM_TRUE, CM_TRUE);
    msg_opengauss_txn_status_request_t *status_req = (msg_opengauss_txn_status_request_t *)(receive_msg->buffer);

    uint64 xid = status_req->xid;
    unsigned char req_type = status_req->request_type;
    bool8 result;

    int ret = g_dms.callback.get_opengauss_txn_status(process_ctx->db_handle, xid, req_type, &result);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_STATUS_FAILED, ret);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
        return;
    }

    MES_INIT_MESSAGE_HEAD(&ack_head, MSG_ACK_OPENGAUSS_TXN_STATUS, 0, req_head->dst_inst, req_head->src_inst,
        process_ctx->sess_id, req_head->src_sid);
    ack_head.size = (uint16)(sizeof(uint64) + sizeof(mes_message_head_t));
    ack_head.rsn = req_head->rsn;

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data2(&ack_head, &result) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss txn status ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

int dms_request_opengauss_update_xid(dms_context_t *dms_ctx, unsigned short t_infomask,
    unsigned short t_infomask2, unsigned long long *uxid)
{
    msg_opengauss_update_xid_request_t uxid_req;
    mes_message_head_t *head = &uxid_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    uxid_req.xid = xid_ctx->xid;
    uxid_req.t_infomask = t_infomask;
    uxid_req.t_infomask2 = t_infomask2;

    head->size = (uint16)sizeof(msg_opengauss_update_xid_request_t);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, head->rsn, (uint32)ret);
        return ret;
    }

    ret = mfc_allocbuf_and_recv_data(dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, head->rsn, (uint32)ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RECV_MSG_SIZE(&receive_msg, (uint32)(sizeof(mes_message_head_t) + sizeof(uint64)), CM_TRUE, CM_FALSE);
    *uxid = *(uint64 *)(receive_msg.buffer + sizeof(mes_message_head_t));
    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_update_xid_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    mes_message_head_t *req_head = receive_msg->head;
    mes_message_head_t ack_head;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_update_xid_request_t), CM_TRUE, CM_TRUE);
    msg_opengauss_update_xid_request_t *uxid_req = (msg_opengauss_update_xid_request_t *)(receive_msg->buffer);

    uint64 uxid;
    uint64 xid = uxid_req->xid;
    uint16 t_infomask = uxid_req->t_infomask;
    uint16 t_infomask2 = uxid_req->t_infomask2;

    int ret = g_dms.callback.get_opengauss_update_xid(process_ctx->db_handle, xid, t_infomask, t_infomask2, &uxid);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_UPDATE_XID_FAILED, ret);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
        return;
    }

    MES_INIT_MESSAGE_HEAD(&ack_head, MSG_ACK_OPENGAUSS_TXN_UPDATE_XID, 0, req_head->dst_inst, req_head->src_inst,
        process_ctx->sess_id, req_head->src_sid);
    ack_head.size = (uint16)(sizeof(uint64) + sizeof(mes_message_head_t));
    ack_head.rsn = req_head->rsn;

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data2(&ack_head, &uxid) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss txn update xid ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

int dms_request_opengauss_xid_csn(dms_context_t *dms_ctx, dms_opengauss_xid_csn_t *dms_txn_info,
    dms_opengauss_csn_result_t *xid_csn_result)
{
    msg_opengauss_xid_csn_request_t xid_csn_req;
    mes_message_head_t *head = &xid_csn_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_XID_CSN, 0, (uint8)dms_ctx->inst_id, (uint8)xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    xid_csn_req.xid_csn_ctx = *dms_txn_info;
    head->size = (uint16)sizeof(msg_opengauss_xid_csn_request_t);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] send message to instance(%hhu) failed, cmd(%d) rsn(%u) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_XID_CSN, head->rsn, ret);
        return ret;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%hhu) failed, cmd(%d) rsn(%u) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_XID_CSN, head->rsn, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RECV_MSG_SIZE(&receive_msg,
        (uint32)(sizeof(mes_message_head_t) + sizeof(dms_opengauss_csn_result_t)), CM_TRUE, CM_FALSE);
    errno_t err = memcpy_s(xid_csn_result, sizeof(dms_opengauss_csn_result_t),
        (receive_msg.buffer + sizeof(mes_message_head_t)), sizeof(dms_opengauss_csn_result_t));
    if (err != EOK) {
        mfc_release_message_buf(&receive_msg);
        LOG_DEBUG_ERR("[TXN] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_xid_csn_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    mes_message_head_t *req_head = receive_msg->head;
    mes_message_head_t ack_head;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_xid_csn_request_t), CM_TRUE, CM_TRUE);
    msg_opengauss_xid_csn_request_t *xid_csn_req = (msg_opengauss_xid_csn_request_t *)(receive_msg->buffer);
    dms_opengauss_xid_csn_t xid_csn = xid_csn_req->xid_csn_ctx;
    dms_opengauss_csn_result_t csn_result = { 0 };

    int ret = g_dms.callback.get_opengauss_xid_csn(process_ctx->db_handle, &xid_csn, &csn_result);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_XID_CSN_FAILED, ret);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
        return;
    }

    MES_INIT_MESSAGE_HEAD(&ack_head, MSG_ACK_OPENGAUSS_XID_CSN, 0, req_head->dst_inst, req_head->src_inst,
        process_ctx->sess_id, req_head->src_sid);
    ack_head.size = (uint16)(sizeof(dms_opengauss_xid_csn_t) + sizeof(mes_message_head_t));
    ack_head.rsn = req_head->rsn;

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data2(&ack_head, &csn_result) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss xid csn ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

void dcs_proc_txn_info_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    mes_message_head_t *req_head = receive_msg->head;
    mes_message_head_t ack_head;
    dms_txn_info_t txn_info = { 0 };

    uint32 total_size = (uint32)(sizeof(mes_message_head_t) + sizeof(uint64) + sizeof(bool32));
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE, CM_FALSE);
    uint64 xid = *(uint64 *)(receive_msg->buffer + sizeof(mes_message_head_t));
    bool32 is_scan = *(bool32 *)(receive_msg->buffer + sizeof(mes_message_head_t) + sizeof(uint64));

    int ret = g_dms.callback.get_txn_info(process_ctx->db_handle, xid, (bool8)is_scan, &txn_info);
    if (ret != DMS_SUCCESS) {
        /* need to response error message */
        mfc_release_message_buf(receive_msg);
        return;
    }

    MES_INIT_MESSAGE_HEAD(&ack_head, MSG_ACK_TXN_INFO, 0, req_head->dst_inst, req_head->src_inst, process_ctx->sess_id,
        req_head->src_sid);
    ack_head.size = (uint16)(sizeof(dms_txn_info_t) + sizeof(mes_message_head_t));
    ack_head.rsn = req_head->rsn;

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data2(&ack_head, &txn_info) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send txn info ack message failed, src_inst = %u, dst_inst = %u", (uint32)ack_head.src_inst,
            (uint32)ack_head.dst_inst);
    }
#endif
}

int dms_request_txn_info(dms_context_t *dms_ctx, dms_txn_info_t *dms_txn_info)
{
    msg_txn_info_request_t txn_info_req;
    mes_message_head_t *head = &txn_info_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_TXN_INFO, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_info_req.xid = xid_ctx->xid;
    txn_info_req.is_scan = xid_ctx->is_scan;
    head->size = (uint16)sizeof(txn_info_req);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_TXN_INFO, xid_ctx->inst_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RECV_MSG_SIZE(&receive_msg,
        (uint32)(sizeof(mes_message_head_t) + sizeof(dms_txn_info_t)), CM_TRUE, CM_FALSE);
    errno_t err = memcpy_s(dms_txn_info, sizeof(dms_txn_info_t),
        (receive_msg.buffer + sizeof(mes_message_head_t)), sizeof(dms_txn_info_t));
    if (err != EOK) {
        mfc_release_message_buf(&receive_msg);
        LOG_DEBUG_ERR("[TXN] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_txn_snapshot_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    mes_message_head_t ack;
    dms_opengauss_txn_snapshot_t txn_snapshot;
    int32 ret = g_dms.callback.get_opengauss_txn_snapshot(process_ctx->db_handle, &txn_snapshot);
    if (ret == DMS_SUCCESS) {
        MES_INIT_MESSAGE_HEAD(&ack, MSG_ACK_OPENGAUSS_TXN_SNAPSHOT, 0, receive_msg->head->dst_inst,
            receive_msg->head->src_inst, process_ctx->sess_id, receive_msg->head->src_sid);
        ack.rsn = receive_msg->head->rsn;
        ack.size = (uint16)(sizeof(mes_message_head_t) + sizeof(dms_opengauss_txn_snapshot_t));
        mfc_release_message_buf(receive_msg);
        (void)mfc_send_data2(&ack, &txn_snapshot);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
    }
}

void dcs_proc_txn_snapshot_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    mes_message_head_t ack;
    dms_txn_snapshot_t txn_snapshot;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_snapshot_t), CM_TRUE, CM_TRUE);
    msg_txn_snapshot_t *req = (msg_txn_snapshot_t *)receive_msg->buffer;
    uint32 xmap = req->xmap;
    int32 ret = g_dms.callback.get_txn_snapshot(process_ctx->db_handle, xmap, &txn_snapshot);
    if (ret == DMS_SUCCESS) {
        MES_INIT_MESSAGE_HEAD(&ack, MSG_ACK_TXN_SNAPSHOT, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
            process_ctx->sess_id, receive_msg->head->src_sid);
        ack.rsn = receive_msg->head->rsn;
        ack.size = (uint16)(sizeof(mes_message_head_t) + sizeof(dms_txn_snapshot_t));
        mfc_release_message_buf(receive_msg);
        (void)mfc_send_data2(&ack, &txn_snapshot);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
    }
#endif
}

int dms_request_opengauss_txn_snapshot(dms_context_t *dms_ctx, dms_opengauss_txn_snapshot_t *dms_txn_snapshot)
{
    mes_message_t message;
    msg_opengauss_txn_snapshot_t req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;

    MES_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
    req.head.size = (uint16)sizeof(msg_opengauss_txn_snapshot_t);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_SNAPSHOT, CM_TRUE);

    int32 ret = mfc_send_data(&req.head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN][request openGauss txn snapshot failed] src_inst %u src_sid %u dst_inst %u",
            dms_ctx->inst_id, dms_ctx->sess_id, xmap_ctx->dest_id);
        return ret;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)", xmap_ctx->dest_id,
            (uint32)MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, req.head.rsn, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    if (message.head->cmd == MSG_ACK_OPENGAUSS_TXN_SNAPSHOT) {
        uint32 total_size = (uint32)(sizeof(mes_message_head_t) + sizeof(dms_opengauss_txn_snapshot_t));
        CM_CHK_RECV_MSG_SIZE(&message, total_size, CM_TRUE, CM_FALSE);
        *dms_txn_snapshot = *(dms_opengauss_txn_snapshot_t *)(message.buffer + sizeof(mes_message_head_t));
        mfc_release_message_buf(&message);
        return DMS_SUCCESS;
    } else {
        mfc_release_message_buf(&message);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED);
        return ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED;
    }
}

int dms_request_txn_snapshot(dms_context_t *dms_ctx, dms_txn_snapshot_t *dms_txn_snapshot)
{
    mes_message_t message;
    msg_txn_snapshot_t req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;

    MES_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_TXN_SNAPSHOT, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
    req.head.size = (uint16)sizeof(msg_txn_snapshot_t);
    req.xmap = xmap_ctx->xmap;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_SNAPSHOT, CM_TRUE);

    int32 ret = mfc_send_data(&req.head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN][request txn snapshot failed] src_inst %u src_sid %u dst_inst %u",
            dms_ctx->inst_id, dms_ctx->sess_id, xmap_ctx->dest_id);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_TXN_SNAPSHOT, xmap_ctx->dest_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)", xmap_ctx->dest_id,
            (uint32)MSG_REQ_TXN_SNAPSHOT, req.head.rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    dms_end_stat(dms_ctx->sess_id);

    if (message.head->cmd == MSG_ACK_TXN_SNAPSHOT) {
        CM_CHK_RECV_MSG_SIZE(&message,
            (uint32)(sizeof(mes_message_head_t) + sizeof(dms_txn_snapshot_t)), CM_TRUE, CM_FALSE);
        *dms_txn_snapshot = *(dms_txn_snapshot_t *)(message.buffer + sizeof(mes_message_head_t));
        mfc_release_message_buf(&message);
        if (dms_txn_snapshot->status == DMS_XACT_END) {
            g_dms.callback.update_global_scn(dms_ctx->db_handle, dms_txn_snapshot->scn);
        }
        return DMS_SUCCESS;
    } else {
        mfc_release_message_buf(&message);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED);
        return ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED;
    }
}

void dcs_proc_txn_wait_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    mfc_release_message_buf(receive_msg);
#else
    msg_txn_wait_ack_t txn_wait_ack;

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_wait_request_t), CM_TRUE, CM_TRUE);
    msg_txn_wait_request_t *txn_wait_req = (msg_txn_wait_request_t *)(receive_msg->buffer);
    uint64 xid = txn_wait_req->xid;
    uint64 scn = 0;
    dms_txn_info_t txn_info;
    int ret;

    (void)g_dms.callback.get_txn_info(process_ctx->db_handle, xid, CM_FALSE, &txn_info);
    if (txn_info.status == DMS_XACT_END) {
        ret = DMS_REMOTE_TXN_END;
        scn = txn_info.scn;
    } else {
        drc_enqueue_txn(&xid, receive_msg->head->src_inst);
        ret = DMS_REMOTE_TXN_WAIT;
    }

    MES_INIT_MESSAGE_HEAD(&txn_wait_ack.head, MSG_ACK_AWAKE_TXN, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, process_ctx->sess_id, receive_msg->head->src_sid);
    txn_wait_ack.head.size = (uint16)sizeof(msg_txn_wait_ack_t);
    txn_wait_ack.head.rsn = receive_msg->head->rsn;
    txn_wait_ack.status = ret;
    txn_wait_ack.scn = scn;
    mfc_release_message_buf(receive_msg);

    if (mfc_send_data(&txn_wait_ack.head) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send txn info ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)txn_wait_ack.head.src_inst, (uint32)txn_wait_ack.head.dst_inst);
    }
#endif
}

void dcs_proc_txn_awake_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
#ifndef OPENGAUSS
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_awake_request_t), CM_TRUE, CM_FALSE);
    // machines are the same endian, if they are different, we need to adapt it.
    msg_txn_awake_request_t *txn_awake_req = (msg_txn_awake_request_t *)(receive_msg->buffer);
    uint64 xid = txn_awake_req->xid;
    uint64 scn = txn_awake_req->scn;

    drc_local_txn_awake(&xid);
    g_dms.callback.update_global_scn(process_ctx->db_handle, scn);
#endif
    mfc_release_message_buf(receive_msg);
    // there is no ack msg.
}

static int32 dms_send_awake_txn_msg(dms_context_t *dms_ctx, uint32 dest_id)
{
    msg_txn_awake_request_t txn_awake_req;
    mes_message_head_t *head = &txn_awake_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_AWAKE_TXN, 0, dms_ctx->inst_id, dest_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_awake_req.xid = xid_ctx->xid;
    txn_awake_req.scn = xid_ctx->scn;
    head->size = (uint16)sizeof(msg_txn_awake_request_t);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_AWAKE_TXN, head->rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, head->cmd, head->dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return DMS_SUCCESS;
}

void dms_release_txn_cond(dms_context_t *dms_ctx)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->txn_res_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;
    uint64 xid = dms_ctx->xid_ctx.xid;

    bucket = drc_res_map_get_bucket(res_map, (char *)&xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)&xid, sizeof(uint64));
    if (txn_res == NULL) {
        cm_spin_unlock(&bucket->lock);
        return;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&txn_res->inst_map, i)) {
            if (i == g_dms.inst_id) {
                continue; // self instance
            }
            (void)dms_send_awake_txn_msg(dms_ctx, i);
        }
    }

    drc_res_map_del_res(res_map, bucket, (char *)&xid, sizeof(uint64));
    drc_release_txn_res(txn_res);
    cm_spin_unlock(&bucket->lock);
}

void dms_recycle_txn_cond(dms_context_t *dms_ctx)
{
    uint64 *xid = &dms_ctx->xid_ctx.xid;
    drc_local_txn_recycle(xid);
}

int dms_request_txn_cond_status(dms_context_t *dms_ctx, int *status)
{
    msg_txn_wait_request_t txn_wait_req;
    mes_message_head_t *head = &txn_wait_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    mes_message_t receive_msg = { 0 };

    MES_INIT_MESSAGE_HEAD(head, MSG_REQ_WAIT_TXN, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_wait_req.xid = xid_ctx->xid;
    head->size = (uint16)sizeof(txn_wait_req);
    head->rsn = mfc_get_rsn(dms_ctx->sess_id);

    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_WAIT_TXN, head->rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_WAIT_TXN, xid_ctx->inst_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) rsn(%u) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->rsn, ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_WAIT_TXN, xid_ctx->inst_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    CM_CHK_RECV_MSG_SIZE(&receive_msg, (uint32)sizeof(msg_txn_wait_ack_t), CM_TRUE, CM_FALSE);
    msg_txn_wait_ack_t *ack = (msg_txn_wait_ack_t *)(receive_msg.buffer);
    *status = ack->status;
    if (*status == DMS_REMOTE_TXN_END) {
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
    }

    mfc_release_message_buf(&receive_msg);
    return DMS_SUCCESS;
}

unsigned char dms_wait_txn_cond(dms_context_t *dms_ctx)
{
    uint64 *xid = &dms_ctx->xid_ctx.xid;
    return drc_local_txn_wait(xid);
}

