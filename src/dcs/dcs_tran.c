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
#include "dms_msg_command.h"
#include "dms_msg_protocol.h"
#include "drc.h"
#include "drc_tran.h"
#include "dms_stat.h"
#include "dms_error.h"

int dms_request_opengauss_txn_status(dms_context_t *dms_ctx, unsigned char request, unsigned char *result)
{
    dms_reset_error();
    msg_opengauss_txn_status_request_t status_req;
    dms_message_head_t *head = &status_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_TXN_STATUS, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    status_req.xid = xid_ctx->xid;
    status_req.request_type = request;

    head->size = (uint16)sizeof(msg_opengauss_txn_status_request_t);

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);
    
    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_STATUS, head->ruid, (uint32)ret);
        return ret;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_STATUS, head->ruid, (uint32)ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&receive_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(bool8)), CM_FALSE);
    *result = *(bool8 *)(receive_msg.buffer + sizeof(dms_message_head_t));
    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_txn_status_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_txn_status_request_t), CM_TRUE);
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

    dms_init_ack_head2(&ack_head, MSG_ACK_OPENGAUSS_TXN_STATUS, 0, req_head->dst_inst, req_head->src_inst,
        (uint16)process_ctx->sess_id, req_head->src_sid, req_head->msg_proto_ver);
    ack_head.size = (uint16)(sizeof(uint64) + sizeof(dms_message_head_t));
    ack_head.ruid = req_head->ruid;

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &result) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss txn status ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

int dms_request_opengauss_update_xid(dms_context_t *dms_ctx, unsigned short t_infomask,
    unsigned short t_infomask2, unsigned long long *uxid)
{
    dms_reset_error();
    msg_opengauss_update_xid_request_t uxid_req;
    dms_message_head_t *head = &uxid_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    uxid_req.xid = xid_ctx->xid;
    uxid_req.t_infomask = t_infomask;
    uxid_req.t_infomask2 = t_infomask2;

    head->size = (uint16)sizeof(msg_opengauss_update_xid_request_t);

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, head->ruid, (uint32)ret);
        return ret;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, head->ruid, (uint32)ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&receive_msg, (uint32)(sizeof(dms_message_head_t) + sizeof(uint64)), CM_FALSE);
    *uxid = *(uint64 *)(receive_msg.buffer + sizeof(dms_message_head_t));
    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_update_xid_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_update_xid_request_t), CM_TRUE);
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

    dms_init_ack_head2(&ack_head, MSG_ACK_OPENGAUSS_TXN_UPDATE_XID, 0, req_head->dst_inst, req_head->src_inst,
        (uint16)process_ctx->sess_id, req_head->src_sid, req_head->msg_proto_ver);
    ack_head.size = (uint16)(sizeof(uint64) + sizeof(dms_message_head_t));
    ack_head.ruid = req_head->ruid;

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &uxid) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss txn update xid ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

int dms_request_opengauss_xid_csn(dms_context_t *dms_ctx, dms_opengauss_xid_csn_t *dms_txn_info,
    dms_opengauss_csn_result_t *xid_csn_result)
{
    dms_reset_error();
    msg_opengauss_xid_csn_request_t xid_csn_req;
    dms_message_head_t *head = &xid_csn_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_XID_CSN, 0, (uint8)dms_ctx->inst_id, (uint8)xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    xid_csn_req.xid_csn_ctx = *dms_txn_info;
    head->size = (uint16)sizeof(msg_opengauss_xid_csn_request_t);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] send message to instance(%hhu) failed, cmd(%d) ruid(%llu) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_XID_CSN, head->ruid, ret);
        return ret;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%hhu) failed, cmd(%d) ruid(%llu) errcode(%d)",
            xid_ctx->inst_id, MSG_REQ_OPENGAUSS_XID_CSN, head->ruid, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&receive_msg,
        (uint32)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_csn_result_t)), CM_FALSE);
    errno_t err = memcpy_s(xid_csn_result, sizeof(dms_opengauss_csn_result_t),
        (receive_msg.buffer + sizeof(dms_message_head_t)), sizeof(dms_opengauss_csn_result_t));
    if (err != EOK) {
        mfc_release_response(&receive_msg);
        LOG_DEBUG_ERR("[TXN] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_xid_csn_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_xid_csn_request_t), CM_TRUE);
    msg_opengauss_xid_csn_request_t *xid_csn_req = (msg_opengauss_xid_csn_request_t *)(receive_msg->buffer);
    dms_opengauss_xid_csn_t xid_csn = xid_csn_req->xid_csn_ctx;
    dms_opengauss_csn_result_t csn_result = { 0 };

    int ret = g_dms.callback.get_opengauss_xid_csn(process_ctx->db_handle, &xid_csn, &csn_result);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_XID_CSN_FAILED, ret);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
        return;
    }

    dms_init_ack_head2(&ack_head, MSG_ACK_OPENGAUSS_XID_CSN, 0, req_head->dst_inst, req_head->src_inst,
        (uint16)process_ctx->sess_id, req_head->src_sid, req_head->msg_proto_ver);
    ack_head.size = (uint16)(sizeof(dms_opengauss_xid_csn_t) + sizeof(dms_message_head_t));
    ack_head.ruid = req_head->ruid;

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &csn_result) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send openGauss xid csn ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

void dcs_proc_txn_info_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
#else
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;
    dms_txn_info_t txn_info = { 0 };

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint64) + sizeof(bool32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    uint64 xid = *(uint64 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    bool32 is_scan = *(bool32 *)(receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint64));

    int ret = g_dms.callback.get_txn_info(process_ctx->db_handle, xid, (bool8)is_scan, &txn_info);
    if (ret != DMS_SUCCESS) {
        /* need to response error message */
        return;
    }

    dms_init_ack_head2(&ack_head, MSG_ACK_TXN_INFO, 0, req_head->dst_inst, req_head->src_inst,
        (uint16)process_ctx->sess_id, req_head->src_sid, req_head->msg_proto_ver);
    ack_head.size = (uint16)(sizeof(dms_txn_info_t) + sizeof(dms_message_head_t));
    ack_head.ruid = req_head->ruid;

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &txn_info) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send txn info ack message failed, src_inst = %u, dst_inst = %u", 
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
#endif
}

int dms_request_txn_info(dms_context_t *dms_ctx, dms_txn_info_t *dms_txn_info)
{
    dms_reset_error();
    msg_txn_info_request_t txn_info_req;
    dms_message_head_t *head = &txn_info_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_TXN_INFO, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_info_req.xid = xid_ctx->xid;
    txn_info_req.is_scan = xid_ctx->is_scan;
    head->size = (uint16)sizeof(txn_info_req);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->ruid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_TXN_INFO, xid_ctx->inst_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->ruid, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&receive_msg,
        (uint32)(sizeof(dms_message_head_t) + sizeof(dms_txn_info_t)), CM_FALSE);
    errno_t err = memcpy_s(dms_txn_info, sizeof(dms_txn_info_t),
        (receive_msg.buffer + sizeof(dms_message_head_t)), sizeof(dms_txn_info_t));
    if (err != EOK) {
        LOG_DEBUG_ERR("[TXN] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        mfc_release_response(&receive_msg);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_txn_snapshot_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t ack;
    dms_opengauss_txn_snapshot_t txn_snapshot = { 0 };

    uint8 src_inst = receive_msg->head->src_inst;
    int32 ret = g_dms.callback.get_opengauss_txn_snapshot(process_ctx->db_handle, &txn_snapshot, src_inst);
    if (ret == DMS_SUCCESS) {
        dms_init_ack_head2(&ack, MSG_ACK_OPENGAUSS_TXN_SNAPSHOT, 0, receive_msg->head->dst_inst,
            receive_msg->head->src_inst, (uint16)process_ctx->sess_id, receive_msg->head->src_sid,
            receive_msg->head->msg_proto_ver);
        ack.ruid = receive_msg->head->ruid;
        ack.size = (uint16)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_txn_snapshot_t));
        (void)mfc_send_data3(&ack, sizeof(dms_message_head_t), &txn_snapshot);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
    }
}

void dcs_proc_opengauss_txn_of_master_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    dms_opengauss_txn_sw_info_t dms_swinfo = { 0 };

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    dms_swinfo.server_proc_slot = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));

    dms_message_head_t ack;
    int32 ret = g_dms.callback.get_opengauss_txn_of_master(process_ctx->db_handle, &dms_swinfo);
    if (ret == DMS_SUCCESS) {
        dms_init_ack_head2(&ack, MSG_ACK_OPENGAUSS_TXN_SWINFO, 0, receive_msg->head->dst_inst,
            receive_msg->head->src_inst, (uint16)process_ctx->sess_id, receive_msg->head->src_sid,
            receive_msg->head->msg_proto_ver);
        ack.ruid = receive_msg->head->ruid;
        ack.size = (uint16)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_txn_sw_info_t));
        (void)mfc_send_data3(&ack, sizeof(dms_message_head_t), &dms_swinfo);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
    }
#endif
}

void dcs_proc_txn_snapshot_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
#else
    dms_message_head_t ack;
    dms_txn_snapshot_t txn_snapshot = { 0 };

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_snapshot_t), CM_TRUE);
    msg_txn_snapshot_t *req = (msg_txn_snapshot_t *)receive_msg->buffer;
    uint32 xmap = req->xmap;
    int32 ret = g_dms.callback.get_txn_snapshot(process_ctx->db_handle, xmap, &txn_snapshot);
    if (ret == DMS_SUCCESS) {
        dms_init_ack_head2(&ack, MSG_ACK_TXN_SNAPSHOT, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
            (uint16)process_ctx->sess_id, (uint16)receive_msg->head->src_sid, req->head.msg_proto_ver);
        ack.ruid = receive_msg->head->ruid;
        ack.size = (uint16)(sizeof(dms_message_head_t) + sizeof(dms_txn_snapshot_t));
        (void)mfc_send_data3(&ack, sizeof(dms_message_head_t), &txn_snapshot);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
    }
#endif
}

int dms_request_opengauss_txn_snapshot(dms_context_t *dms_ctx, dms_opengauss_txn_snapshot_t *dms_txn_snapshot)
{
    dms_reset_error();
    dms_message_t dms_msg = { 0 };
    msg_opengauss_txn_snapshot_t req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(msg_opengauss_txn_snapshot_t);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_SNAPSHOT, CM_TRUE);

    
    int32 ret = mfc_send_data(&req.head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN][request openGauss txn snapshot failed] src_inst %u src_sid %u dst_inst %u",
            dms_ctx->inst_id, dms_ctx->sess_id, xmap_ctx->dest_id);
        return ret;
    }

    ret = mfc_get_response(req.head.ruid, &dms_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)", xmap_ctx->dest_id,
            (uint32)MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, req.head.ruid, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    if (dms_msg.head->cmd == MSG_ACK_OPENGAUSS_TXN_SNAPSHOT) {
        uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_txn_snapshot_t));
        CM_CHK_RESPONSE_SIZE(&dms_msg, total_size, CM_FALSE);
        *dms_txn_snapshot = *(dms_opengauss_txn_snapshot_t *)(dms_msg.buffer + sizeof(dms_message_head_t));
        mfc_release_response(&dms_msg);
        return DMS_SUCCESS;
    } else {
        mfc_release_response(&dms_msg);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED);
        return ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED;
    }
}

int dms_request_opengauss_txn_of_master(dms_context_t *dms_ctx, dms_opengauss_txn_sw_info_t *dms_txn_swinfo)
{
    dms_reset_error();
    dms_message_t dms_msg = { 0 };
    msg_opengauss_txn_swinfo_t req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_OPENGAUSS_TXN_SWINFO, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.proc_slot = dms_txn_swinfo->server_proc_slot;
    req.head.size = (uint16)sizeof(msg_opengauss_txn_swinfo_t);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_TXN_REQ_INFO, CM_TRUE);

    
    int32 ret = mfc_send_data(&req.head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN][request openGauss txn swinfo failed] src_inst %u src_sid %u dst_inst %u",
            dms_ctx->inst_id, dms_ctx->sess_id, xmap_ctx->dest_id);
        return ret;
    }

    ret = mfc_get_response(req.head.ruid, &dms_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)", xmap_ctx->dest_id,
            (uint32)MSG_REQ_OPENGAUSS_TXN_SWINFO, req.head.ruid, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    if (dms_msg.head->cmd == MSG_ACK_OPENGAUSS_TXN_SWINFO) {
        uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_txn_sw_info_t));
        CM_CHK_RESPONSE_SIZE(&dms_msg, total_size, CM_FALSE);
        dms_opengauss_txn_sw_info_t received_swinfo = *(dms_opengauss_txn_sw_info_t *)(dms_msg.buffer + sizeof(dms_message_head_t));
        dms_txn_swinfo->sxid = received_swinfo.sxid;
        dms_txn_swinfo->scid = received_swinfo.scid;
        mfc_release_response(&dms_msg);
        return DMS_SUCCESS;
    } else {
        mfc_release_response(&dms_msg);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_INFO_FAILED);
        return ERRNO_DMS_DCS_GET_TXN_INFO_FAILED;
    }
}

int dms_request_txn_snapshot(dms_context_t *dms_ctx, dms_txn_snapshot_t *dms_txn_snapshot)
{
    dms_reset_error();
    dms_message_t message;
    msg_txn_snapshot_t req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_TXN_SNAPSHOT, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
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

    ret = mfc_get_response(req.head.ruid, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)", xmap_ctx->dest_id,
            (uint32)MSG_REQ_TXN_SNAPSHOT, req.head.ruid, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    dms_end_stat(dms_ctx->sess_id);

    dms_message_head_t *ack_dms_head = get_dms_head(&message);
    if (ack_dms_head->cmd == MSG_ACK_TXN_SNAPSHOT) {
        CM_CHK_RESPONSE_SIZE((dms_message_t *)&message.buffer,
            (uint32)(sizeof(dms_message_head_t) + sizeof(dms_txn_snapshot_t)), CM_FALSE);
        *dms_txn_snapshot = *(dms_txn_snapshot_t *)(message.buffer + sizeof(dms_message_head_t));
        if (dms_txn_snapshot->status == DMS_XACT_END) {
            g_dms.callback.update_global_scn(dms_ctx->db_handle, dms_txn_snapshot->scn);
        }
        mfc_release_response(&message);
        return DMS_SUCCESS;
    } else {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED);
        mfc_release_response(&message);
        return ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED;
    }
}

void dcs_proc_txn_wait_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
#else
    msg_txn_wait_ack_t txn_wait_ack;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_wait_request_t), CM_TRUE);
    msg_txn_wait_request_t *txn_wait_req = (msg_txn_wait_request_t *)(receive_msg->buffer);
    uint64 xid = txn_wait_req->xid;
    uint64 scn = 0;
    dms_txn_info_t txn_info;
    int ret = g_dms.callback.get_txn_info(process_ctx->db_handle, xid, CM_FALSE, &txn_info);
    if (ret != DMS_SUCCESS) {
        return;
    }

    if (txn_info.status == DMS_XACT_END) {
        ret = DMS_REMOTE_TXN_END;
        scn = txn_info.scn;
    } else {
        drc_enqueue_txn(&xid, receive_msg->head->src_inst);
        ret = DMS_REMOTE_TXN_WAIT;
    }

    dms_init_ack_head2(&txn_wait_ack.head, MSG_ACK_AWAKE_TXN, 0, receive_msg->head->dst_inst,
        receive_msg->head->src_inst, (uint16)process_ctx->sess_id, receive_msg->head->src_sid,
        receive_msg->head->msg_proto_ver);
    txn_wait_ack.head.size = (uint16)sizeof(msg_txn_wait_ack_t);
    txn_wait_ack.head.ruid = receive_msg->head->ruid;
    txn_wait_ack.status = ret;
    txn_wait_ack.scn = scn;

    if (mfc_send_data(&txn_wait_ack.head) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send txn info ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)txn_wait_ack.head.src_inst, (uint32)txn_wait_ack.head.dst_inst);
    }
#endif
}

void dcs_proc_txn_awake_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifndef OPENGAUSS
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_txn_awake_request_t), CM_FALSE);
    // machines are the same endian, if they are different, we need to adapt it.
    msg_txn_awake_request_t *txn_awake_req = (msg_txn_awake_request_t *)(receive_msg->buffer);
    uint64 xid = txn_awake_req->xid;
    uint64 scn = txn_awake_req->scn;

    g_dms.callback.update_global_scn(process_ctx->db_handle, scn);
    drc_local_txn_awake(&xid);
#endif
    // there is no ack msg.
}

static int32 dms_send_awake_txn_msg(dms_context_t *dms_ctx, uint32 dest_id)
{
    msg_txn_awake_request_t txn_awake_req;
    dms_message_head_t *head = &txn_awake_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_AWAKE_TXN, 0, dms_ctx->inst_id, dest_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_awake_req.xid = xid_ctx->xid;
    txn_awake_req.scn = xid_ctx->scn;
    head->size = (uint16)sizeof(msg_txn_awake_request_t);

    int32 ret = mfc_send_data_async(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_AWAKE_TXN, head->ruid, ret);
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

    for (uint8 i = 0; i < g_dms.inst_cnt; i++) {
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
    dms_reset_error();
    msg_txn_wait_request_t txn_wait_req;
    dms_message_head_t *head = &txn_wait_req.head;
    dms_xid_ctx_t *xid_ctx = &dms_ctx->xid_ctx;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_WAIT_TXN, 0, dms_ctx->inst_id, xid_ctx->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    txn_wait_req.xid = xid_ctx->xid;
    head->size = (uint16)sizeof(txn_wait_req);

    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_WAIT_TXN, head->ruid, ret);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_WAIT_TXN, xid_ctx->inst_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[TXN] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            (uint32)xid_ctx->inst_id, (uint32)MSG_REQ_TXN_INFO, head->ruid, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_WAIT_TXN, xid_ctx->inst_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    CM_CHK_RESPONSE_SIZE(&receive_msg, (uint32)sizeof(msg_txn_wait_ack_t), CM_FALSE);
    msg_txn_wait_ack_t *ack = (msg_txn_wait_ack_t *)(receive_msg.buffer);
    *status = ack->status;
    if (*status == DMS_REMOTE_TXN_END) {
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
    }

    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

unsigned char dms_wait_txn_cond(dms_context_t *dms_ctx)
{
    dms_reset_error();
    uint64 *xid = &dms_ctx->xid_ctx.xid;
    return drc_local_txn_wait(xid);
}

int dms_request_opengauss_page_status(dms_context_t *dms_ctx, unsigned int page, int page_num,
    unsigned long int *page_map, int *bit_count)
{
    dms_reset_error();
    msg_opengauss_page_status_request_t status_req;
    dms_message_head_t *head = &status_req.head;
    dms_rfn_t *node = &dms_ctx->rfn;
    dms_message_t receive_msg = { 0 };

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_OPENGAUSS_PAGE_STATUS, 0, dms_ctx->inst_id, node->inst_id,
        (uint16)dms_ctx->sess_id, CM_INVALID_ID16);
    status_req.rnode = node->rnode;
    status_req.page = page;
    status_req.page_num = page_num;
    status_req.bit_count = *bit_count;
    errno_t err = memcpy_s(status_req.page_map, sizeof(status_req.page_map), page_map, sizeof(status_req.page_map));
    if (err != EOK) {
        LOG_DEBUG_ERR("[PAGE] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    head->size = (uint16)sizeof(msg_opengauss_page_status_request_t);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_PAGE_STATUS_INFO, CM_TRUE);

    
    int32 ret = mfc_send_data(head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[PAGE] send message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)node->inst_id, (uint32)MSG_REQ_OPENGAUSS_PAGE_STATUS, head->ruid, (uint32)ret);
        return ret;
    }

    ret = mfc_get_response(head->ruid, &receive_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[PAGE] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%u)",
            (uint32)node->inst_id, (uint32)MSG_REQ_OPENGAUSS_PAGE_STATUS, head->ruid, (uint32)ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&receive_msg,
        (uint32)(sizeof(dms_message_head_t) + sizeof(dms_opengauss_page_status_result_t)), CM_FALSE);
    dms_opengauss_page_status_result_t status_result;
    err = memcpy_s(&status_result, sizeof(dms_opengauss_page_status_result_t),
        (receive_msg.buffer + sizeof(dms_message_head_t)), sizeof(dms_opengauss_page_status_result_t));
    if (err != EOK) {
        LOG_DEBUG_ERR("[PAGE] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        mfc_release_response(&receive_msg);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }
    *bit_count = status_result.bit_count;
    err = memcpy_s(page_map, sizeof(status_result.page_map), status_result.page_map, sizeof(status_result.page_map));
    if (err != EOK) {
        LOG_DEBUG_ERR("[PAGE] memcpy_s failed, errno = %d", err);
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        mfc_release_response(&receive_msg);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }
    mfc_release_response(&receive_msg);
    return DMS_SUCCESS;
}

void dcs_proc_opengauss_page_status_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_opengauss_page_status_request_t), CM_TRUE);
    msg_opengauss_page_status_request_t *status_req = (msg_opengauss_page_status_request_t *)(receive_msg->buffer);
    dms_opengauss_page_status_result_t page_result = { 0 };

    unsigned int page = status_req->page;
    dms_opengauss_relfilenode_t *rnode = &status_req->rnode;
    int page_num = status_req->page_num;
    page_result.bit_count = status_req->bit_count;
    errno_t err = memcpy_s(page_result.page_map, sizeof(page_result.page_map), status_req->page_map,
        sizeof(page_result.page_map));
    if (err != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, DMS_ERROR);
        return;
    }

    int ret = g_dms.callback.get_opengauss_page_status(process_ctx->db_handle, rnode, page, page_num, &page_result);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_PAGE_IN_BUFFER_FAILED, ret);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_ERROR, ret);
        return;
    }

    dms_init_ack_head2(&ack_head, MSG_ACK_OPENGAUSS_PAGE_STATUS, 0, req_head->dst_inst, req_head->src_inst,
        (uint16)process_ctx->sess_id, req_head->src_sid, req_head->msg_proto_ver);
    ack_head.size = (uint16)(sizeof(dms_opengauss_page_status_result_t) + sizeof(dms_message_head_t));
    ack_head.ruid = req_head->ruid;

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &page_result) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[PAGE] send openGauss page status ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

int dms_send_opengauss_oldest_xmin(dms_context_t *dms_ctx, uint64 oldest_xmin, unsigned char dest_id)
{
    msg_send_opengauss_oldest_xmin_t send_msg;
    DMS_INIT_MESSAGE_HEAD(&send_msg.head, MSG_REQ_SEND_OPENGAUSS_OLDEST_XMIN, 0, dms_ctx->inst_id,
        dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    send_msg.head.size = sizeof(msg_send_opengauss_oldest_xmin_t);
    send_msg.oldest_xmin = oldest_xmin;
    int ret = CM_SUCCESS;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_OPENGAUSS_SEND_XMIN, CM_TRUE);
    ret = mfc_send_data(&send_msg.head);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_WAR("[OG XMIN] send openGauss oldest xmin failed, src_inst:%u, src_sid:%u, "
            "dst_inst:%u, ruid:%llu, oldest_xmin:%llu",
            send_msg.head.src_inst, send_msg.head.src_sid, send_msg.head.dst_inst, send_msg.head.ruid, oldest_xmin);
        return ret;
    }
    LOG_DEBUG_INF("[OG XMIN] send openGauss oldest xmin success, src_inst:%u, src_sid:%u, "
        "dst_inst:%u, ruid:%llu",
        send_msg.head.src_inst, send_msg.head.src_sid, send_msg.head.dst_inst, send_msg.head.ruid);

    dms_message_t ack_msg = { 0 };
    ret = mfc_get_response(send_msg.head.ruid, &ack_msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_WAR("[OG XMIN] wait receive openGauss oldest xmin ack failed, src_inst:%u, src_sid:%u, "
            "dst_inst:%u, ruid:%llu",
            send_msg.head.src_inst, send_msg.head.src_sid, send_msg.head.dst_inst, send_msg.head.ruid);
        return ret;
    }
    dms_end_stat(dms_ctx->sess_id);
    LOG_DEBUG_INF("[OG XMIN] receive openGauss oldest xmin ack success, src_inst:%u, src_sid:%u, "
        "dst_inst:%u, ruid:%llu",
        send_msg.head.src_inst, send_msg.head.src_sid, send_msg.head.dst_inst, send_msg.head.ruid);
    mfc_release_response(&ack_msg);
    return ret;
}

void dcs_proc_send_opengauss_oldest_xmin(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_send_opengauss_oldest_xmin_t), CM_TRUE);
    msg_send_opengauss_oldest_xmin_t recv_msg = *(msg_send_opengauss_oldest_xmin_t*)receive_msg->buffer;

    uint64 oldest_xmin = recv_msg.oldest_xmin;
    LOG_DEBUG_INF("[OG XMIN] receive openGauss oldest xmin, src_inst:%u, src_sid:%u, dst_inst:%u, ruid:%llu, "
        "oldest_xmin:%llu",
        recv_msg.head.src_inst, recv_msg.head.src_sid, recv_msg.head.dst_inst, recv_msg.head.ruid, oldest_xmin);
    g_dms.callback.update_node_oldest_xmin(process_ctx->db_handle, recv_msg.head.src_inst, oldest_xmin);

    dms_message_head_t ack_msg;
    dms_init_ack_head(&recv_msg.head, &ack_msg, MSG_ACK_SEND_OPENGAUSS_OLDEST_XMIN, sizeof(dms_message_head_t),
        process_ctx->sess_id);
    int ret = mfc_send_data(&ack_msg);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_WAR("[OG XMIN] send openGauss oldest xmin ack failed, src_inst:%u, src_sid:%u, dst_inst:%u, ruid:%llu",
            ack_msg.src_inst, ack_msg.src_sid, ack_msg.dst_inst, ack_msg.ruid);
        return;
    }
    LOG_DEBUG_INF("[OG XMIN] send openGauss oldest xmin ack success, src_inst:%u, src_sid:%u, dst_inst:%u, ruid:%llu",
        ack_msg.src_inst, ack_msg.src_sid, ack_msg.dst_inst, ack_msg.ruid);
}

static bool8 dms_proc_check_xid_valid(drc_global_xid_t *xid)
{
    if (xid->bqual_len > DMS_MAX_XA_BASE16_BQUAL_LEN || xid->gtrid_len > DMS_MAX_XA_BASE16_GTRID_LEN) {
        LOG_RUN_ERR("[DMS]: invalid global xa xid");
        return CM_FALSE;
    }

    text_t gtrid, bqual;
    cm_str2text_safe(xid->gtrid, xid->gtrid_len, &gtrid);
    cm_str2text_safe(xid->bqual, xid->bqual_len, &bqual);
    if (cm_chk_and_upper_base16(&gtrid) != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS][%s]: invalid global transaction ID", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return CM_FALSE;
    }

    if (cm_chk_and_upper_base16(&bqual) != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS][%s]: invalid global transaction branch ID", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return CM_FALSE;
    }

    return CM_TRUE;
}

int32 dms_request_create_xa_res(dms_context_t *dms_ctx, uint8 master_id, uint8 undo_set_id, uint32 *result_code)
{
    dms_xa_res_req_t req;
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES, CM_TRUE);
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_CREATE_GLOBAL_XA_RES, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_xa_res_req_t);
    req.oper_type = DMS_XA_OPER_CREATE;
    req.undo_set_id = undo_set_id;
    req.check_xa_drc = (bool32)dms_is_recovery_session(dms_ctx->sess_id);
    errno_t ret = memcpy_sp(&req.xa_xid, sizeof(drc_global_xid_t), &dms_ctx->global_xid, sizeof(drc_global_xid_t));
    if (ret != EOK) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_request_create_xa_res]: src_id = %u, dst_id = %u",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), dms_ctx->inst_id, (uint32)master_id);
    int32 ret_code = mfc_send_data(&req.head);
    if (ret_code != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_request_create_xa_res]: failed to send create xa res request",
            cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE));
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_CREATE_GLOBAL_XA_RES, master_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t recv_msg = { 0 };
    ret_code = mfc_get_response(req.head.ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret_code != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_request_create_xa_res]: wait master node ack timeout, timeout = %u ms",
            cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), DMS_WAIT_MAX_TIME);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_CREATE_GLOBAL_XA_RES, master_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    LOG_DEBUG_INF("[DMS][%s]: src_id = %u, src_sid = %u, dst_id = %u, dts_sid = %u, flag = %u, ruid = %llu",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), (uint32)recv_msg.head->src_inst,
        (uint32)recv_msg.head->src_sid, (uint32)recv_msg.head->dst_inst,
        (uint32)recv_msg.head->dst_sid, (uint32)recv_msg.head->flags, recv_msg.head->ruid);

    dms_xa_res_ack_t *result_msg = (dms_xa_res_ack_t *)recv_msg.buffer;
    *result_code = result_msg->return_code;
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
    mfc_release_response(&recv_msg);
    LOG_DEBUG_INF("[DMS][%s][dms_request_create_xa_res]: create xa res remote success, master_id = %u",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), (uint32)master_id);
    return DMS_SUCCESS;
}

void dms_proc_create_xa_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_xa_res_req_t), CM_TRUE);
    dms_xa_res_req_t req = *(dms_xa_res_req_t *)receive_msg->buffer;

    drc_global_xid_t *xid = &req.xa_xid;
    if (dms_proc_check_xid_valid(xid)) {
        return;
    }

    int32 ret = drc_create_xa_res(proc_ctx->db_handle, proc_ctx->sess_id, xid, req.head.src_inst, req.undo_set_id,
        req.check_xa_drc);
    dms_xa_res_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_CREATE_GLOBAL_XA_RES, sizeof(dms_xa_res_ack_t),
        proc_ctx->sess_id);
    ack.return_code = ret;

    ret = mfc_send_data(&ack.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_create_xa_res]: failed to send ack, dst_id = %u, dst_sid = %u, errcode = %d",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid, ret);
    } else {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_create_xa_res]: finished, dst_id = %u, dst_sid = %u",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid);
    }
}

int32 dms_request_delete_xa_res(dms_context_t *dms_ctx, uint8 master_id, uint32 *result_code)
{
    dms_xa_res_req_t req;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_DELETE_XA_RES, CM_TRUE);
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_DELETE_GLOBAL_XA_RES, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_xa_res_req_t);
    errno_t ret = memcpy_sp(&req.xa_xid, sizeof(drc_global_xid_t), &dms_ctx->global_xid, sizeof(drc_global_xid_t));
    if (ret != EOK) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_DELETE_XA_RES);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_request_delete_xa_res]: src_id = %u, dst_id = %u",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), dms_ctx->inst_id, (uint32)master_id);
    int32 ret_code = mfc_send_data(&req.head);
    if (ret_code != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_request_delete_xa_res]: failed to send delete xa res request",
            cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE));
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_DELETE_XA_RES);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret_code, MSG_REQ_DELETE_GLOBAL_XA_RES, master_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t recv_msg = { 0 };
    ret_code = mfc_get_response(req.head.ruid, &recv_msg, DMS_WAIT_MAX_TIME);
    if (ret_code != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_request_delete_xa_res]: wait master node ack timeout, timeout = %u ms",
            cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), DMS_WAIT_MAX_TIME);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_DELETE_XA_RES);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret_code, MSG_REQ_DELETE_GLOBAL_XA_RES, master_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (recv_msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(recv_msg.buffer);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        mfc_release_response(&recv_msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    LOG_DEBUG_INF("[DMS][%s]: src_id = %u, src_sid = %u, dst_id = %u, dts_sid = %u, flag = %u, ruid = %llu",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), (uint32)recv_msg.head->src_inst,
        (uint32)recv_msg.head->src_sid, (uint32)recv_msg.head->dst_inst,
        (uint32)recv_msg.head->dst_sid, (uint32)recv_msg.head->flags, recv_msg.head->ruid);

    dms_xa_res_ack_t *result_msg = (dms_xa_res_ack_t *)recv_msg.buffer;
    *result_code = result_msg->return_code;
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_DELETE_XA_RES);
    mfc_release_response(&recv_msg);
    LOG_DEBUG_INF("[DMS][%s][dms_request_delete_xa_res]: delete xa res remote success, master_id = %u",
        cm_display_resid((char *)&dms_ctx->global_xid, DRC_RES_GLOBAL_XA_TYPE), (uint32)master_id);
    return DMS_SUCCESS;
}

void dms_proc_delete_xa_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_xa_res_req_t), CM_TRUE);
    dms_xa_res_req_t req = *(dms_xa_res_req_t *)receive_msg->buffer;

    drc_global_xid_t *xid = &req.xa_xid;
    if (dms_proc_check_xid_valid(xid)) {
        return;
    }

    int32 ret = drc_delete_xa_res(xid, req.check_xa_drc);
    dms_xa_res_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_DELETE_GLOBAL_XA_RES, sizeof(dms_xa_res_ack_t),
        proc_ctx->sess_id);
    ack.return_code = ret;

    ret = mfc_send_data(&ack.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_delete_xa_res]: failed to send ack, dst_id = %u, dst_sid = %u, errcode = %d",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid, ret);
    } else {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_delete_xa_res]: finished, dst_id = %u, dst_sid = %u",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid);
    }
}

void dms_proc_ask_xa_owner(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_xa_owner_req_t), CM_TRUE);
    dms_ask_xa_owner_req_t req = *(dms_ask_xa_owner_req_t *)receive_msg->buffer;

    drc_global_xid_t *xid = &req.xa_xid;
    if (dms_proc_check_xid_valid(xid)) {
        return;
    }
    
    uint8 owner_id = CM_INVALID_ID8;
    drc_global_xa_res_t *xa_res = NULL;
    int32 ret = drc_enter_xa_res(xid, &xa_res, req.check_xa_drc);
    if (ret != DMS_SUCCESS) {
        dms_send_error_ack(
            proc_ctx->inst_id, proc_ctx->sess_id, req.head.src_inst, req.head.src_sid, req.head.ruid, ret,
            req.head.msg_proto_ver);
        return;
    }

    if (xa_res != NULL) {
        owner_id = xa_res->owner_id;
    }

    drc_global_res_map_t *xa_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(&xa_res_map->res_map, (char *)xid, sizeof(drc_global_xid_t));
    drc_leave_xa_res(xa_res_map, bucket);

    dms_ask_xa_owner_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_ASK_XA_OWNER_ID, sizeof(dms_xa_res_ack_t),
        proc_ctx->sess_id);
    ack.owner_id = owner_id;

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_xa_owner]: src_id = %u, src_sid = %u",
        cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)req.head.src_inst, (uint16)req.head.src_sid);

    ret = mfc_send_data(&ack.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_ask_xa_owner]: failed to send ack, dst_id = %u, dst_sid = %u, errcode = %d",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid, ret);
    } else {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_xa_owner]: finished, dst_id = %u, dst_sid = %u",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid);
    }
}

static int32 dms_ask_xa_owner_local(dms_context_t *dms_ctx, uint8 *owner_id)
{
    drc_global_xa_res_t *xa_res = NULL;
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;
    drc_global_res_map_t *res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(&res_map->res_map, (char *)global_xid, sizeof(drc_global_xid_t));
    bool32 check_xa_drc = (bool32)dms_is_recovery_session(dms_ctx->sess_id);

    int32 ret = drc_enter_xa_res(global_xid, &xa_res, check_xa_drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (xa_res == NULL) {
        LOG_DEBUG_ERR("[DMS][%s][dms_ask_xa_owner_local]: xa res not exists", cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        drc_leave_xa_res(res_map, bucket);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_RES_NOT_EXISTS, cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_RES_NOT_EXISTS;
    }

    *owner_id = xa_res->owner_id;
    drc_leave_xa_res(res_map, bucket);
    return DMS_SUCCESS;
}

static int32 dms_ask_xa_owner_remote(dms_context_t *dms_ctx, uint8 master_id, uint8 *owner_id)
{
    dms_ask_xa_owner_req_t req = { 0 };
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID, CM_TRUE);
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_XA_OWNER_ID, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_ask_xa_owner_req_t);
    req.sess_type = dms_ctx->sess_type;
    req.check_xa_drc = (bool32)dms_is_recovery_session(dms_ctx->sess_id);
    errno_t err = memcpy_sp(&req.xa_xid, sizeof(drc_global_xid_t), &dms_ctx->global_xid, sizeof(drc_global_xid_t));
    if (err != EOK) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return err;
    }

    int32 ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_ASK_XA_OWNER_ID, master_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[TXN][%s][dms_ask_xa_owner_remote]: src_id = %u, dst_id = %u", cm_display_resid((char *)global_xid,
        DRC_RES_GLOBAL_XA_TYPE), dms_ctx->inst_id, master_id);
    dms_message_t msg = { 0 };
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
        LOG_DEBUG_ERR("[TXN][%s][dms_ask_xa_owner_remote]: wait owner ack of xa res timeout timeout = %d ms", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE), DMS_WAIT_MAX_TIME);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_ASK_XA_OWNER_ID, master_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }
    
    if (msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(msg.buffer);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&msg, sizeof(dms_ask_xa_owner_ack_t), CM_FALSE);
    dms_ask_xa_owner_ack_t *ack = (dms_ask_xa_owner_ack_t *)msg.buffer;
    if (ack->owner_id == CM_INVALID_ID8) {
        LOG_DEBUG_ERR("[TXN][%s][dms_ask_xa_owner_remote]: xa res not exists", cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
        mfc_release_response(&msg);
        return ERRNO_DMS_DRC_XA_RES_NOT_EXISTS;
    }

    *owner_id = ack->owner_id;
    mfc_release_response(&msg);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_OWNER_ID);
    return DMS_SUCCESS;
}

int32 dms_request_xa_owner(dms_context_t *dms_ctx, unsigned char *owner_id)
{
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;

    LOG_DEBUG_INF("[TXN][%s] dms_request_xa_owner", cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
    uint8 master_id = 0xFF;
    int32 ret = drc_get_master_id((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[TXN][%s] failed to get master id when get xa owner id", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        return dms_ask_xa_owner_local(dms_ctx, owner_id);
    } else {
        return dms_ask_xa_owner_remote(dms_ctx, master_id, owner_id);
    }
}

int32 dms_request_end_xa(dms_context_t *dms_ctx, uint8 owner_id, uint64 flags, uint64 scn, bool8 is_commit, int32 *return_code)
{
    dms_end_xa_req_t req = { 0 };
    drc_global_xid_t *xid = &dms_ctx->global_xid;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_END_XA, CM_TRUE);
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_END_XA, 0, dms_ctx->inst_id, owner_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_end_xa_req_t);
    req.commit_scn = scn;
    req.flags = flags;
    req.is_commit = is_commit;
    errno_t err = memcpy_sp(&req.xa_xid, sizeof(drc_global_xid_t), xid, sizeof(drc_global_xid_t));
    if (err != EOK) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_END_XA);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return err;
    }

    LOG_DEBUG_INF("[TXN][%s] end the xa remote, src_id = %u, dst_id = %u", cm_display_resid((char *)xid,
        DRC_RES_GLOBAL_XA_TYPE), dms_ctx->inst_id, owner_id);
    int32 ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_END_XA);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_END_XA, owner_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t msg = { 0 };
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_END_XA);
        LOG_DEBUG_ERR("[TXN][%s] wait owner ack timeout while end xa, timeout = %u ms", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE), DMS_WAIT_MAX_TIME);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_END_XA, owner_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }
    
    if (msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(msg.buffer);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&msg, (uint32)sizeof(dms_end_xa_ack_t), CM_FALSE);
    dms_end_xa_ack_t *ack = (dms_end_xa_ack_t *)msg.buffer;
    *return_code = ack->return_code;
    mfc_release_response(&msg);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_END_XA);
    return DMS_SUCCESS;
}

void dms_proc_end_xa(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_end_xa_req_t), CM_TRUE);
    dms_end_xa_req_t req = *(dms_end_xa_req_t *)receive_msg->buffer;

    drc_global_xid_t *xid = &req.xa_xid;
    if (!dms_proc_check_xid_valid(xid)) {
        return;
    }

    int32 ret = g_dms.callback.end_xa(proc_ctx->db_handle, xid, req.flags, req.commit_scn, req.is_commit);
    dms_end_xa_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_END_XA, sizeof(dms_end_xa_ack_t), proc_ctx->sess_id);
    ack.return_code = (ret == DMS_SUCCESS ? ret :g_dms.callback.db_get_kernel_error_code());

    LOG_DEBUG_INF("[DMS][%s][dms_proc_end_xa]: src_id = %u, src_sid = %u", 
        cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)req.head.src_inst, (uint16)req.head.src_sid);
    
    ret = mfc_send_data(&ack.head);
    if (ret == DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_end_xa]: finished, dst_id = %u, dst_sid = %u", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid);
    } else {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_end_xa]: failed to send ack, dst_id = %u, dst_sid = %u, errcode = %u",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid, ret);
    }
}

static int32 dms_ask_xa_inuse_remote(dms_context_t *dms_ctx, uint8 owner_id, bool8 *inuse)
{
    dms_ask_xa_inuse_req_t req = { 0 };
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_IN_USE, CM_TRUE);
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_XA_IN_USE, 0, dms_ctx->inst_id, owner_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_ask_xa_inuse_req_t);
    req.sess_type = dms_ctx->sess_type;
    errno_t err = memcpy_sp(&req.xa_xid, sizeof(drc_global_xid_t), global_xid, sizeof(drc_global_xid_t));
    if (err != EOK) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, err);
        return err;
    }

    LOG_DEBUG_INF("[TXN][%s][dms_ask_xa_inuse_remote]: src_id = %u, dst_id = %u", cm_display_resid((char *)global_xid,
        DRC_RES_GLOBAL_XA_TYPE), dms_ctx->inst_id, owner_id);
    int32 ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_ASK_XA_IN_USE, owner_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t msg = { 0 };
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
        LOG_DEBUG_ERR("[TXN][%s][dms_ask_xa_inuse_remote]: wait if in use ack of xa res timeout, timeout = %d ms",
            cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE), DMS_WAIT_MAX_TIME);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_ASK_XA_IN_USE, owner_id);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(msg.buffer);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_CREATE_XA_RES);
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&msg, sizeof(dms_ask_xa_inuse_ack_t), CM_FALSE);
    dms_ask_xa_inuse_ack_t *ack = (dms_ask_xa_inuse_ack_t *)msg.buffer;
    *inuse = ack->inuse;
    
    mfc_release_response(&msg);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
    return DMS_SUCCESS;
}

int32 dms_request_xa_inuse(dms_context_t *dms_ctx, uint8 owner_id, bool8 *inuse)
{
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;
    LOG_DEBUG_INF("[TXN][%s] enter dms_request_xa_inuse", cm_display_resid((char *)global_xid,
        DRC_RES_GLOBAL_XA_TYPE));
    
    if (owner_id == dms_ctx->inst_id) {
        *inuse = g_dms.callback.xa_inuse(dms_ctx->db_handle, (void *)global_xid);
        return DMS_SUCCESS;
    } else {
        return dms_ask_xa_inuse_remote(dms_ctx, owner_id, inuse);
    }
}

void dms_proc_ask_xa_inuse(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_xa_inuse_req_t), CM_TRUE);
    dms_ask_xa_inuse_req_t req = *(dms_ask_xa_inuse_req_t *)receive_msg->buffer;

    drc_global_xid_t *xid = &req.xa_xid;
    if (!dms_proc_check_xid_valid(xid)) {
        return;
    }

    dms_ask_xa_inuse_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_XA_IN_USE, sizeof(dms_ask_xa_inuse_ack_t), proc_ctx->sess_id);
    ack.inuse = g_dms.callback.xa_inuse(proc_ctx->db_handle, (void *)xid);

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_xa_inuse]: src_id = %u, src_sid = %u",
        cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)req.head.src_inst, (uint16)req.head.src_sid);

    int32 ret = mfc_send_data(&ack.head);
    if (ret == DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_xa_inuse]: finished, dst_id = %u, dst_sid = %u", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst, (uint16)ack.head.dst_sid);
    } else {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_xa_inuse]: failed to send ack, dst_id = %u, dst_sid = %u, errcode = %u",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), (uint8)ack.head.dst_inst,
            (uint16)ack.head.dst_sid, ret);
    }
}