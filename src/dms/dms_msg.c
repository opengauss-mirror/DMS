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
 * dms_msg.c
 *
 *
 * IDENTIFICATION
 *    src/common/dms_msg.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_log.h"
#include "dms_process.h"
#include "dms_cm.h"
#include "dms_errno.h"
#include "drc_page.h"
#include "dls_msg.h"
#include "dcs_page.h"
#include "dms_stat.h"
#include "dms_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

void cm_send_error_msg(mes_message_head_t *head, int32 err_code, char *err_info)
{
    msg_error_t msg_error;

    mfc_init_ack_head(head, &msg_error.head, MSG_ACK_ERROR, (uint16)(sizeof(msg_error_t) + strlen(err_info) + 1),
        CM_INVALID_ID32);
    msg_error.code = err_code;

    if (mfc_send_data3(&msg_error.head, sizeof(msg_error_t), err_info) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send error msg to instance %d failed.", head->src_inst);
    }
}

void cm_ack_result_msg(dms_process_context_t *process_ctx, mes_message_t *receive_msg, uint8 cmd, int32 ret)
{
    char ack_buf[sizeof(mes_message_head_t) + sizeof(int32)];
    uint8 *send_msg = (uint8 *)ack_buf;
    mes_message_head_t *head = (mes_message_head_t *)send_msg;

    DMS_INIT_MESSAGE_HEAD(head, cmd, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        process_ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)(sizeof(mes_message_head_t) + sizeof(int32));
    head->rsn = receive_msg->head->rsn;
    *(int32 *)(send_msg + sizeof(mes_message_head_t)) = ret;

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data(head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send result msg to instance %d failed.", receive_msg->head->src_inst);
    }

    return;
}

void cm_ack_result_msg2(dms_process_context_t *process_ctx, mes_message_t *receive_msg, uint8 cmd, char *msg,
    uint32 len, char *ack_buf)
{
    uint8 *send_msg = (uint8 *)ack_buf;
    mes_message_head_t *head = (mes_message_head_t *)ack_buf;

    DMS_INIT_MESSAGE_HEAD(head, cmd, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        process_ctx->sess_id, receive_msg->head->src_sid);
    head->size = (uint16)(sizeof(mes_message_head_t) + len);
    head->rsn = receive_msg->head->rsn;
    int ret = memcpy_s(send_msg + sizeof(mes_message_head_t), len, msg, len);
    DMS_SECUREC_CHECK(ret);

    mfc_release_message_buf(receive_msg);
    if (mfc_send_data(head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send result msg to instance %d failed.", receive_msg->head->src_inst);
    }
    return;
}

void dms_send_error_ack(uint8 src_inst, uint32 src_sid, uint8 dst_inst, uint32 dst_sid, uint64 dst_rsn, int32 ret)
{
    msg_error_t msg_error;
    const char *errmsg = NULL;
    cm_get_error(&ret, &errmsg);

    DMS_INIT_MESSAGE_HEAD(&msg_error.head, MSG_ACK_ERROR, 0, src_inst, dst_inst, src_sid, dst_sid);
    msg_error.code      = ret;
    msg_error.head.rsn  = dst_rsn;
    msg_error.head.size = (uint16)(sizeof(msg_error_t) + strlen(errmsg) + 1);

    if (mfc_send_data3(&msg_error.head, sizeof(msg_error_t), errmsg) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send error msg to instance %u failed.", dst_sid);
    }
}

static int32 dms_notify_invld_share_copy(dms_invld_req_t *req, uint32 sess_id, uint64 invld_insts, uint64 *succ_insts)
{
    dms_begin_stat(sess_id, DMS_EVT_DCS_INVLDT_SHARE_COPY_REQ, CM_TRUE);
    int32 ret = mfc_broadcast_and_wait2(sess_id, invld_insts, (void *)req, DMS_WAIT_MAX_TIME, succ_insts);
    if (ret != DMS_SUCCESS || *succ_insts != invld_insts) {
        dms_end_stat(sess_id);
        LOG_DEBUG_ERR("[DMS][%s][dms_notify_invld_share_copy]: failed, invld_insts=%llu, succ_insts=%llu",
            cm_display_resid(req->resid, req->res_type), invld_insts, *succ_insts);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED);
        return ERRNO_DMS_DCS_BROADCAST_FAILED;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_notify_invld_share_copy]: invld_insts=%llu, succ_insts=%llu",
        cm_display_resid(req->resid, req->res_type), invld_insts, *succ_insts);
    dms_end_stat(sess_id);
    return DMS_SUCCESS;
}

static void drc_clean_share_copy_insts(char *resid, uint16 len, uint8 type,
    dms_session_e sess_type, uint64 owner_map, drc_buf_res_t *buf_res)
{
    bool need_lock = (buf_res == NULL);
    if (need_lock) {
        uint8 options = drc_build_options(CM_FALSE, sess_type, CM_TRUE);
        int ret = drc_enter_buf_res(resid, len, type, options, &buf_res);
        if (ret != DMS_SUCCESS) {
            return;
        }
    }

    cm_panic_log(buf_res != NULL, "[DCS][%s][drc_clean_share_copy_insts]: buf_res is NULL",
        cm_display_resid(resid, type));
    buf_res->copy_insts = buf_res->copy_insts & (~owner_map);
    LOG_DEBUG_INF("[DCS][%s][drc_clean_share_copy_insts]: invld_owner_map=%llu, curr_copy_insts=%llu",
        cm_display_resid(resid, type), owner_map, buf_res->copy_insts);
    
    if (need_lock) {
        drc_leave_buf_res(buf_res); 
    }
}

static int32 dms_invalidate_share_copy(uint32 inst_id, uint32 sess_id, char *resid,
    uint16 len, uint8 type, uint64 invld_insts, dms_session_e sess_type, uint32 ver, drc_buf_res_t *buf_res)
{
    uint64 succ_insts = 0;
    dms_invld_req_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_INVALIDATE_SHARE_COPY, 0, inst_id, 0, sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_invld_req_t);
    req.head.rsn  = mfc_get_rsn(sess_id);
    req.len       = len;
    req.res_type  = type;
    req.sess_type = sess_type;
    req.ver       = ver;
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, resid, len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(resid, type));
        LOG_DEBUG_ERR("[DMS][%s][dms_invalidate_share_copy]: system call failed", cm_display_resid(resid, type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    ret = dms_notify_invld_share_copy(&req, sess_id, invld_insts, &succ_insts);

    if (succ_insts > 0) {
        drc_clean_share_copy_insts(resid, len, type, sess_type, succ_insts, buf_res);
    }
    return ret;
}

int32 dms_claim_ownership_r(dms_context_t *dms_ctx, uint8 master_id,
    dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn, uint32 ver)
{
    dms_claim_owner_req_t request;
    DMS_INIT_MESSAGE_HEAD(&request.head,
        MSG_REQ_CLAIM_OWNER, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.size = (uint16)sizeof(dms_claim_owner_req_t);
    request.head.rsn  = mfc_get_rsn(dms_ctx->sess_id);
    request.req_mode  = mode;
    request.has_edp   = has_edp;
    request.lsn       = page_lsn;
    request.sess_type = dms_ctx->sess_type;
    request.res_type  = dms_ctx->type;
    request.len       = dms_ctx->len;
    request.ver       = ver;
    int32 ret = memcpy_sp(request.resid, DMS_RESID_SIZE, dms_ctx->resid, request.len);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(dms_ctx->resid, dms_ctx->type));
        LOG_DEBUG_ERR("[DMS][%s][dms_claim_ownership_r]: system call failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    ret = mfc_send_data(&request.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: send failed, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, rsn=%llu",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(request.head.cmd),
            (uint32)request.head.src_inst, (uint32)request.head.src_sid, (uint32)request.head.dst_inst,
            (uint32)request.head.dst_sid, (bool32)request.has_edp, request.head.rsn);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_CLAIM_OWNER, request.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: send ok, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, rsn=%llu",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(request.head.cmd),
        (uint32)request.head.src_inst, (uint32)request.head.src_sid, (uint32)request.head.dst_inst,
        (uint32)request.head.dst_sid, (bool32)request.has_edp, request.head.rsn);
    return DMS_SUCCESS;
}

static int32 dms_set_claim_info(claim_info_t *claim_info, char *resid, uint16 len, uint8 res_type, uint8 ownerid,
    dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn, uint32 sess_id, uint32 ver, uint64 rsn,
    dms_session_e sess_type)
{
    claim_info->new_id   = ownerid;
    claim_info->has_edp  = has_edp;
    claim_info->lsn      = page_lsn;
    claim_info->req_mode = mode;
    claim_info->res_type = res_type;
    claim_info->len      = len;
    claim_info->sess_id  = sess_id;
    claim_info->ver      = ver;
    claim_info->sess_type = sess_type;
    claim_info->rsn      = rsn;
    int ret = memcpy_s(claim_info->resid, DMS_RESID_SIZE, resid, len);
    if (ret == EOK) {
        return DMS_SUCCESS;
    }
    LOG_DEBUG_ERR("[DMS][%s][dms_set_claim_info]: system call failed", cm_display_resid(resid, res_type));
    DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(resid, res_type));
    return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
}

static inline int32 dms_handle_grant_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, mes_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_need_load(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_grant_owner_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static inline int32 dms_handle_already_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, mes_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_already_owner(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_already_owner_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static inline int32 dms_handle_res_ready_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, mes_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_page_ready(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_lock_ready_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static int32 dms_handle_ask_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, mes_message_t *msg)
{
    if (msg->head->cmd == MSG_ACK_PAGE_READY) {
        return dms_handle_res_ready_ack(dms_ctx, res, master_id, mode, msg);
    }

    if (msg->head->cmd == MSG_ACK_GRANT_OWNER) {
        return dms_handle_grant_owner_ack(dms_ctx, res, master_id, mode, msg);
    }

    if (msg->head->cmd == MSG_ACK_ERROR) {
        msg_error_t error_ack = *(msg_error_t*)msg->buffer;
        return error_ack.code;
    }
    LOG_DEBUG_ERR("[DMS][dms_handle_ask_owner_ack]recieve unexpected message,cmd:%u", (uint32)msg->head->cmd);
    return ERRNO_DMS_MES_INVALID_MSG;
}

static int32 dms_ask_owner_for_res(dms_context_t *dms_ctx, void *res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, drc_req_owner_result_t *result)
{
    dms_ask_res_req_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head,
        MSG_REQ_ASK_OWNER_FOR_PAGE, 0, dms_ctx->inst_id, result->curr_owner_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.rsn  = mfc_get_rsn(dms_ctx->sess_id);
    req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    req.req_mode  = req_mode;
    req.curr_mode = curr_mode;
    req.has_share_copy = result->has_share_copy;
    req.res_type  = dms_ctx->type;
    req.is_try    = (bool8)dms_ctx->is_try;
    req.len       = dms_ctx->len;
    req.sess_type = dms_ctx->sess_type;
    req.ver       = result->ver;
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, req.len);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(dms_ctx->resid, dms_ctx->type));
        LOG_DEBUG_ERR("[DMS][%s][dms_ask_owner_for_res]: system call failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS]%s][%s]: send failed, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(req.head.cmd),
            (uint32)req.head.src_inst, (uint32)req.head.src_sid, (uint32)req.head.dst_inst,
            (uint32)req.head.dst_sid, (uint32)req_mode);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, req.head.cmd, req.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DMS]%s][%s]: send ok, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(req.head.cmd),
        (uint32)req.head.src_inst, (uint32)req.head.src_sid, (uint32)req.head.dst_inst,
        (uint32)req.head.dst_sid, (uint32)req_mode);

    mes_message_t msg;
    ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: wait ack timeout, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), "ASK OWNER", (uint32)req.head.src_inst,
            (uint32)req.head.src_sid, (uint32)req.head.dst_inst, (uint32)req.head.dst_sid, (uint32)req_mode);
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_ASK_OWNER_FOR_PAGE, req.head.dst_inst);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    ret = dms_handle_ask_owner_ack(dms_ctx, res, (uint8)dms_ctx->inst_id, req_mode, &msg);

    mfc_release_message_buf(&msg);
    return ret;
}

static int32 dms_handle_ask_master_ack(dms_context_t *dms_ctx,
    void *res, uint8 master_id, dms_lock_mode_t mode, dms_wait_event_t *ack_event)
{
    if (ack_event) {
        *ack_event = DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY;
    }

    mes_message_t msg;
    int32 ret = mfc_allocbuf_and_recv_data((uint16)dms_ctx->sess_id, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_handle_ask_master_ack]:wait master ack timeout timeout=%d ms",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), DMS_WAIT_MAX_TIME);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_DCS_MSG_EAGAIN;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]:src_id=%u, src_sid=%u, dst_id=%u, dst_sid =%u, flag=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(msg.head->cmd),
        (uint32)msg.head->src_inst, (uint32)msg.head->src_sid, (uint32)msg.head->dst_inst,
        (uint32)msg.head->dst_sid, (uint32)msg.head->flags);

    switch (msg.head->cmd) {
        case MSG_ACK_GRANT_OWNER:
            ret = dms_handle_grant_owner_ack(dms_ctx, res, master_id, mode, &msg);
            break;

        case MSG_ACK_ALREADY_OWNER:
            ret = dms_handle_already_owner_ack(dms_ctx, res, master_id, mode, &msg);
            break;

        case MSG_ACK_ERROR:
            ret = ERRNO_DMS_COMMON_MSG_ACK;
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (char *)((char *)(msg.buffer) + sizeof(msg_error_t)));
            break;

        case MSG_ACK_EDP_LOCAL:
            CM_ASSERT(dms_ctx->type == DRC_RES_PAGE_TYPE);
            ret = dcs_handle_ack_edp_local(dms_ctx, (dms_buf_ctrl_t*)res, master_id, &msg, mode);
            break;

        case MSG_ACK_PAGE_READY:
            ret = dms_handle_res_ready_ack(dms_ctx, res, master_id, mode, &msg);
            if (ack_event && master_id != msg.head->src_inst) {
                *ack_event = DMS_EVT_DCS_REQ_MASTER4PAGE_3WAY;
            }
            break;
        case MSG_ACK_EDP_READY:
            CM_ASSERT(dms_ctx->type == DRC_RES_PAGE_TYPE);
            ret = dcs_handle_ack_edp_remote(dms_ctx, (dms_buf_ctrl_t*)res, master_id, &msg, mode);
            if (ack_event && master_id != msg.head->src_inst) {
                *ack_event = DMS_EVT_DCS_REQ_MASTER4PAGE_3WAY;
            }
            break;

        default:
            CM_ASSERT(0);
            LOG_DEBUG_ERR("[DMS][dms_handle_ask_master_ack]recieve unexpected message");
            break;
    }

    mfc_release_message_buf(&msg);
    return ret;
}

static int32 dms_handle_local_req_result(dms_context_t *dms_ctx, void *res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, drc_req_owner_result_t *result)
{
    int ret;

    switch (result->type) {
        case DRC_REQ_OWNER_GRANTED:
            ret = dms_handle_grant_owner_ack(dms_ctx, res, (uint8)dms_ctx->inst_id, req_mode, NULL);
            dms_end_stat(dms_ctx->sess_id);

            LOG_DEBUG_INF("[DMS][%s][ask master local]:granted, inst_id=%u, req_mode=%u, curr_mode=%u",
                cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id, (uint32)req_mode, (uint32)curr_mode);
            return ret;

        case DRC_REQ_OWNER_ALREADY_OWNER:
            ret = dms_handle_already_owner_ack(dms_ctx, res, (uint8)dms_ctx->inst_id, req_mode, NULL);
            dms_end_stat(dms_ctx->sess_id);

            LOG_DEBUG_INF("[DMS][%s][ask master local]:already owner, inst_id=%u, req_mode=%u, curr_mode=%u",
                cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id, (uint32)req_mode, (uint32)curr_mode);
            return ret;

        case DRC_REQ_OWNER_CONVERTING:
            // owner is another instance
            ret = dms_ask_owner_for_res(dms_ctx, res, curr_mode, req_mode, result);
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_OWNER4PAGE);
            return ret;

        case DRC_REQ_OWNER_WAITING:
            ret = dms_handle_ask_master_ack(dms_ctx, res, (uint8)dms_ctx->inst_id, req_mode, NULL);
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_OWNER4PAGE);
            return ret;

        case DRC_REQ_EDP_LOCAL:
            CM_ASSERT(dms_ctx->type == DRC_RES_PAGE_TYPE);
            ret = dcs_handle_ack_edp_local(dms_ctx, (dms_buf_ctrl_t*)res, (uint8)dms_ctx->inst_id, NULL, req_mode);
            dms_end_stat(dms_ctx->sess_id);
            LOG_DEBUG_INF("[DMS][%s][ask edp local]: ret=%d",
                cm_display_resid(dms_ctx->resid, (uint8)dms_ctx->type), ret);
            return ret;

        case DRC_REQ_EDP_REMOTE:
            CM_ASSERT(dms_ctx->type == DRC_RES_PAGE_TYPE);
            ret = dcs_handle_ask_edp_remote(dms_ctx, (dms_buf_ctrl_t*)res, result->curr_owner_id, req_mode);
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_OWNER4PAGE);
            LOG_DEBUG_INF("[DMS][%s][ask edp remote]: dst_id=%u, req_mode=%u, curr_mode=%u, ret=%d",
                cm_display_resid(dms_ctx->resid, dms_ctx->type), (uint32)result->curr_owner_id,
                (uint32)req_mode, (uint32)curr_mode, ret);
            return ret;

        default:
            dms_end_stat(dms_ctx->sess_id);
            LOG_DEBUG_ERR("[DMS][%s]dms_handle_local_req_result]: result type %u not expect",
                cm_display_resid(dms_ctx->resid, dms_ctx->type), (uint32)result->type);
            DMS_THROW_ERROR(ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT, result->type);
            return ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT;
    }
}

static int32 dms_ask_master4res_l(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t req_mode, uint32 ver)
{
    uint8 req_id = (uint8)dms_ctx->inst_id;
    drc_req_owner_result_t result;

    LOG_DEBUG_INF("[DMS][%s][ask master local]: src_id=%u, req_mode=%u, curr_mode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id, (uint32)req_mode, (uint32)curr_mode);

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, req_id, (uint16)dms_ctx->sess_id, mfc_get_rsn(dms_ctx->sess_id),
        curr_mode, req_mode, dms_ctx->is_try, dms_ctx->sess_type, ver);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_1WAY, CM_TRUE);

    int32 ret = drc_request_page_owner(dms_ctx->resid, dms_ctx->len, dms_ctx->type, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_end_stat(dms_ctx->sess_id);
        return ret;
    }

    if (result.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), result.invld_insts);

        ret = dms_invalidate_share_copy(dms_ctx->inst_id, dms_ctx->sess_id, dms_ctx->resid,
            dms_ctx->len, dms_ctx->type, result.invld_insts, dms_ctx->sess_type, result.ver, NULL);
        if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
            dms_end_stat(dms_ctx->sess_id);
            return ret;
        }
    }

    LOG_DEBUG_INF("[DMS][%s][dms_ask_master4res_l] result type=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), result.type);

    // dms_stat ends in sub-func for different scenarios
    return dms_handle_local_req_result(dms_ctx, res, curr_mode, req_mode, &result);
}

static int32 dms_send_ask_master_req(dms_context_t *dms_ctx, uint8 master_id,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, uint32 ver)
{
    dms_ask_res_req_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_MASTER_FOR_PAGE,
        0, dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);

    req.head.rsn  = mfc_get_rsn(dms_ctx->sess_id);
    req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    req.req_mode  = req_mode;
    req.curr_mode = curr_mode;
    req.sess_type = dms_ctx->sess_type;
    req.is_try    = dms_ctx->is_try;
    req.res_type  = dms_ctx->type;
    req.len       = dms_ctx->len;
    req.ver       = ver;
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, dms_ctx->len);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][%s] system call failed", cm_display_resid(dms_ctx->resid, dms_ctx->type));
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    LOG_DEBUG_INF("[DMS][%s][ASK MASTER]: src_id=%u, dst_id=%u, req_mode=%u, curr_mode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id,
        (uint32)master_id, (uint32)req_mode, (uint32)curr_mode);

    if (mfc_send_data(&req.head) == DMS_SUCCESS) {
        return DMS_SUCCESS;
    }

    LOG_DEBUG_ERR("failed to send ask master request. Try again later");
    DMS_THROW_ERROR(ERRNO_DMS_DCS_MSG_EAGAIN);
    return ERRNO_DMS_DCS_MSG_EAGAIN;
}

static int32 dms_ask_master4res_r(dms_context_t *dms_ctx, void *res, uint8 master_id, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode, uint32 ver)
{
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY, CM_TRUE);

    int32 ret = dms_send_ask_master_req(dms_ctx, master_id, curr_mode, mode, ver);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY);
        return ret;
    }

    dms_wait_event_t event = DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY;
    ret = dms_handle_ask_master_ack(dms_ctx, res, master_id, mode, &event);

    dms_end_stat_ex(dms_ctx->sess_id, event);
    return ret;
}

int32 dms_request_res_internal(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t req_mode, uint32 ver)
{
    uint8 master_id;
    int32 ret = drc_get_master_id(dms_ctx->resid, dms_ctx->type, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        ret = dms_ask_master4res_l(dms_ctx, res, curr_mode, req_mode, ver);
    } else {
        ret = dms_ask_master4res_r(dms_ctx, res, master_id, curr_mode, req_mode, ver);
    }
    return ret;
}

static void dms_send_requester_granted(dms_process_context_t *ctx, dms_ask_res_req_t *req)
{
    // this page not in memory of other instance, notify requester to load from disk
    dms_ask_res_ack_ld_t ack;
    mfc_init_ack_head(&req->head, &ack.head, MSG_ACK_GRANT_OWNER, sizeof(dms_ask_res_ack_ld_t), ctx->sess_id);
    ack.head.rsn = req->head.rsn;
#ifndef OPENGAUSS
    if (req->res_type == DRC_RES_PAGE_TYPE) {
        ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
        ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
    }
#endif
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd), (uint32)ack.head.src_inst,
            (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)req->req_mode);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd), (uint32)ack.head.src_inst,
        (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)req->req_mode);
}

static void dms_send_requester_already_owner(dms_process_context_t *ctx, dms_ask_res_req_t *req)
{
    // asker is already owner, just notify requester(owner) page is ready
    mes_message_head_t head;
    mfc_init_ack_head(&req->head, &head, MSG_ACK_ALREADY_OWNER, sizeof(mes_message_head_t), ctx->sess_id);
    if (mfc_send_data(&head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd), (uint32)head.src_inst,
            (uint32)head.src_sid, (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)req->req_mode);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send ok, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd), (uint32)head.src_inst,
        (uint32)head.src_sid, (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)req->req_mode);
}

static int dms_notify_owner_for_res_r(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    int ret;

    if (req_info->owner_id != req_info->req_id) {
        dms_ask_res_req_t req;
        DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_OWNER_FOR_PAGE, 0,
            req_info->req_id, req_info->owner_id, req_info->req_sid, CM_INVALID_ID16);
        req.req_mode  = req_info->req_mode;
        req.curr_mode = req_info->curr_mode;
        req.head.size = (uint16)sizeof(dms_ask_res_req_t);
        req.head.rsn  = req_info->req_rsn;
        req.has_share_copy = req_info->has_share_copy;
        req.sess_type = req_info->sess_type;
        req.res_type = req_info->res_type;
        req.is_try = req_info->is_try;
        req.len = (uint16)req_info->len;
        req.ver = req_info->ver;
        ret = memcpy_sp(req.resid, DMS_RESID_SIZE, req_info->resid, req.len);
        if (SECUREC_UNLIKELY(ret != EOK)) {
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(req_info->resid, req_info->res_type));
            return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS][%s][%s] send failed: dst_id=%u, dst_sid=%u, mode=%u",
                cm_display_resid(req_info->resid, req_info->res_type), "ASK OWNER",
                (uint32)req.head.dst_inst, (uint32)req.head.dst_sid, (uint32)req.req_mode);
            DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, req.head.cmd, req.head.dst_inst);
            dms_send_error_ack(ctx->inst_id, ctx->sess_id, req_info->req_id, req_info->req_sid,
                req_info->req_rsn, ret);
            return ERRNO_DMS_SEND_MSG_FAILED;
        }

        LOG_DEBUG_INF("[DMS][%s][%s] send ok: dst_id=%u, dst_sid=%u, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type), "ASK OWNER",
            (uint32)req.head.dst_inst, (uint32)req.head.dst_sid, (uint32)req.req_mode);
        return ret;
    }

    // asker is already owner, just notify requester(owner) page is ready
    mes_message_head_t head;
    DMS_INIT_MESSAGE_HEAD(&head, MSG_ACK_ALREADY_OWNER, 0, ctx->inst_id, req_info->req_id,
        ctx->sess_id, req_info->req_sid);
    head.rsn = req_info->req_rsn;
    head.size = (uint16)sizeof(mes_message_head_t);

    ret = mfc_send_data(&head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: failed, dst_id=%u, dst_sid=%u, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type),
            "MASTER ACK ALREADY OWNER", (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)req_info->req_mode);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, head.cmd, head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: ok, dst_id=%u, dst_sid=%u, mode=%u",
        cm_display_resid(req_info->resid, req_info->res_type),
        "MASTER ACK ALREADY OWNER", (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)req_info->req_mode);
    return DMS_SUCCESS;
}

static inline int32 dms_transfer_res_owner(dms_process_context_t *process_ctx, dms_res_req_info_t *req_info)
{
    if (req_info->res_type == DRC_RES_PAGE_TYPE) {
        return dcs_owner_transfer_page(process_ctx, req_info);
    }
    return dls_owner_transfer_lock(process_ctx, req_info);
}

static int dms_notify_owner_for_res(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    LOG_DEBUG_INF("[DMS][%s][dms_notify_owner_for_res]: owner_id=%u, curr_mode=%u, req_mode=%u, has_share_copy=%u",
        cm_display_resid(req_info->resid, req_info->res_type), (uint32)req_info->owner_id,
        (uint32)req_info->curr_mode, (uint32)req_info->req_mode, (uint32)req_info->has_share_copy);

    if (ctx->inst_id != req_info->owner_id) {
        // notify owner to transfer this page to requester
        return dms_notify_owner_for_res_r(ctx, req_info);
    }

    // this instance is owner, transfer local page, and requester must be on another instance
    int ret = dms_transfer_res_owner(ctx, req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][owner transfer page]: failed, dst_id=%u, dst_sid=%u, dst_rsn=%llu, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type),
            (uint32)req_info->req_id, (uint32)req_info->req_sid, req_info->req_rsn, (uint32)req_info->req_mode);
    }
    return ret;
}

static int dms_send_req2owner(dms_process_context_t *ctx, dms_ask_res_req_t *req_msg, drc_req_owner_result_t *result)
{
    dms_res_req_info_t req_info;
    req_info.owner_id = result->curr_owner_id;
    req_info.req_id   = req_msg->head.src_inst;
    req_info.req_sid  = req_msg->head.src_sid;
    req_info.req_rsn  = req_msg->head.rsn;
    req_info.curr_mode = req_msg->curr_mode;
    req_info.req_mode  = req_msg->req_mode;
    req_info.has_share_copy = result->has_share_copy;
    req_info.sess_type = req_msg->sess_type;
    req_info.res_type = req_msg->res_type;
    req_info.is_try   = req_msg->is_try;
    req_info.len      = req_msg->len;
    req_info.ver      = result->ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, req_msg->resid, req_info.len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(req_msg->resid, req_msg->res_type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }
    return dms_notify_owner_for_res(ctx, &req_info);
}

void dms_handle_remote_req_result(dms_process_context_t *ctx, dms_ask_res_req_t *req, drc_req_owner_result_t *result)
{
    switch (result->type) {
        case DRC_REQ_OWNER_GRANTED:
            dms_send_requester_granted(ctx, req);
            break;

        case DRC_REQ_OWNER_ALREADY_OWNER:
            dms_send_requester_already_owner(ctx, req);
            break;

        case DRC_REQ_OWNER_WAITING:
            // do nothing.
            LOG_DEBUG_INF("[DMS][%s][waiting for converting]: dst_id=%u, dst_sid=%u, req_mode=%u, curr_mode=%u",
                cm_display_resid(req->resid, req->res_type),
                (uint32)req->head.src_inst, (uint32)req->head.src_sid, (uint32)req->req_mode, (uint32)req->curr_mode);
            break;

        case DRC_REQ_OWNER_CONVERTING:
            LOG_DEBUG_INF("[DMS][%s][waiting for converting]: dst_id=%u, dst_sid=%u, req_mode=%u, curr_mode=%u",
                cm_display_resid(req->resid, req->res_type),
                (uint32)req->head.src_inst, (uint32)req->head.src_sid, (uint32)req->req_mode, (uint32)req->curr_mode);
            (void)dms_send_req2owner(ctx, req, result);
            break;

        case DRC_REQ_EDP_LOCAL:
            dcs_send_requester_edp_local(ctx, req);
            break;

        case DRC_REQ_EDP_REMOTE:
            (void)dcs_send_requester_edp_remote(ctx, req, result);
            break;

        default:
            CM_ASSERT(0);
    }
}

void dms_proc_ask_master_for_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE, CM_TRUE);
    dms_ask_res_req_t req = *(dms_ask_res_req_t *)(receive_msg->buffer);
    mfc_release_message_buf(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE ||
        req.curr_mode >= DMS_LOCK_MODE_MAX ||
        req.req_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_ask_master_for_res]: invalid req message");
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_master_for_res]: src_id=%d, src_sid=%d, req_mode=%u, curr_mode=%u",
        cm_display_resid(req.resid, req.res_type),
        req.head.src_inst, req.head.src_sid, req.req_mode, req.curr_mode);

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, req.head.src_inst, req.head.src_sid,
        req.head.rsn, req.curr_mode, req.req_mode, req.is_try, req.sess_type, req.ver);

    drc_req_owner_result_t result;
    int ret = drc_request_page_owner(req.resid, req.len, req.res_type, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id, req_info.inst_id, req_info.sess_id, req_info.rsn, ret);
        return;
    }

    if (result.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(req.resid, req.res_type), result.invld_insts);
        ret = dms_invalidate_share_copy(proc_ctx->inst_id, proc_ctx->sess_id, req.resid,
            req.len, req.res_type, result.invld_insts, req.sess_type, result.ver, NULL);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                req_info.inst_id, req_info.sess_id, req_info.rsn, ret);
            return;
        }
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_master_for_res], result type=%u",
        cm_display_resid(req.resid, req.res_type), result.type);

    dms_handle_remote_req_result(proc_ctx, &req, &result);
}

void dms_proc_ask_owner_for_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE, CM_TRUE);
    dms_ask_res_req_t req = *(dms_ask_res_req_t *)(receive_msg->buffer);
    mfc_release_message_buf(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE ||
        req.curr_mode >= DMS_LOCK_MODE_MAX ||
        req.req_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_ask_owner_for_res]: invalid req message");
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_owner_for_res]: started, owner_id=%u, req_id=%u, "
        "req_sid=%u, req_rsn=%llu, mode=%u, has_share_copy=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)proc_ctx->inst_id, (uint32)req.head.src_inst,
        (uint32)req.head.src_sid, req.head.rsn, (uint32)req.req_mode, (uint32)req.has_share_copy);

    dms_res_req_info_t req_info;
    req_info.owner_id = req.head.dst_inst;
    req_info.req_id   = req.head.src_inst;
    req_info.req_sid  = req.head.src_sid;
    req_info.curr_mode = req.curr_mode;
    req_info.req_mode  = req.req_mode;
    req_info.has_share_copy = req.has_share_copy;
    req_info.req_rsn = req.head.rsn;
    req_info.sess_type = DMS_SESSION_NORMAL;
    req_info.res_type = req.res_type;
    req_info.is_try   = req.is_try;
    req_info.len      = req.len;
    req_info.ver      = req.ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, req.resid, req_info.len);
    DMS_SECUREC_CHECK(ret);
    ret = dms_transfer_res_owner(proc_ctx, &req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][owner transfer page]: failed, owner_id=%u, req_id=%u, req_sid=%u, "
            "req_rsn=%llu, mode=%u", cm_display_resid(req.resid, req.res_type), (uint32)req_info.owner_id,
            (uint32)req_info.req_id, (uint32)req_info.req_sid, req_info.req_rsn, (uint32)req_info.req_mode);
    }
}

void dms_proc_invld_req(dms_process_context_t *proc_ctx, mes_message_t *receive_msg)
{
    dms_begin_stat(proc_ctx->sess_id, DMS_EVT_DCS_INVLDT_SHARE_COPY_PROCESS, CM_TRUE);

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_invld_req_t), CM_TRUE, CM_TRUE);
    dms_invld_req_t req = *(dms_invld_req_t *)(receive_msg->buffer);
    mfc_release_message_buf(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_invld_req]: invalid req message");
        return;
    }

    dms_invld_ack_t ack;
    mfc_init_ack_head(&(req.head), &ack.head, MSG_ACK_INVLD_OWNER, sizeof(dms_invld_ack_t), proc_ctx->sess_id);
    LOG_DEBUG_INF("[DMS][%s][dms_proc_invld_req]: src_id=%u, src_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst, (uint32)req.head.src_sid);

    int32 ret = DMS_SUCCESS;
    if (req.res_type == DRC_RES_PAGE_TYPE) {
        ret = g_dms.callback.invld_share_copy(proc_ctx->db_handle, req.resid, req.ver);
    } else {
        ret = dls_invld_lock_ownership(req.resid, DMS_LOCK_EXCLUSIVE, req.is_try, req.ver);
    }
    ack.err_code = ret;
    if (mfc_send_data(&ack.head) == DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_invld_req]: finished, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid);
    } else {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_invld_req]: failed to send ack, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid);
    }
    dms_end_stat(proc_ctx->sess_id);
}

static int dms_try_notify_owner_for_res(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    dms_res_req_info_t req_info;
    req_info.owner_id = cvt_info->owner_id;
    req_info.req_id   = cvt_info->req_id;
    req_info.req_sid  = (uint16)(cvt_info->req_sid);
    req_info.req_rsn  = cvt_info->req_rsn;
    req_info.curr_mode = cvt_info->curr_mode;
    req_info.req_mode  = cvt_info->req_mode;
    req_info.has_share_copy = cvt_info->has_share_copy;
    req_info.sess_type = DMS_SESSION_NORMAL;
    req_info.res_type    = cvt_info->res_type;
    req_info.is_try      = cvt_info->is_try;
    req_info.len         = cvt_info->len;
    req_info.ver         = cvt_info->ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, cvt_info->resid, cvt_info->len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(cvt_info->resid, cvt_info->res_type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    ret = dms_notify_owner_for_res(ctx, &req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][notify owner transfer page]: failed, owner_id=%u, req_id=%u, "
            "req_sid=%u, req_rsn=%llu, req_mode=%u, curr_mode=%u",
            cm_display_resid(req_info.resid, req_info.res_type), (uint32)req_info.owner_id, (uint32)req_info.req_id,
            (uint32)req_info.req_sid, req_info.req_rsn, (uint32)req_info.req_mode, (uint32)req_info.curr_mode);
    }
    return ret;
}

static int32 dms_notify_already_owner(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    mes_message_head_t head;
    DMS_INIT_MESSAGE_HEAD(&head, MSG_ACK_ALREADY_OWNER,
        0, ctx->inst_id, cvt_info->req_id, ctx->sess_id, cvt_info->req_sid);
    head.rsn = cvt_info->req_rsn;
    head.size = sizeof(mes_message_head_t);
    if (mfc_send_data(&head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(cvt_info->resid, cvt_info->res_type), dms_get_mescmd_msg(head.cmd), (uint32)head.src_inst,
            (uint32)head.src_sid, (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)cvt_info->req_mode);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send ok, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(cvt_info->resid, cvt_info->res_type), dms_get_mescmd_msg(head.cmd), (uint32)head.src_inst,
        (uint32)head.src_sid, (uint32)head.dst_inst, (uint32)head.dst_sid, (uint32)cvt_info->req_mode);
    return CM_SUCCESS;
}

static int32 dms_notify_granted_directly(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    // this page not in memory of other instance, notify requester to load from disk
    dms_ask_res_ack_ld_t ack;
    DMS_INIT_MESSAGE_HEAD(&ack.head, MSG_ACK_GRANT_OWNER,
        0, ctx->inst_id, cvt_info->req_id, ctx->sess_id, cvt_info->req_sid);
    ack.head.rsn  = cvt_info->req_rsn;
    ack.head.size = sizeof(dms_ask_res_ack_ld_t);

#ifndef OPENGAUSS
    if (cvt_info->res_type == DRC_RES_PAGE_TYPE) {
        ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
        ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
    }
#endif
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][ASK MASTER]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(cvt_info->resid, cvt_info->res_type), (uint32)ack.head.src_inst,
            (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)cvt_info->req_mode);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[DMS][%s][ASK MASTER]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(cvt_info->resid, cvt_info->res_type), (uint32)ack.head.src_inst,
        (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)cvt_info->req_mode);
    return CM_SUCCESS;
}

static void dms_handle_cvt_info(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    int ret;

    if (!DCS_INSTID_VALID(cvt_info->req_id)) {
        // no converting, just return
        return;
    }

    switch (cvt_info->type) {
        case DRC_REQ_OWNER_CONVERTING:
            ret = dms_try_notify_owner_for_res(ctx, cvt_info);
            break;
        case DRC_REQ_OWNER_ALREADY_OWNER:
            ret = dms_notify_already_owner(ctx, cvt_info);
            break;
        case DRC_REQ_OWNER_GRANTED:
            ret = dms_notify_granted_directly(ctx, cvt_info);
            break;
        default:
            ret = CM_ERROR;
    }

    if (ret != DMS_SUCCESS) {
        dms_send_error_ack(ctx->inst_id, ctx->sess_id, cvt_info->req_id, cvt_info->req_sid, cvt_info->req_rsn, ret);
    }
}

void dms_proc_claim_ownership_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_claim_owner_req_t), CM_TRUE, CM_FALSE);
    dms_claim_owner_req_t *request = (dms_claim_owner_req_t *)(receive_msg->buffer);
    cvt_info_t cvt_info;
    claim_info_t claim_info;

    if (SECUREC_UNLIKELY(request->req_mode >= DMS_LOCK_MODE_MAX || request->len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_claim_ownership_req]: invalid req message");
        mfc_release_message_buf(receive_msg);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, req_mode=%u",
        cm_display_resid(request->resid, request->res_type), "claim owner", (uint32)request->head.src_inst,
        (uint32)request->head.src_sid, (uint32)request->head.dst_inst, (uint32)request->head.dst_sid,
        (uint32)request->has_edp, (uint32)request->req_mode);

    // call drc interface to claim ownership
    (void)dms_set_claim_info(&claim_info, request->resid, request->len, (uint8)request->res_type,
        request->head.src_inst, request->req_mode, (bool8)request->has_edp, request->lsn, request->head.src_sid,
        request->ver, request->head.rsn, request->sess_type);

    if (drc_claim_page_owner(&claim_info, &cvt_info) != DMS_SUCCESS) {
        mfc_release_message_buf(receive_msg);
        return;
    }

    mfc_release_message_buf(receive_msg);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(request->resid, request->res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(process_ctx->inst_id, process_ctx->sess_id, cvt_info.resid,
            cvt_info.len, cvt_info.res_type, cvt_info.invld_insts, request->sess_type, cvt_info.ver, NULL);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(process_ctx->inst_id, process_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_rsn, ret);
            return;
        }
    }
    dms_handle_cvt_info(process_ctx, &cvt_info);
}

void dms_cancel_request_res(dms_context_t *dms_ctx)
{
    uint8 master_id;
    int32 ret = drc_get_master_id(dms_ctx->resid, dms_ctx->type, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s] notify master cancel req: get master id failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return;
    }

    dms_cancel_request_res_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_CANCEL_REQUEST_RES, 0,
        dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_cancel_request_res_t);
    req.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
    req.len = dms_ctx->len;
    req.res_type = (uint8)dms_ctx->type;
    req.sess_type = dms_ctx->sess_type;
    ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, dms_ctx->len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        LOG_DEBUG_ERR("[DMS][%s] notify master cancel request res: system call failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return;
    }
    ret = mfc_send_data(&req.head);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s] notify master cancel request res: send msg failed, src_id=%u, src_sid=%u, dest_id=%u",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), (uint32)req.head.src_inst,
            (uint32)req.head.src_sid, (uint32)req.head.dst_inst);
        return;
    }
    LOG_DEBUG_INF("[DMS][%s] notify master cancel request res successfully, src_id=%u, src_sid=%u, dest_id=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid, (uint32)req.head.dst_inst);
}

void dms_proc_cancel_request_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_cancel_request_res_t), CM_TRUE, CM_FALSE);
    dms_cancel_request_res_t req = *(dms_cancel_request_res_t*)receive_msg->buffer;
    mfc_release_message_buf(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_cancel_request_res]invalid cancel request res message");
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_cancel_request_res], src_id=%u, src_sid=%u, dest_id=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid, (uint32)req.head.dst_inst);

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, req.head.src_inst, req.head.src_sid, req.head.rsn, 0, 0, CM_FALSE, req.sess_type, 0);

    cvt_info_t cvt_info;
    drc_cancel_request_res(req.resid, req.len, req.res_type, &req_info, &cvt_info);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(req.resid, req.res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx->inst_id, proc_ctx->sess_id, cvt_info.resid,
            cvt_info.len, cvt_info.res_type, cvt_info.invld_insts, CM_FALSE, cvt_info.ver, NULL);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_rsn, ret);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

void dms_proc_confirm_cvt_req(dms_process_context_t *proc_ctx, mes_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_confirm_cvt_req_t), CM_TRUE, CM_FALSE);
    dms_confirm_cvt_req_t req = *(dms_confirm_cvt_req_t *)(receive_msg->buffer);
    mfc_release_message_buf(receive_msg);

    int32 ret;
    uint8 lock_mode;
    dms_confirm_cvt_ack_t ack;
    if (memset_s(&ack, sizeof(dms_confirm_cvt_ack_t), 0, sizeof(dms_confirm_cvt_ack_t)) != EOK) {
        cm_panic(0);
    }
    mfc_init_ack_head(&(req.head), &ack.head, MSG_ACK_CONFIRM_CVT, sizeof(dms_confirm_cvt_ack_t), proc_ctx->sess_id);
    LOG_DEBUG_INF("[DMS][%s][dms_proc_confirm_cvt_req]: src_id=%u, src_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst, (uint32)req.head.src_sid);

    if (req.res_type == DRC_RES_PAGE_TYPE) {
        ret = g_dms.callback.confirm_converting(proc_ctx->db_handle,
            req.resid, CM_TRUE, &lock_mode, &ack.edp_map, &ack.lsn, &ack.ver);
    } else {
        ret = drc_confirm_converting(req.resid, CM_TRUE, &lock_mode, &ack.ver);
    }
    if (ret != DMS_SUCCESS) {
        ack.result = CONFIRM_NONE;
    } else {
        ack.lock_mode = lock_mode;
        ack.result = (lock_mode >= req.cvt_mode) ? CONFIRM_READY : CONFIRM_CANCEL;
    }

    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_confirm_cvt_req]: failed to send ack, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid);
        return;
    }
    LOG_DEBUG_INF("[DMS][%s][dms_proc_confirm_cvt_req]: send ack ok, dst_id=%u, dst_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid);
}

static int32 dms_smon_send_confirm_req(res_id_t *res_id, drc_request_info_t *cvt_req)
{
    dms_confirm_cvt_req_t req;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_CONFIRM_CVT, 0,
        g_dms.inst_id, cvt_req->inst_id, ctx->smon_sid, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_confirm_cvt_req_t);
    req.head.rsn = mes_get_rsn(ctx->smon_sid);
    req.res_type = res_id->type;
    req.cvt_mode = cvt_req->req_mode;
    errno_t err = memcpy_s(req.resid, DMS_RESID_SIZE, res_id->data, res_id->len);
    DMS_SECUREC_CHECK(err);
    if (mfc_send_data(&req.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS]dms_smon_send_confirm_req send error, dst_id: %d", cvt_req->inst_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    LOG_DEBUG_INF("[DMS]dms_smon_send_confirm_req send ok dst_id: %d", cvt_req->inst_id);
    return DMS_SUCCESS;
}

static inline bool32 dms_the_same_drc_req(drc_request_info_t *req1, drc_request_info_t *req2)
{
    if (req1->inst_id == req2->inst_id &&
        req1->curr_mode == req2->curr_mode &&
        req1->req_mode == req2->req_mode &&
        req1->sess_id == req2->sess_id &&
        req1->rsn == req2->rsn) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static void dms_smon_handle_ready_ack(dms_process_context_t *proc_ctx,
    drc_buf_res_t *buf_res, drc_request_info_t *cvt_req, dms_confirm_cvt_ack_t *ack)
{
    if (!dms_the_same_drc_req(&buf_res->converting.req_info, cvt_req)) {
        return;
    }

    bool32 has_edp = CM_FALSE;
    if (buf_res->claimed_owner != CM_INVALID_ID8) {
        has_edp = bitmap64_exist(&ack->edp_map, buf_res->claimed_owner);
    }
    claim_info_t claim_info;
    (void)dms_set_claim_info(&claim_info, buf_res->data, buf_res->len, buf_res->type, cvt_req->inst_id,
        ack->lock_mode, (bool8)has_edp, ack->lsn, cvt_req->sess_id, ack->ver, cvt_req->rsn, DMS_SESSION_NORMAL);

    cvt_info_t cvt_info;
    if (drc_convert_page_owner(buf_res, &claim_info, &cvt_info) != DMS_SUCCESS) {
        return;
    }
    LOG_DEBUG_INF("[DMS][%s][dms_smon_handle_ready_ack]: mode=%u, claimed_owner=%u, edp_map=%llu, copy_insts=%llu",
        cm_display_resid(claim_info.resid, claim_info.res_type), (uint32)buf_res->lock_mode,
        (uint32)buf_res->claimed_owner, buf_res->edp_map, buf_res->copy_insts);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(claim_info.resid, claim_info.res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx->inst_id, proc_ctx->sess_id, cvt_info.resid,
            cvt_info.len, cvt_info.res_type, cvt_info.invld_insts, CM_FALSE, cvt_info.ver, buf_res);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_rsn, ret);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

static void dms_smon_handle_cancel_ack(dms_process_context_t *proc_ctx, drc_buf_res_t *buf_res,
    drc_request_info_t *cvt_req)
{
    if (!dms_the_same_drc_req(&buf_res->converting.req_info, cvt_req)) {
        return;
    }

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, cvt_req->inst_id, cvt_req->sess_id, cvt_req->rsn, 0, 0,
        CM_FALSE, CM_FALSE, buf_res->ver);

    cvt_info_t cvt_info;
    cvt_info.invld_insts = 0;
    cvt_info.req_id = CM_INVALID_ID8;
    
    (void)drc_cancel_converting(buf_res, &req_info, &cvt_info);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(buf_res->data, buf_res->type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx->inst_id, proc_ctx->sess_id, cvt_info.resid,
            cvt_info.len, cvt_info.res_type, cvt_info.invld_insts, CM_FALSE, cvt_info.ver, buf_res);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_rsn, ret);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

static void dms_smon_handle_confirm_ack(res_id_t *res_id, drc_request_info_t *cvt_req)
{
    mes_message_t msg;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    int32 ret = mfc_allocbuf_and_recv_data((uint16)ctx->smon_sid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: wait ack timeout, src_id=%u, src_sid=%u, dst_id=%u",
            cm_display_resid(res_id->data, res_id->type), "CONFIRM CVT", (uint32)g_dms.inst_id,
            (uint32)ctx->smon_sid, (uint32)cvt_req->inst_id);
        return;
    }
    dms_confirm_cvt_ack_t ack = *(dms_confirm_cvt_ack_t*)msg.buffer;
    mfc_release_message_buf(&msg);

    LOG_DEBUG_INF("[DMS][%s] recv confirm ack [result:%u edp_map:%llu lsn:%llu]",
        cm_display_resid(res_id->data, res_id->type), (uint32)ack.result, ack.edp_map, ack.lsn);

    if (ack.result == CONFIRM_NONE) {
        return;
    }

    /* page request will be infinite loop until success in db layer */
    if (res_id->type == DRC_RES_PAGE_TYPE && ack.result == CONFIRM_CANCEL) {
        return;
    }

    dms_process_context_t proc_ctx;
    proc_ctx.inst_id = (uint8)g_dms.inst_id;
    proc_ctx.sess_id = DRC_RES_CTX->smon_sid;
    proc_ctx.db_handle = DRC_RES_CTX->smon_handle;

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, CM_TRUE);
    ret = drc_enter_buf_res(res_id->data, res_id->len, res_id->type, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        return;
    }

    if (ack.result == CONFIRM_READY) {
        dms_smon_handle_ready_ack(&proc_ctx, buf_res, cvt_req, &ack);
    } else {
        dms_smon_handle_cancel_ack(&proc_ctx, buf_res, cvt_req);
    }
    drc_leave_buf_res(buf_res);
}

static void dms_smon_confirm_converting(res_id_t *res_id)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, CM_TRUE);
    int ret = drc_enter_buf_res(res_id->data, res_id->len, res_id->type, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        return;
    }

    if (!if_cvt_need_confirm(buf_res) || buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        drc_leave_buf_res(buf_res);
        return;
    }
    buf_res->converting.begin_time = g_timer()->now;
    drc_request_info_t cvt_req = buf_res->converting.req_info;
    drc_leave_buf_res(buf_res);

    LOG_DEBUG_WAR("[DMS][%s] start confirm converting [inst:%u sid:%u rsn:%llu req_mode:%u]",
        cm_display_resid(res_id->data, res_id->type), (uint32)cvt_req.inst_id,
        (uint32)cvt_req.sess_id, cvt_req.rsn, (uint32)cvt_req.req_mode);

    if (dms_smon_send_confirm_req(res_id, &cvt_req) != DMS_SUCCESS) {
        return;
    }

    dms_smon_handle_confirm_ack(res_id, &cvt_req);
}

void dms_smon_entry(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    res_id_t res_id;

    while (!thread->closed) {
        if (cm_chan_recv_timeout(DRC_RES_CTX->chan, (void *)&res_id, DMS_MSG_SLEEP_TIME) != CM_SUCCESS) {
            continue;
        }
        dms_smon_confirm_converting(&res_id);
    }
}

#ifdef __cplusplus
}
#endif