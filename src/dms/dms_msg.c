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

#include "dms_process.h"
#include "dms_cm.h"
#include "dms_error.h"
#include "drc_page.h"
#include "dls_msg.h"
#include "dcs_page.h"
#include "dms_stat.h"
#include "dms_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

void cm_send_error_msg(dms_message_head_t *head, int32 err_code, char *err_info)
{
    msg_error_t msg_error;

    dms_init_ack_head(head, &msg_error.head, MSG_ACK_ERROR, (uint16)(sizeof(msg_error_t) + strlen(err_info) + 1),
        CM_INVALID_ID32);
    msg_error.code = err_code;

    if (mfc_send_data3(&msg_error.head, sizeof(msg_error_t), err_info) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send error msg to instance %d failed.", head->src_inst);
    }
}

void cm_ack_result_msg(dms_process_context_t *process_ctx, dms_message_t *receive_msg, uint32 cmd, int32 ret)
{
    dms_common_ack_t ack_msg;
    dms_init_ack_head(receive_msg->head, &ack_msg.head, cmd, sizeof(dms_common_ack_t), process_ctx->sess_id);
    ack_msg.ret = ret;

    dms_release_recv_message(receive_msg);
    if (mfc_send_data(&ack_msg.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send result msg to instance %d failed.", receive_msg->head->src_inst);
    }

    return;
}

void cm_ack_result_msg2(dms_process_context_t *process_ctx, dms_message_t *receive_msg, uint32 cmd, char *msg,
    uint32 len, char *ack_buf)
{
    uint8 *send_msg = (uint8 *)ack_buf;
    dms_message_head_t *head = (dms_message_head_t *)ack_buf;

    dms_init_ack_head2(head, cmd, 0, receive_msg->head->dst_inst, receive_msg->head->src_inst,
        (uint16)process_ctx->sess_id, receive_msg->head->src_sid, receive_msg->head->msg_proto_ver);
    head->size = (uint16)(sizeof(dms_message_head_t) + len);
    head->ruid = receive_msg->head->ruid;
    int ret = memcpy_s(send_msg + sizeof(dms_message_head_t), len, msg, len);
    DMS_SECUREC_CHECK(ret);

    dms_release_recv_message(receive_msg);
    if (mfc_send_data(head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send result msg to instance %d failed.", receive_msg->head->src_inst);
    }
    return;
}

void dms_send_error_ack(uint32 src_inst, uint32 src_sid, uint8 dst_inst, uint32 dst_sid, uint64 dst_ruid, int32 code,
    uint32 req_proto_ver)
{
    int32 ret;
    msg_error_t msg_error;
    const char *errmsg = cm_get_errormsg(code);

    dms_init_ack_head2(&msg_error.head, MSG_ACK_ERROR, 0, (uint8)src_inst, dst_inst,
        (uint16)src_sid, (uint16)dst_sid, req_proto_ver);
    msg_error.code      = code;
    msg_error.head.ruid  = dst_ruid;

    if (strlen(errmsg) == 0) {
        msg_error.head.size = (uint16)sizeof(msg_error_t);
        ret = mfc_send_data(&msg_error.head);
    } else {
        msg_error.head.size = (uint16)(sizeof(msg_error_t) + strlen(errmsg) + 1);
        ret = mfc_send_data3(&msg_error.head, sizeof(msg_error_t), errmsg);
    }
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("send error msg to instance %u failed.", dst_sid);
    }
}

static uint64 dms_send_invalidate_req(dms_process_context_t *ctx, char *resid, uint16 len,
    uint8 type, uint64 invld_insts, dms_session_e sess_type, bool8 is_try)
{
    dms_invld_req_t req;
    uint64 succ_insts;

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_INVALIDATE_SHARE_COPY, 0, ctx->inst_id, 0, ctx->sess_id, CM_INVALID_ID16);
    req.head.size   = (uint16)sizeof(dms_invld_req_t);
    req.len         = len;
    req.is_try      = is_try;
    req.res_type    = type;
    req.sess_type   = sess_type;
    req.invld_owner = CM_FALSE;
    if (memcpy_sp(req.resid, DMS_RESID_SIZE, resid, len) != EOK) {
        LOG_DEBUG_ERR("[DMS][%s]: system call failed", cm_display_resid(resid, type));
        return 0;
    }

    mfc_broadcast(invld_insts, (void *)&req, &succ_insts);
    if (succ_insts != invld_insts) {
        LOG_DEBUG_ERR("[DMS][%s]:send failed, invld_insts=%llu, succ_insts=%llu",
            cm_display_resid(req.resid, req.res_type), invld_insts, succ_insts);
        return 0;
    }

    LOG_DEBUG_INF("[DMS][%s]:send ok invld_insts=%llu, succ_insts=%llu",
        cm_display_resid(req.resid, req.res_type), invld_insts, succ_insts);
    return req.head.ruid;
}

static inline int32 dms_handle_invalidate_ack(dms_process_context_t *ctx, uint64 invld_insts,
    uint64 ruid, uint64 *succ_insts)
{
    int32 ret = mfc_get_broadcast_res_with_succ_insts(ruid, (uint32)DMS_WAIT_MAX_TIME, invld_insts, succ_insts);
    dms_end_stat(ctx->sess_id);
    return ret;
}

int32 dms_invalidate_ownership(dms_process_context_t *ctx, char* resid, uint16 len,
    uint8 type, dms_session_e sess_type, uint8 owner_id)
{
    cm_panic(type == DRC_RES_PAGE_TYPE);
    if (ctx->inst_id == owner_id) {
        return g_dms.callback.invalidate_page(ctx->db_handle, resid, CM_TRUE);
    }
    dms_invld_req_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_INVALID_OWNER, 0, ctx->inst_id, owner_id, ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_invld_req_t);
    req.len = len;
    req.res_type = type;
    req.sess_type = sess_type;
    req.invld_owner = CM_TRUE;
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, resid, len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        LOG_DEBUG_ERR("[DMS][%s]: system call failed", cm_display_resid(resid, type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_INVLDT_SHARE_COPY_REQ, CM_TRUE);
    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        dms_end_stat(ctx->sess_id);
        LOG_DEBUG_ERR("[DMS][%s]: send to owner:%u failed",
            cm_display_resid(req.resid, req.res_type), (uint32)owner_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t msg = {0};
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        dms_end_stat(ctx->sess_id);
        LOG_DEBUG_ERR("[DMS][%s]:wait owner ack timeout timeout=%d ms",
            cm_display_resid(req.resid, req.res_type), DMS_WAIT_MAX_TIME);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }
    dms_common_ack_t ack = *(dms_common_ack_t*)msg.buffer;
    dms_release_recv_message(&msg);

    LOG_DEBUG_INF("[DMS][%s]: invalid owner:%u result:%d",
        cm_display_resid(req.resid, req.res_type), (uint32)owner_id, ack.ret);
    dms_end_stat(ctx->sess_id);
    return ack.ret;
}

static void drc_clean_share_copy_insts(char *resid, uint16 len, uint8 type, dms_session_e sess_type, uint64 owner_map)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 opts = drc_build_options(CM_FALSE, sess_type, CM_TRUE);
    if (drc_enter_buf_res(resid, len, type, opts, &buf_res) != DMS_SUCCESS || buf_res == NULL) {
        return;
    }
    buf_res->copy_insts = buf_res->copy_insts & (~owner_map);
    LOG_DEBUG_INF("[DMS][%s]: invld_owner_map=%llu, curr_copy_insts=%llu",
        cm_display_resid(resid, type), owner_map, buf_res->copy_insts);
    drc_leave_buf_res(buf_res);
}

static inline int32 dms_invalidate_res_l(dms_process_context_t *ctx, char *resid, uint8 type, bool8 is_try)
{
    int32 ret = DMS_SUCCESS;
    if (type == DRC_RES_PAGE_TYPE) {
        ret = g_dms.callback.invalidate_page(ctx->db_handle, resid, CM_FALSE);
    } else {
        ret = dls_invld_lock_ownership(ctx->db_handle, resid, DMS_LOCK_EXCLUSIVE, is_try);
    }
    return ret;
}

int32 dms_invalidate_share_copy(dms_process_context_t *ctx, char *resid, uint16 len,
    uint8 type, uint64 copy_insts, dms_session_e sess_type, bool8 is_try, bool8 can_direct)
{
    uint64 succ_insts = 0;
    bool32 invld_local = CM_FALSE;
    uint64 invld_insts = copy_insts;
    uint64 ruid = 0;
    int ret = DMS_SUCCESS;

    if (can_direct && bitmap64_exist(&invld_insts, (uint8)ctx->inst_id)) {
        invld_local = CM_TRUE;
        bitmap64_clear(&invld_insts, (uint8)ctx->inst_id);
    }

    if (invld_insts > 0) {
        dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_INVLDT_SHARE_COPY_REQ, CM_TRUE);
        ruid = dms_send_invalidate_req(ctx, resid, len, type, invld_insts, sess_type, is_try);
    }

    if (invld_local) {
        if (dms_invalidate_res_l(ctx, resid, type, is_try) == DMS_SUCCESS) {
            bitmap64_set(&succ_insts, (uint8)ctx->inst_id);
        }
    }

    if (invld_insts > 0) {
        uint64 tmp_result = 0;
        ret = dms_handle_invalidate_ack(ctx, invld_insts, ruid, &tmp_result);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        if (tmp_result > 0) {
            bitmap64_union(&succ_insts, tmp_result);
        }
    }

    if (succ_insts > 0) {
        drc_clean_share_copy_insts(resid, len, type, sess_type, succ_insts);
    }

    if (succ_insts != copy_insts) {
        LOG_DEBUG_ERR("[DMS][%s]: invalid failed, invld_insts=%llu, succ_insts=%llu",
            cm_display_resid(resid, type), copy_insts, succ_insts);
        return ERRNO_DMS_DCS_BROADCAST_FAILED;
    }
    return DMS_SUCCESS;
}

void dms_claim_ownership(dms_context_t *dms_ctx, uint8 master_id, dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn)
{
    dms_claim_owner_req_t request;
    DMS_INIT_MESSAGE_HEAD(&request.head,
        MSG_REQ_CLAIM_OWNER, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);
    request.head.size = (uint16)sizeof(dms_claim_owner_req_t);
    request.req_mode  = mode;
    request.has_edp   = has_edp;
    request.lsn       = page_lsn;
    request.sess_type = dms_ctx->sess_type;
    request.res_type  = dms_ctx->type;
    request.len       = dms_ctx->len;
    request.srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    int32 ret = memcpy_sp(request.resid, DMS_RESID_SIZE, dms_ctx->resid, request.len);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][%s][dms_claim_ownership]: system call failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return;
    }

    ret = mfc_send_data_async(&request.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: send failed, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, ruid=%llu",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(request.head.cmd),
            (uint32)request.head.src_inst, (uint32)request.head.src_sid, (uint32)request.head.dst_inst,
            (uint32)request.head.dst_sid, (bool32)request.has_edp, request.head.ruid);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: send ok, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, ruid=%llu",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(request.head.cmd),
        (uint32)request.head.src_inst, (uint32)request.head.src_sid, (uint32)request.head.dst_inst,
        (uint32)request.head.dst_sid, (bool32)request.has_edp, request.head.ruid);
}

static int32 dms_set_claim_info(claim_info_t *claim_info, char *resid, uint16 len, uint8 res_type, uint8 ownerid,
    dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn, uint32 sess_id, dms_session_e sess_type, uint32 srsn)
{
    claim_info->new_id   = ownerid;
    claim_info->has_edp  = has_edp;
    claim_info->lsn      = page_lsn;
    claim_info->req_mode = mode;
    claim_info->res_type = res_type;
    claim_info->len      = len;
    claim_info->sess_id  = sess_id;
    claim_info->sess_type = sess_type;
    claim_info->srsn = srsn;
    int ret = memcpy_s(claim_info->resid, DMS_RESID_SIZE, resid, len);
    if (ret == EOK) {
        return DMS_SUCCESS;
    }
    LOG_DEBUG_ERR("[DMS][%s][dms_set_claim_info]: system call failed", cm_display_resid(resid, res_type));
    return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
}

static inline int32 dms_handle_grant_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, dms_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_need_load(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_grant_owner_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static inline int32 dms_handle_already_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, dms_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_already_owner(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_already_owner_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static inline int32 dms_handle_res_ready_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, dms_message_t *msg)
{
    if (dms_ctx->type == DRC_RES_PAGE_TYPE) {
        return dcs_handle_ack_page_ready(dms_ctx, (dms_buf_ctrl_t *)res, master_id, msg, mode);
    }
    return dls_handle_lock_ready_ack(dms_ctx, (drc_local_lock_res_t*)res, master_id, msg, mode);
}

static int32 dms_handle_ask_owner_ack(dms_context_t *dms_ctx, void *res,
    uint8 master_id, dms_lock_mode_t mode, dms_message_t *msg)
{
    dms_message_head_t *ack_dms_head = get_dms_head(msg);
    if (ack_dms_head->cmd == MSG_ACK_PAGE_READY) {
        return dms_handle_res_ready_ack(dms_ctx, res, master_id, mode, msg);
    }

    if (ack_dms_head->cmd == MSG_ACK_GRANT_OWNER) {
        return dms_handle_grant_owner_ack(dms_ctx, res, master_id, mode, msg);
    }

    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        msg_error_t error_ack = *(msg_error_t*)msg->buffer;
        return error_ack.code;
    }
    LOG_DEBUG_ERR("[DMS][dms_handle_ask_owner_ack]recieve unexpected message,cmd:%u", (uint32)ack_dms_head->cmd);
    return ERRNO_DMS_MES_INVALID_MSG;
}

static int32 dms_ask_owner_for_res(dms_context_t *dms_ctx, void *res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, drc_req_owner_result_t *result)
{
    dms_ask_res_req_t req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&req.head,
        MSG_REQ_ASK_OWNER_FOR_PAGE, 0, dms_ctx->inst_id, result->curr_owner_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    req.req_mode  = req_mode;
    req.curr_mode = curr_mode;
    req.res_type  = dms_ctx->type;
    req.is_try    = (bool8)dms_ctx->is_try;
    req.len       = dms_ctx->len;
    req.sess_type = dms_ctx->sess_type;
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, req.len);
    if (ret != EOK) {
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
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DMS]%s][%s]: send ok, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(req.head.cmd),
        (uint32)req.head.src_inst, (uint32)req.head.src_sid, (uint32)req.head.dst_inst,
        (uint32)req.head.dst_sid, (uint32)req_mode);

    dms_message_t msg = {0};
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: wait ack timeout, src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, req_mode=%u, "
            "ret=%d",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), "ASK OWNER", (uint32)req.head.src_inst,
            (uint32)req.head.src_sid, (uint32)req.head.dst_inst, (uint32)req.head.dst_sid,
            (uint32)req_mode, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    ret = dms_handle_ask_owner_ack(dms_ctx, res, (uint8)dms_ctx->inst_id, req_mode, &msg);

    dms_release_recv_message(&msg);
    return ret;
}

static int32 dms_handle_ask_master_ack(dms_context_t *dms_ctx,
    void *res, uint8 master_id, dms_lock_mode_t mode, dms_wait_event_t *ack_event)
{
    if (ack_event) {
        *ack_event = DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY;
    }

    dms_message_t msg = {0};
    int32 ret = mfc_get_response(dms_ctx->ctx_ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_handle_ask_master_ack]:wait master ack timeout timeout=%d ms, ruid=%llu",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), DMS_WAIT_MAX_TIME, dms_ctx->ctx_ruid);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        return ERRNO_DMS_DCS_MSG_EAGAIN;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&msg);
    LOG_DEBUG_INF("[DMS][%s][%s]:src_id=%u, src_sid=%u, dst_id=%u, dst_sid =%u, flag=%u, ruid=%llu",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(ack_dms_head->cmd),
        (uint32)msg.head->src_inst, (uint32)msg.head->src_sid, (uint32)msg.head->dst_inst,
        (uint32)msg.head->dst_sid, (uint32)msg.head->flags, msg.head->ruid);

    switch (ack_dms_head->cmd) {
        case MSG_ACK_GRANT_OWNER:
            ret = dms_handle_grant_owner_ack(dms_ctx, res, master_id, mode, &msg);
            break;

        case MSG_ACK_ALREADY_OWNER:
            ret = dms_handle_already_owner_ack(dms_ctx, res, master_id, mode, &msg);
            break;

        case MSG_ACK_ERROR: {
            msg_error_t msg_error = *(msg_error_t*)msg.buffer;
            ret = msg_error.code;
            LOG_DEBUG_ERR("[DMS][%s][%s]:src_id=%u, src_sid=%u, dst_id=%u, dst_sid =%u, flag=%u, ruid=%llu, ret=%d",
                cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_get_mescmd_msg(ack_dms_head->cmd),
                (uint32)msg.head->src_inst, (uint32)msg.head->src_sid, (uint32)msg.head->dst_inst,
                (uint32)msg.head->dst_sid, (uint32)msg.head->flags, msg.head->ruid, ret);
            break;
        }
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
            LOG_DEBUG_ERR("[DMS][dms_handle_ask_master_ack]recieve unexpected message");
            ret = ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT;
            break;
    }

    dms_release_recv_message(&msg);
    return ret;
}

static int32 dms_handle_local_req_result(dms_context_t *dms_ctx, void *res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, drc_req_owner_result_t *result)
{
    int ret;

    if (result->type != DRC_REQ_OWNER_WAITING) {
        (void)mfc_get_response(dms_ctx->ctx_ruid, NULL, 0);
    }

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
    dms_lock_mode_t req_mode)
{
    uint8 req_id = (uint8)dms_ctx->inst_id;
    drc_req_owner_result_t result;

    mes_prepare_request(&dms_ctx->ctx_ruid); /* need to prepare for acutal sending */
    LOG_DEBUG_INF("[DMS][%s][ask master local]: src_id=%u, req_mode=%u, curr_mode=%u, prep_ruid=%llu",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id, (uint32)req_mode,
        (uint32)curr_mode, dms_ctx->ctx_ruid);

    uint32 srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    drc_request_info_t req_info;
    dms_set_req_info(&req_info, req_id, (uint16)dms_ctx->sess_id, dms_ctx->ctx_ruid,
        curr_mode, req_mode, dms_ctx->is_try, dms_ctx->sess_type, g_timer()->now, srsn);

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_1WAY, CM_TRUE);

    int32 ret = drc_request_page_owner(dms_ctx->resid, dms_ctx->len, dms_ctx->type, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        (void)mfc_get_response(dms_ctx->ctx_ruid, NULL, 0);
        dms_end_stat(dms_ctx->sess_id);
        return ret;
    }

    if (result.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), result.invld_insts);

        ret = dms_invalidate_share_copy(&dms_ctx->proc_ctx, dms_ctx->resid, dms_ctx->len,
            dms_ctx->type, result.invld_insts, dms_ctx->sess_type, dms_ctx->is_try, CM_FALSE);
        if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
            (void)mfc_get_response(dms_ctx->ctx_ruid, NULL, 0);
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
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode)
{
    dms_ask_res_req_t req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_MASTER_FOR_PAGE,
        0, dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);

    req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    req.req_mode  = req_mode;
    req.curr_mode = curr_mode;
    req.sess_type = dms_ctx->sess_type;
    req.is_try    = dms_ctx->is_try;
    req.res_type  = dms_ctx->type;
    req.len       = dms_ctx->len;
    req.req_time  = g_timer()->now;
    req.srsn      = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    int32 ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, dms_ctx->len);

    dms_ctx->ctx_ruid = 0;
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][%s] system call failed", cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    LOG_DEBUG_INF("[DMS][%s][ASK MASTER]: src_id=%u, dst_id=%u, req_mode=%u, curr_mode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id,
        (uint32)master_id, (uint32)req_mode, (uint32)curr_mode);


    if (mfc_send_data(&req.head) == DMS_SUCCESS) {
        dms_ctx->ctx_ruid = req.head.ruid;
        return DMS_SUCCESS;
    }

    LOG_DEBUG_ERR("failed to send ask master request. Try again later");
    return ERRNO_DMS_DCS_MSG_EAGAIN;
}

static int32 dms_ask_master4res_r(dms_context_t *dms_ctx, void *res, uint8 master_id, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode)
{
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY, CM_TRUE);

    int32 ret = dms_send_ask_master_req(dms_ctx, master_id, curr_mode, mode);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY);
        return ret;
    }

    dms_wait_event_t event = DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY;
    ret = dms_handle_ask_master_ack(dms_ctx, res, master_id, mode, &event);

    dms_end_stat_ex(dms_ctx->sess_id, event);
    return ret;
}

int32 dms_request_res_internal(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode)
{
    uint8 master_id;
    int32 ret = drc_get_master_id(dms_ctx->resid, dms_ctx->type, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        ret = dms_ask_master4res_l(dms_ctx, res, curr_mode, req_mode);
    } else {
        ret = dms_ask_master4res_r(dms_ctx, res, master_id, curr_mode, req_mode);
    }
    return ret;
}

static int32 dms_send_ask_res_owner_id_req(dms_context_t *dms_ctx, uint8 master_id, uint64 *ruid)
{
    dms_ask_res_owner_id_req_t req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_RES_OWNER_ID,
        0, dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);

    req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    req.sess_type = dms_ctx->sess_type;
    req.res_type  = dms_ctx->type;
    req.len       = dms_ctx->len;
    errno_t ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, dms_ctx->len);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][%s] system call failed", cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    LOG_DEBUG_INF("[DMS][%s][ASK OWNER ID]: src_id=%u, dst_id=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), dms_ctx->inst_id, (uint32)master_id);


    ret = mfc_send_data(&req.head);
    *ruid = req.head.ruid;
    return ret;
}

int32 dms_ask_res_owner_id_r(dms_context_t *dms_ctx, uint8 master_id, uint8 *owner_id)
{
    *owner_id = CM_INVALID_ID8;
    uint64 ruid = 0;
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_QUERY_OWNER_ID, CM_TRUE);
    int32 ret = dms_send_ask_res_owner_id_req(dms_ctx, master_id, &ruid);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_QUERY_OWNER_ID);
        return ret;
    }

    dms_message_t msg = {0};
    ret = mfc_get_response(ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_QUERY_OWNER_ID);
        LOG_DEBUG_ERR("[DMS][%s][dms_ask_res_owner_id_r]: wait owner ack timeout timeout=%d ms",
            cm_display_resid(dms_ctx->resid, dms_ctx->type), DMS_WAIT_MAX_TIME);
        return ret;
    }

    dms_message_head_t *ack_dms_head = get_dms_head(&msg);
    if (ack_dms_head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, msg.buffer + sizeof(msg_error_t));
        dms_release_recv_message(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RECV_MSG_SIZE(&msg, (uint32)sizeof(dms_ask_res_owner_id_ack_t), CM_FALSE, CM_FALSE);
    dms_ask_res_owner_id_ack_t *ack = (dms_ask_res_owner_id_ack_t *)msg.buffer;
    *owner_id = ack->owner_id;

    dms_release_recv_message(&msg);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_QUERY_OWNER_ID);
    return DMS_SUCCESS;
}

static void dms_send_requester_granted(dms_process_context_t *ctx, dms_ask_res_req_t *req)
{
    // this page not in memory of other instance, notify requester to load from disk
    dms_ask_res_ack_ld_t ack;
    dms_init_ack_head(&req->head, &ack.head, MSG_ACK_GRANT_OWNER, sizeof(dms_ask_res_ack_ld_t), ctx->sess_id);
    ack.head.ruid = req->head.ruid;
    ack.master_grant = CM_TRUE; /* master may grant first-time request X, since there's no sharer */
#ifndef OPENGAUSS
    if (req->res_type == DRC_RES_PAGE_TYPE) {
        ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
        ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
    }
#endif
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd),
            (uint32)ack.head.src_inst, (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst,
            (uint32)ack.head.dst_sid, (uint32)req->req_mode);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd),
        (uint32)ack.head.src_inst, (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst,
        (uint32)ack.head.dst_sid, (uint32)req->req_mode);
}

static void dms_send_requester_already_owner(dms_process_context_t *ctx, dms_ask_res_req_t *req)
{
    // asker is already owner, just notify requester(owner) page is ready
    dms_message_head_t head;
    dms_init_ack_head(&req->head, &head, MSG_ACK_ALREADY_OWNER, sizeof(dms_message_head_t), ctx->sess_id);
    if (mfc_send_data(&head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd),
            (uint32)head.src_inst, (uint32)head.src_sid, (uint32)head.dst_inst,
            (uint32)head.dst_sid, (uint32)req->req_mode);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send ok, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(req->resid, req->res_type), dms_get_mescmd_msg(req->head.cmd),
        (uint32)head.src_inst, (uint32)head.src_sid, (uint32)head.dst_inst,
        (uint32)head.dst_sid, (uint32)req->req_mode);
}

static int dms_notify_owner_for_res_r(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    int ret;

    if (req_info->owner_id != req_info->req_id) {
        dms_ask_res_req_t req = { 0 };
        uint32 send_proto_ver = dms_get_forward_request_proto_version(req_info->owner_id, req_info->req_proto_ver);
        DMS_INIT_MESSAGE_HEAD2(&req.head, MSG_REQ_ASK_OWNER_FOR_PAGE, 0,
            req_info->req_id, req_info->owner_id, req_info->req_sid, CM_INVALID_ID16,
            send_proto_ver, (uint16)sizeof(dms_ask_res_req_t));
        req.req_mode  = req_info->req_mode;
        req.curr_mode = req_info->curr_mode;
        req.sess_type = req_info->sess_type;
        req.res_type = req_info->res_type;
        req.is_try = req_info->is_try;
        req.len = (uint16)req_info->len;
        ret = memcpy_sp(req.resid, DMS_RESID_SIZE, req_info->resid, req.len);
        if (SECUREC_UNLIKELY(ret != EOK)) {
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(req_info->resid, req_info->res_type));
            return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
        }

        req.head.ruid  = req_info->req_ruid; /* forward ruid to owner */
        ret = mfc_forward_request(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS][%s][%s] send failed: dst_id=%u, dst_sid=%u, mode=%u",
                cm_display_resid(req_info->resid, req_info->res_type), "ASK OWNER",
                (uint32)req.head.dst_inst, (uint32)req.head.dst_sid, (uint32)req.req_mode);
            dms_send_error_ack(ctx->inst_id, ctx->sess_id, req_info->req_id, req_info->req_sid,
                req_info->req_ruid, ret, req_info->req_proto_ver);
            return ERRNO_DMS_SEND_MSG_FAILED;
        }

        LOG_DEBUG_INF("[DMS][%s][%s] send ok: dst_id=%u, dst_sid=%u, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type), "ASK OWNER",
            (uint32)req.head.dst_inst, (uint32)req.head.dst_sid, (uint32)req.req_mode);

        return ret;
    }

    // asker is already owner, just notify requester(owner) page is ready
    dms_message_head_t head;
    dms_init_ack_head2(&head, MSG_ACK_ALREADY_OWNER, 0, (uint8)ctx->inst_id, req_info->req_id,
        (uint16)ctx->sess_id, req_info->req_sid, req_info->req_proto_ver);
    head.ruid = req_info->req_ruid;
    head.size = (uint16)sizeof(dms_message_head_t);

    ret = mfc_send_data(&head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: failed, dst_id=%u, dst_sid=%u, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type),
            "MASTER ACK ALREADY OWNER", (uint32)head.dst_inst, (uint32)head.dst_sid,
            (uint32)req_info->req_mode);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: ok, dst_id=%u, dst_sid=%u, mode=%u",
        cm_display_resid(req_info->resid, req_info->res_type),
        "MASTER ACK ALREADY OWNER", (uint32)head.dst_inst, (uint32)head.dst_sid,
        (uint32)req_info->req_mode);
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
    LOG_DEBUG_INF("[DMS][%s][dms_notify_owner_for_res]: owner_id=%u, curr_mode=%u, req_mode=%u",
        cm_display_resid(req_info->resid, req_info->res_type), (uint32)req_info->owner_id,
        (uint32)req_info->curr_mode, (uint32)req_info->req_mode);

    if (ctx->inst_id != req_info->owner_id) {
        // notify owner to transfer this page to requester
        return dms_notify_owner_for_res_r(ctx, req_info);
    }

    // this instance is owner, transfer local page, and requester must be on another instance
    int ret = dms_transfer_res_owner(ctx, req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][owner transfer page]: failed, dst_id=%u, dst_sid=%u, dst_ruid=%llu, mode=%u",
            cm_display_resid(req_info->resid, req_info->res_type),
            (uint32)req_info->req_id, (uint32)req_info->req_sid, req_info->req_ruid, (uint32)req_info->req_mode);
    }
    return ret;
}

static int dms_send_req2owner(dms_process_context_t *ctx, dms_ask_res_req_t *req_msg, drc_req_owner_result_t *result)
{
    dms_res_req_info_t req_info = { 0 };
    req_info.owner_id = result->curr_owner_id;
    req_info.req_id   = req_msg->head.src_inst;
    req_info.req_sid  = req_msg->head.src_sid;
    req_info.req_ruid  = req_msg->head.ruid;
    req_info.curr_mode = req_msg->curr_mode;
    req_info.req_mode  = req_msg->req_mode;
    req_info.sess_type = req_msg->sess_type;
    req_info.res_type = req_msg->res_type;
    req_info.is_try   = req_msg->is_try;
    req_info.len      = req_msg->len;
    req_info.req_proto_ver = req_msg->head.msg_proto_ver;
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
                (uint32)req->head.src_inst, (uint32)req->head.src_sid, (uint32)req->req_mode,
                (uint32)req->curr_mode);
            break;

        case DRC_REQ_OWNER_CONVERTING:
            LOG_DEBUG_INF("[DMS][%s][waiting for converting]: dst_id=%u, dst_sid=%u, req_mode=%u, curr_mode=%u",
                cm_display_resid(req->resid, req->res_type), (uint32)req->head.src_inst,
                (uint32)req->head.src_sid, (uint32)req->req_mode, (uint32)req->curr_mode);
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

void dms_proc_ask_master_for_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE, CM_TRUE);
    dms_ask_res_req_t req = *(dms_ask_res_req_t *)(receive_msg->buffer);
    dms_release_recv_message(receive_msg);

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
        req.head.ruid, req.curr_mode, req.req_mode, req.is_try, req.sess_type, req.req_time, req.srsn);

    drc_req_owner_result_t result;
    int ret = drc_request_page_owner(req.resid, req.len, req.res_type, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id, req_info.inst_id,
            req_info.sess_id, req_info.ruid, ret, req_info.req_proto_ver);
        return;
    }

    if (result.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(req.resid, req.res_type), result.invld_insts);
        ret = dms_invalidate_share_copy(proc_ctx, req.resid, req.len,
            req.res_type, result.invld_insts, req.sess_type, req.is_try, CM_TRUE);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                req_info.inst_id, req_info.sess_id, req_info.ruid, ret, req_info.req_proto_ver);
            return;
        }
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_master_for_res], result type=%u",
        cm_display_resid(req.resid, req.res_type), result.type);

    dms_handle_remote_req_result(proc_ctx, &req, &result);
}

void dms_proc_ask_res_owner_id(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_owner_id_req_t), CM_TRUE, CM_TRUE);
    dms_ask_res_owner_id_req_t req = *(dms_ask_res_owner_id_req_t *)(receive_msg->buffer);
    dms_release_recv_message(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_ask_res_owner_id]: invalid req message");
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_res_owner_id]: src_id=%d, src_sid=%d",
        cm_display_resid(req.resid, req.res_type), req.head.src_inst, req.head.src_sid);

    uint8 owner_id = CM_INVALID_ID8;
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, req.sess_type, CM_TRUE);
    int ret = drc_enter_buf_res(req.resid, req.len, req.res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        dms_send_error_ack(
            proc_ctx->inst_id, proc_ctx->sess_id, req.head.src_inst, req.head.src_sid, req.head.ruid, ret,
            req.head.msg_proto_ver);
        return;
    }
    if (buf_res != NULL) {
        owner_id = buf_res->claimed_owner;
        drc_leave_buf_res(buf_res);
    }

    dms_ask_res_owner_id_ack_t ack = { 0 };
    dms_init_ack_head(&req.head, &ack.head, MSG_ACK_ASK_RES_OWNER_ID,
        sizeof(dms_ask_res_owner_id_ack_t), proc_ctx->sess_id);
    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_res_owner_id]: src_id=%u, src_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid);

    ack.owner_id = owner_id;
    if (mfc_send_data(&ack.head) == DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_res_owner_id]: finished, dst_id=%u, dst_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
        (uint32)ack.head.dst_sid);
    } else {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_ask_res_owner_id]: failed to send ack, dst_id=%u, dst_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
        (uint32)ack.head.dst_sid);
    }
    return;
}

void dms_proc_ask_owner_for_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE, CM_TRUE);
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    dms_ask_res_req_t req = *(dms_ask_res_req_t *)(receive_msg->buffer);
    dms_release_recv_message(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE ||
        req.curr_mode >= DMS_LOCK_MODE_MAX ||
        req.req_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_ask_owner_for_res]: invalid req message");
        return;
    }

    if (req.res_type == DRC_RES_PAGE_TYPE && ctx->global_buf_res.data_access == CM_FALSE &&
        req.sess_type == DMS_SESSION_NORMAL) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_owner_for_res]: owner received but data access is forbidden, req_id=%u, "
            "req_sid=%u, req_ruid=%llu, mode=%u", cm_display_resid(req.resid, req.res_type),
            (uint32)req.head.src_inst, (uint32)req.head.src_sid, req.head.ruid, (uint32)req.req_mode);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_ask_owner_for_res]: started, owner_id=%u, req_id=%u, "
        "req_sid=%u, req_ruid=%llu, mode=%u", cm_display_resid(req.resid, req.res_type), (uint32)proc_ctx->inst_id,
        (uint32)req.head.src_inst, (uint32)req.head.src_sid, req.head.ruid, (uint32)req.req_mode);

    dms_res_req_info_t req_info = { 0 };
    req_info.owner_id = req.head.dst_inst;
    req_info.req_id   = req.head.src_inst;
    req_info.req_sid  = req.head.src_sid;
    req_info.curr_mode = req.curr_mode;
    req_info.req_mode  = req.req_mode;
    req_info.req_ruid = req.head.ruid;
    req_info.sess_type = DMS_SESSION_NORMAL;
    req_info.res_type = req.res_type;
    req_info.is_try   = req.is_try;
    req_info.len      = req.len;
    req_info.req_proto_ver = req.head.msg_proto_ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, req.resid, req_info.len);
    DMS_SECUREC_CHECK(ret);
    ret = dms_transfer_res_owner(proc_ctx, &req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][owner transfer page]: failed, owner_id=%u, req_id=%u, req_sid=%u, "
            "req_ruid=%llu, mode=%u", cm_display_resid(req.resid, req.res_type), (uint32)req_info.owner_id,
            (uint32)req_info.req_id, (uint32)req_info.req_sid, req_info.req_ruid, (uint32)req_info.req_mode);
    }
}

void dms_proc_invld_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    dms_begin_stat(proc_ctx->sess_id, DMS_EVT_DCS_INVLDT_SHARE_COPY_PROCESS, CM_TRUE);

    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_invld_req_t), CM_TRUE, CM_TRUE);
    dms_invld_req_t req = *(dms_invld_req_t *)(receive_msg->buffer);
    dms_release_recv_message(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE)) {
        dms_end_stat(proc_ctx->sess_id);
        LOG_DEBUG_ERR("[DMS][dms_proc_invld_req]: invalid req message");
        return;
    }

    dms_common_ack_t ack;
    uint32 ack_cmd = req.invld_owner ? MSG_ACK_INVLD_OWNER : MSG_ACK_INVLDT_SHARE_COPY;
    dms_init_ack_head(&req.head, &ack.head, ack_cmd, sizeof(dms_common_ack_t), proc_ctx->sess_id);
    LOG_DEBUG_INF("[DMS][%s][dms_proc_invld_req]: src_id=%u, src_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid);

    int32 ret = DMS_SUCCESS;
    if (req.res_type == DRC_RES_PAGE_TYPE) {
        ret = g_dms.callback.invalidate_page(proc_ctx->db_handle, req.resid, req.invld_owner);
    } else {
        ret = dls_invld_lock_ownership(proc_ctx->db_handle, req.resid, DMS_LOCK_EXCLUSIVE, req.is_try);
    }
    ack.ret = ret;
    if (mfc_send_data(&ack.head) == DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS][%s][dms_proc_invld_req]: finished, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
            (uint32)ack.head.dst_sid);
    } else {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_invld_req]: failed to send ack, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
            (uint32)ack.head.dst_sid);
    }
    dms_end_stat(proc_ctx->sess_id);
}

static int dms_try_notify_owner_for_res(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    dms_res_req_info_t req_info = { 0 };
    req_info.owner_id = cvt_info->owner_id;
    req_info.req_id   = cvt_info->req_id;
    req_info.req_sid  = (uint16)(cvt_info->req_sid);
    req_info.req_ruid  = cvt_info->req_ruid; /* forward ruid to owner */
    req_info.curr_mode = cvt_info->curr_mode;
    req_info.req_mode  = cvt_info->req_mode;
    req_info.sess_type = DMS_SESSION_NORMAL;
    req_info.res_type    = cvt_info->res_type;
    req_info.is_try      = cvt_info->is_try;
    req_info.len         = cvt_info->len;
    req_info.req_proto_ver = cvt_info->req_proto_ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, cvt_info->resid, cvt_info->len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_resid(cvt_info->resid, cvt_info->res_type));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    ret = dms_notify_owner_for_res(ctx, &req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DMS][%s][notify owner transfer page]: failed, owner_id=%u, req_id=%u, "
            "req_sid=%u, req_ruid=%llu, req_mode=%u, curr_mode=%u",
            cm_display_resid(req_info.resid, req_info.res_type), (uint32)req_info.owner_id, (uint32)req_info.req_id,
            (uint32)req_info.req_sid, req_info.req_ruid, (uint32)req_info.req_mode, (uint32)req_info.curr_mode);
    }
    return ret;
}

static int32 dms_notify_already_owner(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    dms_message_head_t head;
    dms_init_ack_head2(&head, MSG_ACK_ALREADY_OWNER,
        0, (uint8)ctx->inst_id, cvt_info->req_id, (uint16)ctx->sess_id, (uint16)cvt_info->req_sid,
        cvt_info->req_proto_ver);
    head.ruid = cvt_info->req_ruid;
    head.size = sizeof(dms_message_head_t);
    if (mfc_send_data(&head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(cvt_info->resid, cvt_info->res_type), dms_get_mescmd_msg(head.cmd),
            (uint32)head.src_inst, (uint32)head.src_sid, (uint32)head.dst_inst,
            (uint32)head.dst_sid, (uint32)cvt_info->req_mode);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]send ok, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(cvt_info->resid, cvt_info->res_type), dms_get_mescmd_msg(head.cmd),
        (uint32)head.src_inst, (uint32)head.src_sid, (uint32)head.dst_inst,
        (uint32)head.dst_sid, (uint32)cvt_info->req_mode);
    return CM_SUCCESS;
}

static int32 dms_notify_granted_directly(dms_process_context_t *ctx, cvt_info_t *cvt_info)
{
    // this page not in memory of other instance, notify requester to load from disk
    dms_ask_res_ack_ld_t ack;
    dms_init_ack_head2(&ack.head, MSG_ACK_GRANT_OWNER,
        0, (uint8)ctx->inst_id, cvt_info->req_id, (uint16)ctx->sess_id, (uint16)cvt_info->req_sid,
        cvt_info->req_proto_ver);
    ack.head.ruid  = cvt_info->req_ruid;
    ack.head.size = sizeof(dms_ask_res_ack_ld_t);
    ack.master_grant = CM_TRUE; /* master grants first-time request X, since there's no sharer */

#ifndef OPENGAUSS
    if (cvt_info->res_type == DRC_RES_PAGE_TYPE) {
        ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
        ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
    }
#endif
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][ASK MASTER]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_resid(cvt_info->resid, cvt_info->res_type), (uint32)ack.head.src_inst,
            (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid,
            (uint32)cvt_info->req_mode);
        return CM_ERROR;
    }

    LOG_DEBUG_INF("[DMS][%s][ASK MASTER]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_resid(cvt_info->resid, cvt_info->res_type), (uint32)ack.head.src_inst,
        (uint32)ack.head.src_sid, (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid,
        (uint32)cvt_info->req_mode);
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
        dms_send_error_ack(ctx->inst_id, ctx->sess_id, cvt_info->req_id, cvt_info->req_sid, cvt_info->req_ruid, ret,
            cvt_info->req_proto_ver);
    }
}

void dms_proc_claim_ownership_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_claim_owner_req_t), CM_TRUE, CM_FALSE);
    dms_claim_owner_req_t *request = (dms_claim_owner_req_t *)(receive_msg->buffer);
    cvt_info_t cvt_info;
    claim_info_t claim_info;

    if (SECUREC_UNLIKELY(request->req_mode >= DMS_LOCK_MODE_MAX || request->len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_claim_ownership_req]: invalid req message");
        dms_release_recv_message(receive_msg);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][%s]: src_id=%u, src_sid=%u, dst_id=%u, dst_sid=%u, has_edp=%u, req_mode=%u",
        cm_display_resid(request->resid, request->res_type), "proc claim owner", (uint32)request->head.src_inst,
        (uint32)request->head.src_sid, (uint32)request->head.dst_inst,
        (uint32)request->head.dst_sid, (uint32)request->has_edp, (uint32)request->req_mode);

    // call drc interface to claim ownership
    (void)dms_set_claim_info(&claim_info, request->resid, request->len, (uint8)request->res_type,
        request->head.src_inst, request->req_mode, (bool8)request->has_edp, request->lsn, request->head.src_sid,
        request->sess_type, request->srsn);

    if (drc_claim_page_owner(&claim_info, &cvt_info) != DMS_SUCCESS) {
        dms_release_recv_message(receive_msg);
        return;
    }

    dms_release_recv_message(receive_msg);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(request->resid, request->res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(process_ctx, cvt_info.resid, cvt_info.len,
            cvt_info.res_type, cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_TRUE);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(process_ctx->inst_id, process_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
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

    dms_cancel_request_res_t req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_CANCEL_REQUEST_RES, 0,
        dms_ctx->inst_id, master_id, dms_ctx->sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_cancel_request_res_t);
    req.len = dms_ctx->len;
    req.res_type = (uint8)dms_ctx->type;
    req.sess_type = dms_ctx->sess_type;
    req.srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    ret = memcpy_sp(req.resid, DMS_RESID_SIZE, dms_ctx->resid, dms_ctx->len);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        LOG_DEBUG_ERR("[DMS][%s] notify master cancel request res: system call failed",
            cm_display_resid(dms_ctx->resid, dms_ctx->type));
        return;
    }
    ret = mfc_send_data_async(&req.head);
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

void dms_proc_cancel_request_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_cancel_request_res_t), CM_TRUE, CM_FALSE);
    dms_cancel_request_res_t req = *(dms_cancel_request_res_t*)receive_msg->buffer;
    dms_release_recv_message(receive_msg);

    if (SECUREC_UNLIKELY(req.len > DMS_RESID_SIZE)) {
        LOG_DEBUG_ERR("[DMS][dms_proc_cancel_request_res]invalid cancel request res message");
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dms_proc_cancel_request_res], src_id=%u, src_sid=%u, dest_id=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid, (uint32)req.head.dst_inst);

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, req.head.src_inst, req.head.src_sid, req.head.ruid, 0, 0, CM_FALSE,
        req.sess_type, g_timer()->now, req.srsn);

    cvt_info_t cvt_info;
    drc_cancel_request_res(req.resid, req.len, req.res_type, &req_info, &cvt_info);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(req.resid, req.res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx, cvt_info.resid, cvt_info.len,
            cvt_info.res_type, cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_TRUE);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

void dms_proc_confirm_cvt_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_confirm_cvt_req_t), CM_TRUE, CM_FALSE);
    dms_confirm_cvt_req_t req = *(dms_confirm_cvt_req_t *)(receive_msg->buffer);
    dms_release_recv_message(receive_msg);

    int32 ret;
    uint8 lock_mode;
    dms_confirm_cvt_ack_t ack;
    if (memset_s(&ack, sizeof(dms_confirm_cvt_ack_t), 0, sizeof(dms_confirm_cvt_ack_t)) != EOK) {
        cm_panic(0);
    }
    dms_init_ack_head(&(req.head), &ack.head, MSG_ACK_CONFIRM_CVT, sizeof(dms_confirm_cvt_ack_t),
        proc_ctx->sess_id);
    LOG_DEBUG_INF("[DMS][%s][dms_proc_confirm_cvt_req]: src_id=%u, src_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)req.head.src_inst,
        (uint32)req.head.src_sid);

    if (req.res_type == DRC_RES_PAGE_TYPE) {
        ret = g_dms.callback.confirm_converting(proc_ctx->db_handle,
            req.resid, CM_TRUE, &lock_mode, &ack.edp_map, &ack.lsn);
    } else {
        ret = drc_confirm_converting(req.resid, CM_TRUE, &lock_mode);
    }
    if (ret != DMS_SUCCESS) {
        ack.result = CONFIRM_NONE;
    } else {
        ack.lock_mode = lock_mode;
        ack.result = (lock_mode >= req.cvt_mode) ? CONFIRM_READY : CONFIRM_CANCEL;
    }

    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][dms_proc_confirm_cvt_req]: failed to send ack, dst_id=%u, dst_sid=%u",
            cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
            (uint32)ack.head.dst_sid);
        return;
    }
    LOG_DEBUG_INF("[DMS][%s][dms_proc_confirm_cvt_req]: send ack ok, dst_id=%u, dst_sid=%u",
        cm_display_resid(req.resid, req.res_type), (uint32)ack.head.dst_inst,
        (uint32)ack.head.dst_sid);
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


    if (mfc_send_data(&req.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS]dms_smon_send_confirm_req send error, dst_id: %d", cvt_req->inst_id);
        *ruid = req.head.ruid;
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    *ruid = req.head.ruid;
    LOG_DEBUG_INF("[DMS]dms_smon_send_confirm_req send ok dst_id: %d", cvt_req->inst_id);
    return DMS_SUCCESS;
}

static inline bool32 dms_the_same_drc_req(drc_request_info_t *req1, drc_request_info_t *req2)
{
    if (req1->inst_id == req2->inst_id &&
        req1->curr_mode == req2->curr_mode &&
        req1->req_mode == req2->req_mode &&
        req1->sess_id == req2->sess_id &&
        req1->ruid == req2->ruid) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static void dms_smon_handle_ready_ack(dms_process_context_t *proc_ctx,
    res_id_t *res_id, drc_request_info_t *cvt_req, dms_confirm_cvt_ack_t *ack)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, CM_TRUE);
    int ret = drc_enter_buf_res(res_id->data, res_id->len, res_id->type, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        return;
    }

    if (!dms_the_same_drc_req(&buf_res->converting.req_info, cvt_req)) {
        drc_leave_buf_res(buf_res);
        return;
    }

    bool32 has_edp = CM_FALSE;
    if (buf_res->claimed_owner != CM_INVALID_ID8) {
        has_edp = bitmap64_exist(&ack->edp_map, buf_res->claimed_owner);
    }
    claim_info_t claim_info;
    (void)dms_set_claim_info(&claim_info, buf_res->data, buf_res->len, buf_res->type, cvt_req->inst_id,
        ack->lock_mode, (bool8)has_edp, ack->lsn, cvt_req->sess_id, DMS_SESSION_NORMAL, cvt_req->srsn);

    cvt_info_t cvt_info;
    drc_convert_page_owner(buf_res, &claim_info, &cvt_info);
    LOG_DEBUG_INF("[DMS][%s][dms_smon_handle_ready_ack]: mode=%u, claimed_owner=%u, edp_map=%llu, copy_insts=%llu",
        cm_display_resid(claim_info.resid, claim_info.res_type), (uint32)buf_res->lock_mode,
        (uint32)buf_res->claimed_owner, buf_res->edp_map, buf_res->copy_insts);
    drc_leave_buf_res(buf_res);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(claim_info.resid, claim_info.res_type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx, cvt_info.resid, cvt_info.len,
            cvt_info.res_type, cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_FALSE);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

static void dms_smon_handle_cancel_ack(dms_process_context_t *proc_ctx, res_id_t *res_id,
    drc_request_info_t *cvt_req)
{
    drc_buf_res_t *buf_res = NULL;
     uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, CM_TRUE);
    int ret = drc_enter_buf_res(res_id->data, res_id->len, res_id->type, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        return;
    }

    if (!dms_the_same_drc_req(&buf_res->converting.req_info, cvt_req)) {
        drc_leave_buf_res(buf_res);
        return;
    }

    drc_request_info_t req_info;
    dms_set_req_info(&req_info, cvt_req->inst_id, cvt_req->sess_id, cvt_req->ruid, 0, 0,
        CM_FALSE, CM_FALSE, cvt_req->req_time, cvt_req->srsn);

    cvt_info_t cvt_info;
    cvt_info.invld_insts = 0;
    cvt_info.req_id = CM_INVALID_ID8;

    (void)drc_cancel_converting(buf_res, &req_info, &cvt_info);

    drc_leave_buf_res(buf_res);

    if (cvt_info.invld_insts != 0) {
        LOG_DEBUG_INF("[DMS][%s] share copy to be invalidated: %llu",
            cm_display_resid(buf_res->data, buf_res->type), cvt_info.invld_insts);

        int32 ret = dms_invalidate_share_copy(proc_ctx, cvt_info.resid, cvt_info.len,
            cvt_info.res_type, cvt_info.invld_insts, cvt_info.sess_type, cvt_info.is_try, CM_FALSE);
        if (ret != DMS_SUCCESS) {
            dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
                cvt_info.req_id, cvt_info.req_sid, cvt_info.req_ruid, ret, cvt_info.req_proto_ver);
            return;
        }
    }
    dms_handle_cvt_info(proc_ctx, &cvt_info);
}

static void dms_smon_handle_confirm_ack(uint64 ruid, res_id_t *res_id, drc_request_info_t *cvt_req)
{
    dms_message_t msg = {0};
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    int32 ret = mfc_get_response(ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s][%s]: wait ack timeout, src_id=%u, src_sid=%u, dst_id=%u",
            cm_display_resid(res_id->data, res_id->type), "CONFIRM CVT", (uint32)g_dms.inst_id,
            (uint32)ctx->smon_sid, (uint32)cvt_req->inst_id);
        return;
    }
    dms_confirm_cvt_ack_t ack = *(dms_confirm_cvt_ack_t*)msg.buffer;
    dms_release_recv_message(&msg);

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
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, CM_TRUE);
    int ret = drc_enter_buf_res(res_id->data, res_id->len, res_id->type, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        return;
    }

    if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        drc_leave_buf_res(buf_res);
        return;
    }
    drc_request_info_t cvt_req = buf_res->converting.req_info;
    drc_leave_buf_res(buf_res);

    LOG_DEBUG_WAR("[DMS][%s] start confirm converting [inst:%u sid:%u ruid:%llu req_mode:%u]",
        cm_display_resid(res_id->data, res_id->type), (uint32)cvt_req.inst_id,
        (uint32)cvt_req.sess_id, cvt_req.ruid, (uint32)cvt_req.req_mode);

    uint64 ruid;
    if (dms_smon_send_confirm_req(res_id, &cvt_req, &ruid) != DMS_SUCCESS) {
        return;
    }

    dms_smon_handle_confirm_ack(ruid, res_id, &cvt_req);
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

void dms_smon_recycle_entry(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif

    while (!thread->closed) {
        drc_recycle_buf_res_on_demand();
        DMS_REFORM_SHORT_SLEEP;
    }
}

void dms_proc_removed_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    dms_release_recv_message(receive_msg);
}

void dms_protocol_proc_maintain_version(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    dms_release_recv_message(receive_msg);
}

bool8 dms_cmd_is_broadcast(uint32 cmd)
{
    bool8 res = CM_FALSE;
    switch (cmd) {
        case MSG_REQ_INVALIDATE_SHARE_COPY:
        case MSG_REQ_BROADCAST:
        case MSG_REQ_BOC:
        case MSG_REQ_OPENGAUSS_DDLLOCK:
        case MSG_REQ_DDL_SYNC:
        case MSG_REQ_SYNC_SHARE_INFO:
        case MSG_REQ_NODE_FOR_BUF_INFO:
            res = CM_TRUE;
            break;
        default:
            res = CM_FALSE;
    }
    return res;
}

static uint32 dms_get_broadcast_proto_version()
{
    uint32 msg_version = DMS_SW_PROTO_VER;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (i == g_dms.inst_id) {
            continue;
        }
        uint32 node_version = dms_get_node_proto_version(i);
        if (node_version != DMS_INVALID_PROTO_VER && node_version < msg_version) {
            msg_version = node_version;
        }
    }
    return msg_version;
}

// point-to-point
static uint32 dms_get_ptp_proto_version(uint8 dst_inst)
{
    uint32 msg_version = DMS_SW_PROTO_VER;
    uint32 receiver_version = dms_get_node_proto_version(dst_inst);
    if (receiver_version != DMS_INVALID_PROTO_VER && receiver_version < msg_version) {
        msg_version = receiver_version;
    }
    return msg_version;
}

uint32 dms_get_forward_request_proto_version(uint8 dst_inst, uint32 recv_req_proto_ver)
{
    uint32 msg_proto_ver = recv_req_proto_ver;
    uint32 receiver_proto_ver = dms_get_node_proto_version(dst_inst);
    if (receiver_proto_ver != DMS_INVALID_PROTO_VER && receiver_proto_ver < msg_proto_ver) {
        msg_proto_ver = receiver_proto_ver;
    }
    return msg_proto_ver;
}

uint32 dms_get_send_proto_version_by_cmd(uint32 cmd, uint8 dest_inst)
{
    if (dms_cmd_is_broadcast(cmd)) {
        return dms_get_broadcast_proto_version();
    }
    return dms_get_ptp_proto_version(dest_inst);
}

inline dms_message_head_t *get_dms_head(dms_message_t *msg)
{
    return (dms_message_head_t *)(msg->buffer);
}

inline void dms_set_node_proto_version(uint8 inst_id, uint32 version)
{
    if (inst_id == g_dms.inst_id) {
        return;
    }

    uint32 ret = CM_FALSE;
    do {
        atomic32_t cur_version = cm_atomic32_get(&g_dms.cluster_proto_vers[inst_id]);
        if (cur_version == version) {
            break;
        }
        ret = cm_atomic32_cas(&g_dms.cluster_proto_vers[inst_id], cur_version, version);
    } while (!ret);
}

uint32 dms_get_node_proto_version(uint8 inst_id)
{
    if (inst_id == g_dms.inst_id) {
        return DMS_SW_PROTO_VER;
    }
    return (uint32)cm_atomic32_get(&g_dms.cluster_proto_vers[inst_id]);
}

void dms_init_cluster_proto_version()
{
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        dms_set_node_proto_version(i, DMS_INVALID_PROTO_VER);
    }

    int ret = CM_FALSE;
    do {
        atomic32_t cur_version = cm_atomic32_get(&g_dms.cluster_proto_vers[g_dms.inst_id]);
        ret = cm_atomic32_cas(&g_dms.cluster_proto_vers[g_dms.inst_id], cur_version, DMS_SW_PROTO_VER);
    } while (!ret);
    return;
}

/*
* @brief request buffer related information
* Based on the DRC entry, send broadcast message to all Standby, which held the page copy,
* to obtain buffer related information, mainly buffdesc.
* @[in] drc_info->copy_insts: Identify which nodes hold COPY
* @[in] tag: Uniquely identify a page
* @[out] drc_info->buf_info[]: Save the information returned by instances
*/
int dms_send_request_buf_info(dms_context_t *dms_ctx, stat_drc_info_t *drc_info)
{
    dms_req_buf_info_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_NODE_FOR_BUF_INFO, 0,
        dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);

    req.head.size = sizeof(dms_req_buf_info_t);
    req.claimed_owner = drc_info->claimed_owner;
    req.copy_insts = drc_info->copy_insts;
    req.master_id = drc_info->master_id;
    errno_t err = memcpy_s(req.resid, DMS_RESID_SIZE, drc_info->data, DMS_RESID_SIZE);
    DMS_SECUREC_CHECK(err);
    req.from_inst = dms_ctx->inst_id;

    uint64 inst_list = drc_info->copy_insts;
    if (drc_info->claimed_owner != dms_ctx->inst_id) {
        inst_list |= ((uint64)0x1 << (drc_info->claimed_owner));
    }
    if (drc_info->master_id != dms_ctx->inst_id) {
        inst_list |= ((uint64)0x1 << (drc_info->master_id));
    }

    uint64 succ_inst = 0;
    mfc_broadcast(inst_list, (void*)&req, &succ_inst);

    mes_msg_list_t recv_msg = {0};
    int32 ret = mfc_get_broadcast_res_with_msg(req.head.ruid, DMS_MSG_SLEEP_TIME, succ_inst, &recv_msg);
    DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED);
        return ret;
    }

    // handle messages from other instance
    for (uint32 i = 0; i < recv_msg.count; i++) {
        dms_ack_buf_info_t *ack = (dms_ack_buf_info_t *)recv_msg.messages[i].buffer;
        err = memcpy_s(&drc_info->buf_info[i], sizeof(stat_buf_info_t), &ack->buf_info, sizeof(stat_buf_info_t));
        DMS_SECUREC_CHECK(err);
    }
    mfc_release_mes_msglist(&recv_msg);
    return ret;
}

/*
* @brief Process the request information from the Master and return relevant information
* Obtain the information of the corresponding page in the local buffer pool based on the received resid
*/
void dms_proc_ask_node_buf_info(dms_process_context_t * proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_req_buf_info_t), CM_TRUE, CM_TRUE);
    dms_req_buf_info_t req = *(dms_req_buf_info_t *)(receive_msg->buffer);

    stat_buf_info_t buf_info;
    errno_t err = memcpy_s(&buf_info, sizeof(stat_buf_info_t), 0, sizeof(stat_buf_info_t));
    DMS_SECUREC_CHECK(err);
    if (req.copy_insts & ((uint64)0x1 << proc_ctx->inst_id) ||
        req.master_id == proc_ctx->inst_id ||
        req.claimed_owner == proc_ctx->inst_id) {

        g_dms.callback.get_buf_info(req.resid, &buf_info);
    }

    dms_ack_buf_info_t ack;
    dms_init_ack_head2(&ack.head, MSG_ACK_NODE_FOR_BUF_INFO, 0, (uint8)proc_ctx->inst_id,
        receive_msg->head->src_inst, (uint16)proc_ctx->sess_id, receive_msg->head->src_sid,
        receive_msg->head->msg_proto_ver);
    ack.head.ruid = receive_msg->head->ruid;
    ack.head.size = sizeof(dms_ack_buf_info_t);
    ack.buf_info = buf_info;

    dms_release_recv_message(receive_msg);
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS]dms_proc_ask_node_buf_info send error, dst_id: %d", proc_ctx->inst_id);
    }
}

void dms_check_message_cmd(unsigned int cmd, bool8 is_req)
{
    bool8 is_req_actual;
    if (cmd >= MSG_REQ_BEGIN && cmd < MSG_REQ_END) {
        is_req_actual = CM_TRUE;
    } else if (cmd >= MSG_ACK_BEGIN && cmd < MSG_ACK_END) {
        is_req_actual = CM_FALSE;
    } else {
        cm_panic_log(0, "[DMS MSG] unknown cmd, cmd:%u", cmd);
    }

    if (is_req_actual != is_req) {
        if (is_req_actual) {
            cm_panic_log(0, "[DMS MSG] req msg should use function like DMS_INIT_MESSAGE_HEAD, "
                "cmd:%u, is req msg", cmd);
        } else {
            cm_panic_log(0, "[DMS MSG] ack msg should use function like dms_init_ack_head, "
                "cmd:%u, is ack msg", cmd);
        }
    }
    return;
}

void dms_init_ack_head(const dms_message_head_t *req_head, dms_message_head_t *ack_head, unsigned int cmd,
    unsigned short size, unsigned int src_sid)
{
    dms_check_message_cmd(cmd, CM_FALSE);
    int ret = memset_s(ack_head, DMS_MSG_HEAD_SIZE, 0, DMS_MSG_HEAD_SIZE);
    DMS_SECUREC_CHECK(ret);
    ack_head->msg_proto_ver = req_head->msg_proto_ver;
    ack_head->sw_proto_ver = DMS_SW_PROTO_VER;
    ack_head->cmd = cmd;
    ack_head->flags = req_head->flags;
    ack_head->ruid = req_head->ruid;
    ack_head->src_inst = (uint8)g_dms.inst_id;
    ack_head->dst_inst = req_head->src_inst;
    ack_head->size = size;
    ack_head->cluster_ver = req_head->cluster_ver;
    ack_head->src_sid = (uint16)src_sid;
    ack_head->dst_sid = req_head->src_sid;
}

void dms_init_ack_head2(dms_message_head_t *ack_head, unsigned int cmd, unsigned int flags,
    unsigned char src_inst, unsigned char dst_inst, unsigned short src_sid, unsigned short dst_sid,
    unsigned int req_proto_ver)
{
    dms_check_message_cmd(cmd, CM_FALSE);
    int ret = memset_s(ack_head, DMS_MSG_HEAD_SIZE, 0, DMS_MSG_HEAD_SIZE);
    DMS_SECUREC_CHECK(ret);
    ack_head->msg_proto_ver = req_proto_ver;
    ack_head->sw_proto_ver = DMS_SW_PROTO_VER;
    ack_head->cmd = cmd;
    ack_head->flags = 0;
    ack_head->src_inst = (uint8)g_dms.inst_id;
    ack_head->dst_inst = dst_inst;
    ack_head->cluster_ver = DMS_GLOBAL_CLUSTER_VER;
    ack_head->src_sid = src_sid;
    ack_head->dst_sid = dst_sid;
}

/**
 * rule for broadcast type: msg version < self version, think compatible.
 * rule for PTP type: msg version < self version, think compatible.
 * for ptp(point-to-point) type: msg version should equal to min(sender_version, recviver_version).
 * However existing situation, message src_inst not sender itself, which result in message version
 *   less than min(sender_version, receiver_version), and this sitation is compatible.
 * eg MSG_REQ_ASK_OWNER_FOR_PAGE
 */
bool8 dms_check_message_proto_version(dms_message_head_t *head)
{
    bool8 pass_check = CM_TRUE;
    if (head->msg_proto_ver > DMS_SW_PROTO_VER) {
        pass_check = CM_FALSE;
        LOG_RUN_INF("[DMS PROTOCOL] receive message version not match, recv msg: msg_proto_ver:%u, "
            "sender_proto_ver:%u, self_proto_ver:%u, cmd:%d, src_inst:%u, src_sid:%u, dst_inst:%u, dst_sid:%u",
            head->msg_proto_ver, head->sw_proto_ver, DMS_SW_PROTO_VER, head->cmd, head->src_inst, head->src_sid,
            head->dst_inst, head->dst_sid);
    }
    return pass_check;
}

bool8 dms_cmd_need_ack(uint32 cmd)
{
    if (cmd >= MSG_ACK_BEGIN && cmd < MSG_ACK_END) {
        return CM_FALSE;
    }

    switch (cmd) {
        case MSG_REQ_CLAIM_OWNER:
        case MSG_REQ_AWAKE_TXN:
        case MSG_REQ_CANCEL_REQUEST_RES:
        case MSG_REQ_MASTER_CKPT_EDP:
        case MSG_REQ_OWNER_CKPT_EDP:
        case MSG_REQ_MASTER_CLEAN_EDP:
        case MSG_REQ_OWNER_CLEAN_EDP:
            return CM_FALSE;
        default:
            return CM_TRUE;
    }
}

#ifdef __cplusplus
}
#endif