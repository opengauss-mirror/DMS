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
 * dcs_page.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_page.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_page.h"
#include "cm_defs.h"
#include "cm_memory.h"
#include "drc_res_mgr.h"
#include "dms_stat.h"
#include "dms_cm.h"
#include "dms_error.h"
#include "drc_page.h"
#include "dms_reform_proc.h"
#include "cm_encrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void dcs_set_ctrl_in_rcy(dms_context_t* dms_ctx, dms_buf_ctrl_t* ctrl)
{
    ctrl->in_rcy = (dms_ctx->sess_type == DMS_SESSION_RECOVER);
}

static inline int32 dcs_set_ctrl4already_owner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t mode)
{
    /* owner has no edp */
    ctrl->lock_mode = mode;
    ctrl->is_edp = 0;
    LOG_DEBUG_INF("[DCS][%s]: lock mode=%d, edp=%d", cm_display_pageid(dms_ctx->resid), ctrl->lock_mode, ctrl->is_edp);
    /*
     * 1. has processed x-mode historical transfer request,
     *  buf page does not swap out and in, so it is the latest in memory
     * 2. page is already owned by requester, S->X req_mode, no need to load from disk
     */
    if (ctrl->been_loaded) {
        return g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_IS_LOADED);
    }
    /* 3.page swap out and in, but buf res not be recycled, need to load from disk */
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    return g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_NEED_LOAD);
}

static inline int32 dcs_set_ctrl4edp_local(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t req_mode)
{
    ctrl->is_remote_dirty = 1;
    ctrl->lock_mode = req_mode;
    CM_MFENCE;
    ctrl->is_edp = 0;
    ctrl->been_loaded = CM_TRUE;
    ctrl->break_wal = CM_FALSE;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    LOG_DEBUG_INF("[DCS][%s]: lock mode=%d, edp=%d", cm_display_pageid(dms_ctx->resid), ctrl->lock_mode, ctrl->is_edp);
    return g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_IS_LOADED);
}

int32 dcs_handle_ack_edp_remote(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_t), CM_FALSE);
    dms_ask_res_ack_t *ack = (dms_ask_res_ack_t *)(msg->buffer);

    if (ack->head.cmd == MSG_ACK_EDP_READY && !(ack->head.flags & MSG_FLAG_NO_PAGE)) {
        CM_CHK_PROC_MSG_SIZE(msg, (uint32)(sizeof(dms_ask_res_ack_t) + g_dms.page_size),
            CM_FALSE);
        int ret = memcpy_sp(g_dms.callback.get_page(ctrl), g_dms.page_size, msg->buffer + sizeof(dms_ask_res_ack_t),
            g_dms.page_size);
        if (ret != EOK) {
            return ret;
        }
        if (ack->enable_cks &&
            !g_dms.callback.verify_page_checksum(dms_ctx->db_handle, ctrl, g_dms.page_size, ack->checksum)) {
            LOG_RUN_ERR("[DCS][%s][%s]: edp page checksum failed", cm_display_pageid(dms_ctx->resid),
                dms_get_mescmd_msg(ack->head.cmd));
            return ERRNO_DMS_DCS_PAGE_CHECKSUM_FAILED;
        }

        DMS_STAT_INC_BUFFER_GETS(dms_ctx->sess_id);
    }

    if (ack->edp_map > 0) {
        ctrl->edp_map = (ack->edp_map) & (~(1ULL << dms_ctx->inst_id));
    }
    ctrl->is_remote_dirty = 1;
    ctrl->lock_mode = mode;
    CM_MFENCE;
    ctrl->is_edp = 0;
    ctrl->been_loaded = CM_TRUE;
    ctrl->break_wal = CM_FALSE;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_IS_LOADED);

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    LOG_DEBUG_INF("[DCS][%s][%s]: lock mode=%d, edp=%d, src_id=%d, src_sid=%d, dest_id=%d, dest_sid=%d, dirty=%d,"
        "remote diry=%d, global_lsn=%llu, global_scn=%llu, page_lsn=%llu", cm_display_pageid(dms_ctx->resid),
        dms_get_mescmd_msg(ack->head.cmd), ctrl->lock_mode, ctrl->is_edp, msg->head->src_inst, msg->head->src_sid,
        msg->head->dst_inst, msg->head->dst_sid, DCS_ACK_PAGE_IS_DIRTY(msg), DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg),
        ack->lsn, ack->scn, page_lsn);
    dms_claim_ownership(dms_ctx, (uint8)master_id, mode, CM_FALSE, page_lsn);
    return DMS_SUCCESS;
}

static inline int32 dcs_handle_ask_edp_ack(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    dms_message_head_t *ack_dms_head = get_dms_head(msg);
    if (ack_dms_head->cmd == MSG_ACK_EDP_READY) {
        return dcs_handle_ack_edp_remote(dms_ctx, ctrl, master_id, msg, mode);
    }

    if (ack_dms_head->cmd == MSG_ACK_GRANT_OWNER) {
        return dcs_handle_ack_need_load(dms_ctx, ctrl, master_id, msg, mode);
    }
    LOG_DEBUG_ERR("[DCS][dcs_handle_ask_edp_ack]recieve unexpected message");
    DMS_THROW_ERROR(ERRNO_DMS_MES_INVALID_MSG);
    return ERRNO_DMS_MES_INVALID_MSG;
}

int32 dcs_handle_ask_edp_remote(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 remote_id, dms_lock_mode_t req_mode)
{
    dms_ask_res_req_t page_req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&page_req.head,
        MSG_REQ_ASK_EDP_REMOTE, 0, dms_ctx->inst_id, remote_id, dms_ctx->sess_id, CM_INVALID_ID16);
    page_req.head.size = (uint16)sizeof(dms_ask_res_req_t);
    page_req.req_mode  = req_mode;
    page_req.curr_mode = ctrl->lock_mode;
    page_req.len = DMS_PAGEID_SIZE;

    int ret = memcpy_s(page_req.resid, DMS_PAGEID_SIZE, dms_ctx->resid, DMS_PAGEID_SIZE);
    DMS_SECUREC_CHECK(ret);

    ret = mfc_send_data(&page_req.head);
    if (SECUREC_UNLIKELY(ret != CM_SUCCESS)) {
        LOG_DEBUG_ERR("[DCS]%s][%s]: send failed, src_id=%d, src_sid=%d, dest_id=%d, dest_sid=%d, req_mode=%u",
            cm_display_pageid(dms_ctx->resid), dms_get_mescmd_msg(page_req.head.cmd), page_req.head.src_inst,
            page_req.head.src_sid, page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
        return ret;
    }

    LOG_DEBUG_INF("[DCS][%s][%s]: send ok, src_id=%d, src_sid=%d, dest_id=%d, dest_sid=%d, req_mode=%u",
        cm_display_pageid(dms_ctx->resid), dms_get_mescmd_msg(page_req.head.cmd), page_req.head.src_inst,
        page_req.head.src_sid, page_req.head.dst_inst, page_req.head.dst_sid, req_mode);

    dms_message_t msg;
    ret = mfc_get_response(page_req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][%s]: ack time out, src_id=%d, src_sid=%d, dest_id=%d, dest_sid=%d, req_mode=%u",
            cm_display_pageid(dms_ctx->resid), "ASK OWNER", page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst, page_req.head.dst_sid, req_mode);
        return ret;
    }
    ret = dcs_handle_ask_edp_ack(dms_ctx, ctrl, (uint8)dms_ctx->inst_id, &msg, req_mode);

    mfc_release_response(&msg);
    return ret;
}

static inline void dcs_buf_clean_ctrl_edp(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl)
{
    g_dms.callback.clean_ctrl_edp(dms_ctx->db_handle, ctrl);
}

static inline void dcs_set_ctrl4granted(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t granted_mode)
{
#ifndef OPENGAUSS
    if (ctrl->is_edp) {
        /* incase owner node clean edp info and recycle buffer before cleaning edp on this node */
        LOG_DEBUG_INF("[DCS][%s]: wait to clean edp", cm_display_pageid(dms_ctx->resid));
        dcs_buf_clean_ctrl_edp(dms_ctx, ctrl);
    }
#endif
    /* if no owner exists, master grants X; if owner exists on DRC but local ctrl null, grant S */
    ctrl->lock_mode = granted_mode;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_NEED_LOAD);
}

int32 dcs_handle_ack_need_load(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    dms_ask_res_ack_ld_t *ack = NULL;
    if (msg != NULL) {
        CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_ld_t), CM_FALSE);
        ack = (dms_ask_res_ack_ld_t *)msg->buffer;
#ifndef OPENGAUSS
        // load page from disk, need to sync scn/lsn with master
        g_dms.callback.update_global_lsn(dms_ctx->db_handle, ack->master_lsn);
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
#endif
    }

    dms_lock_mode_t granted_mode = mode;
    /*
     * if no existing owner, master grants to requestor locally/remotely, grant X;
     * if owner acks and grants owner, meaning sharer exists potentially, grant S.
     */
    if (ack == NULL || ack->master_grant == CM_TRUE) {
        granted_mode = DMS_LOCK_EXCLUSIVE;
    }

    dcs_set_ctrl4granted(dms_ctx, ctrl, granted_mode);
    dms_claim_ownership(dms_ctx, master_id, granted_mode, CM_FALSE, CM_INVALID_ID64);
    return DMS_SUCCESS;
}

// if try request page and then receive already_owner
// should set need_load because current ctrl must be load_failed
// grant request mode only because there may be copy insts
int32 dcs_handle_ack_already_owner_for_try(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, uint8 master_id,
    dms_lock_mode_t mode)
{
    dcs_set_ctrl4granted(dms_ctx, ctrl, mode);
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_ID64);
    return DMS_SUCCESS;
}

int32 dcs_handle_ack_already_owner(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    int ret = dcs_set_ctrl4already_owner(dms_ctx, ctrl, mode);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        return ret;
    }

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);

    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, page_lsn);

    return DMS_SUCCESS;
}

static int dcs_handle_page_from_owner(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, dms_message_t *msg, dms_lock_mode_t mode)
{
    CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_t), CM_FALSE);
    dms_ask_res_ack_t *ack = (dms_ask_res_ack_t *)(msg->buffer);

    if (ack->head.cmd == MSG_ACK_PAGE_READY && !(ack->head.flags & MSG_FLAG_NO_PAGE)) {
        CM_CHK_PROC_MSG_SIZE(msg, (uint32)(sizeof(dms_ask_res_ack_t) + g_dms.page_size), CM_FALSE);
#ifdef OPENGAUSS
        ctrl->seg_fileno = ack->seg_fileno;
        ctrl->seg_blockno = ack->seg_blockno;
        if (g_dms.callback.verify_page != NULL) {
            g_dms.callback.verify_page(ctrl, msg->buffer + sizeof(dms_ask_res_ack_t));
        }
#else
        // cache edp page when receive page which breaks wal
        if (ctrl->is_edp && !ctrl->break_wal && ack->break_wal) {
            g_dms.callback.cache_page(dms_ctx->db_handle, ctrl);
            ctrl->break_wal = CM_TRUE;
        }
#endif
        int ret = memcpy_s(g_dms.callback.get_page(ctrl), g_dms.page_size, msg->buffer + sizeof(dms_ask_res_ack_t),
            g_dms.page_size);
        DMS_SECUREC_CHECK(ret);

#ifndef OPENGAUSS
        if (ack->enable_cks &&
            !g_dms.callback.verify_page_checksum(dms_ctx->db_handle, ctrl, g_dms.page_size, ack->checksum)) {
            LOG_RUN_ERR("[DCS][%s][%s]: page checksum failed", cm_display_pageid(dms_ctx->resid),
                dms_get_mescmd_msg(msg->head->cmd));
            return ERRNO_DMS_DCS_PAGE_CHECKSUM_FAILED;
        }
#endif

        DMS_STAT_INC_BUFFER_GETS(dms_ctx->sess_id);
    }

#ifndef OPENGAUSS
    if (ack->lsn != 0) {
        g_dms.callback.update_global_lsn(dms_ctx->db_handle, ack->lsn);
    }

    if (ack->scn != 0) {
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
    }
#endif

    ctrl->lock_mode = mode;

    if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
        ctrl->edp_map = (ack->edp_map) & (~(1ULL << dms_ctx->inst_id));
        ctrl->is_remote_dirty = (ctrl->edp_map != 0);
        ctrl->is_edp = 0;
        LOG_DEBUG_INF("[DCS][%s][%s]: lock mode=%d, edp=%d, src_id=%d, src_sid=%d, dest_id=%d,"
            "dest_sid=%d, dirty=%d, remote diry=%d, page_lsn=%llu, page_scn=%llu", cm_display_pageid(dms_ctx->resid),
            dms_get_mescmd_msg(ack->head.cmd), ctrl->lock_mode, ctrl->is_edp, msg->head->src_inst, msg->head->src_sid,
            msg->head->dst_inst, msg->head->dst_sid, DCS_ACK_PAGE_IS_DIRTY(msg), DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg),
            ack->lsn, ack->scn);
#ifndef OPENGAUSS
        if (ctrl->is_remote_dirty) {
            g_dms.callback.ckpt_enque_one_page(dms_ctx->db_handle, ctrl);
        }
        unsigned long long lastest_lfn = g_dms.callback.get_global_lfn(dms_ctx->db_handle);
        g_dms.callback.update_page_lfn(ctrl, lastest_lfn);
#endif
    } else {
        CM_ASSERT(!DCS_ACK_PAGE_IS_DIRTY(msg) && !DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg));
    }

    ctrl->force_request = 0;
    ctrl->been_loaded = CM_TRUE;
    ctrl->break_wal = ack->break_wal;
    CM_MFENCE;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_IS_LOADED);

    LOG_DEBUG_INF("[DCS][%s][%s]: lock mode=%d, edp=%d, src_id=%d, src_sid=%d, dest_id=%d,"
        "dest_sid=%d, mode=%u, remote dirty=%d, remote remote diry=%d, page_lsn=%llu, page_scn=%llu,"
        "curr_page_lsn=%llu, curr_global_lsn=%llu", cm_display_pageid(dms_ctx->resid),
        dms_get_mescmd_msg(msg->head->cmd), ctrl->lock_mode, ctrl->is_edp, msg->head->src_inst,
        msg->head->src_sid, msg->head->dst_inst, msg->head->dst_sid, mode,
        DCS_ACK_PAGE_IS_DIRTY(msg), DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg), ack->lsn, ack->scn,
        g_dms.callback.get_page_lsn(ctrl), g_dms.callback.get_global_lsn(dms_ctx->db_handle));
    return DMS_SUCCESS;
}

int32 dcs_handle_ack_page_ready(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint32 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    int32 ret = dcs_handle_page_from_owner(dms_ctx, ctrl, msg, mode);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    dms_claim_ownership(dms_ctx, (uint8)master_id, mode, DCS_ACK_PAGE_IS_DIRTY(msg), page_lsn);
    return DMS_SUCCESS;
}

int32 dcs_handle_ack_edp_local(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    int32 ret = dcs_set_ctrl4edp_local(dms_ctx, ctrl, mode);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, page_lsn);
    return DMS_SUCCESS;
}

int dms_request_page(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t mode)
{
    dms_reset_error();
    if (dms_ctx == NULL || ctrl == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return ERRNO_DMS_PARAM_NULL;
    }

#ifdef OPENGAUSS
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (g_dms.enable_reform && !reform_info->first_reform_finish && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }
#endif

    LOG_DEBUG_INF("[DCS][%s][dcs request page enter]", cm_display_pageid(dms_ctx->resid));
    int ret = dms_request_res_internal(dms_ctx, (void*)ctrl, ctrl->lock_mode, mode);
    LOG_DEBUG_INF("[DCS][%s][dcs request page leave] ret: %d", cm_display_pageid(dms_ctx->resid), ret);

    session_stat_t *sess_stat = DMS_GET_SESSION_STAT(dms_ctx->sess_id);
    sess_stat->stat[DMS_STAT_NET_TIME] += sess_stat->wait_time[DMS_EVT_DCS_REQ_MASTER4PAGE_1WAY] +
        sess_stat->wait_time[DMS_EVT_DCS_REQ_MASTER4PAGE_2WAY] +
        sess_stat->wait_time[DMS_EVT_DCS_REQ_MASTER4PAGE_3WAY];
    return ret;
}

void dcs_send_requester_edp_local(dms_process_context_t *ctx, dms_ask_res_req_t *page_req)
{
    dms_ask_res_ack_ld_t ack;
    dms_init_ack_head(&page_req->head, &ack.head, MSG_ACK_EDP_LOCAL, sizeof(dms_ask_res_ack_ld_t), ctx->sess_id);
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_RUN_ERR("[DCS][%s][%s]send failed, src_inst=%d, src_sid=%d, dst_inst=%d, dst_sid=%d, req_mode=%u",
            cm_display_pageid(page_req->resid), dms_get_mescmd_msg(page_req->head.cmd), ack.head.src_inst,
            ack.head.src_sid, ack.head.dst_inst, ack.head.dst_sid, page_req->req_mode);
        return;
    }

    LOG_DEBUG_INF("[DCS][%s][%s]send ok, src_inst=%d, src_sid=%d, dst_inst=%d, dst_sid=%d, req_mode=%u",
        cm_display_pageid(page_req->resid), dms_get_mescmd_msg(page_req->head.cmd), ack.head.src_inst,
        ack.head.src_sid, ack.head.dst_inst, ack.head.dst_sid, page_req->req_mode);
}

static int dcs_owner_transfer_page_ack_v1(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl,
    dms_res_req_info_t *req_info, uint32 cmd)
{
    dms_ask_res_ack_t page_ack = { 0 };

    dms_init_ack_head2(&page_ack.head, cmd, 0, req_info->owner_id,
        req_info->req_id, (uint16)ctx->sess_id, req_info->req_sid, req_info->req_proto_ver);
    page_ack.head.ruid = req_info->req_ruid;

    if (req_info->curr_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        // page will not be sent with ack
        page_ack.head.flags |= MSG_FLAG_NO_PAGE;
        page_ack.head.size = (uint16)sizeof(dms_ask_res_ack_t);
    } else {
        page_ack.head.size = (uint16)(g_dms.page_size + sizeof(dms_ask_res_ack_t));
    }

#ifdef OPENGAUSS
    page_ack.seg_fileno = ctrl->seg_fileno;
    page_ack.seg_blockno = ctrl->seg_blockno;
#endif
    page_ack.lsn = 0;
#ifndef OPENGAUSS
    page_ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
#endif
    page_ack.edp_map = 0;
    if (g_dms.callback.page_is_dirty(ctrl)) {
#ifdef OPENGAUSS
        unsigned long long int page_lsn = g_dms.callback.get_page_lsn(ctrl);
        g_dms.callback.log_wait_flush(ctx->db_handle, page_lsn);
#else
        /*
        * if current page's redo log hasn't been flushed to disk, we need to flush
        * the redo log first, and transfer the max lsn inside current log batch to next owner instance.
        */
        unsigned long long flushed_lfn = g_dms.callback.get_global_flushed_lfn(ctx->db_handle);
        unsigned long long page_lfn = g_dms.callback.get_page_lfn(ctrl);
        if (flushed_lfn < page_lfn) {
            dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_FLUSHLOG, CM_TRUE);
            int ret = g_dms.callback.log_conditional_flush(ctx->db_handle, page_lfn, &page_ack.lsn);
            dms_end_stat(ctx->sess_id);
            if (ret != DMS_SUCCESS) {
                LOG_DEBUG_ERR("[DCS][%s][transfer owner]flush failed: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
                    cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
                    req_info->req_mode);
                return ret;
            }
        }
#endif
    }

    if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        if (g_dms.callback.page_is_dirty(ctrl)) {
            page_ack.edp_map = (ctrl->edp_map) | (1ULL << g_dms.inst_id);
        }
        if (g_dms.callback.page_is_dirty(ctrl)) {
            page_ack.head.flags |= MSG_FLAG_DIRTY_PAGE;
        }

        if (ctrl->is_remote_dirty) {
            page_ack.head.flags |= MSG_FLAG_REMOTE_DIRTY_PAGE;
        }

        if (page_ack.edp_map == 0) {
            page_ack.edp_map = ctrl->edp_map;
        }

        LOG_DEBUG_INF("[DCS][%s][transfer owner]: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
            req_info->req_mode);
    } else {
        // send share copy, multiple share owners are supported on master
        // owner doesn't need to maintain any info. Just send page.
        page_ack.head.flags |= MSG_FLAG_SHARED_PAGE;

        LOG_DEBUG_INF("[DCS][%s][transfer share copy]: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
            req_info->req_mode);
    }

#ifndef OPENGAUSS
    if (page_ack.lsn == 0) {
        /* page is swapped out or page's redo log has been flushed */
        page_ack.lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
    }
#endif

    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE, CM_TRUE);

    int32 ret;
    if (page_ack.head.flags & MSG_FLAG_NO_PAGE) {
        ret = mfc_send_data(&page_ack.head);
    } else {
#ifndef OPENGAUSS
        page_ack.enable_cks = (bool8)g_dms.callback.get_enable_checksum(ctx->db_handle);
        page_ack.checksum = (uint16)g_dms.callback.calc_page_checksum(ctx->db_handle, ctrl, g_dms.page_size);
#endif
        ret = mfc_send_data3(&page_ack.head, sizeof(dms_ask_res_ack_t), (void*)g_dms.callback.get_page(ctrl));
    }

    if (ret == DMS_SUCCESS) {
        DMS_STAT_INC_BUFFER_SENDS(ctx->sess_id);
    }

    dms_end_stat(ctx->sess_id);

    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DCS][%s][%s]:send failed, dest_id=%d, dest_sid=%d, mode=%u, remote dirty=%d, \
            ctrl_lock_mode=%d, ctrl_is_edp=%d, page_lsn=%llu, page_scn=%llu, edp_map=%llu",
            cm_display_pageid(req_info->resid), dms_get_mescmd_msg(page_ack.head.cmd),
            page_ack.head.dst_inst, page_ack.head.dst_sid, req_info->req_mode,
            ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp, page_ack.lsn, page_ack.scn, page_ack.edp_map);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, page_ack.head.cmd, page_ack.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DCS][%s][%s]:send ok, dest_id=%d, dest_sid=%d, req_mode=%u, remote dirty=%d, ctrl_lock_mode=%d,"
        "ctrl_is_edp=%d, global_lsn=%llu, global_scn=%llu, page_lsn=%llu, edp_map=%llu, flags=%u, msg_size=%d",
        cm_display_pageid(req_info->resid), dms_get_mescmd_msg(page_ack.head.cmd), page_ack.head.dst_inst,
        page_ack.head.dst_sid, req_info->req_mode, ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp, page_ack.lsn,
        page_ack.scn, g_dms.callback.get_page_lsn(ctrl), page_ack.edp_map, page_ack.head.flags, page_ack.head.size);

    return DMS_SUCCESS;
}

static int dcs_owner_transfer_page_ack(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl, dms_res_req_info_t *req_info,
    uint32 cmd)
{
    uint32 version = dms_get_node_proto_version(req_info->req_id);
    if (version < DMS_PROTO_VER_2) {
        return dcs_owner_transfer_page_ack_v1(ctx, ctrl, req_info, cmd);
    } else {
        return dcs_owner_transfer_page_ack_v2(ctx, ctrl, req_info, cmd);
    }
}

static int32 dcs_owner_send_granted_ack(dms_process_context_t *ctx, dms_res_req_info_t *req)
{
    dms_ask_res_ack_ld_t ack;
    dms_init_ack_head2(&ack.head, MSG_ACK_GRANT_OWNER, 0, req->owner_id, req->req_id, (uint16)ctx->sess_id,
        req->req_sid, req->req_proto_ver);
    ack.head.ruid  = req->req_ruid;
    ack.head.size = (uint16)sizeof(dms_ask_res_ack_ld_t);
    ack.master_grant = CM_FALSE; /* owner has not loaded page, sharer might exist, grant requested mode only */
#ifndef OPENGAUSS
    ack.master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
    ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
#endif

    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_pageid(req->resid), (uint32)ack.head.src_inst, (uint32)ack.head.src_sid,
            (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)req->req_mode);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DCS][%s]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_pageid(req->resid), (uint32)ack.head.src_inst, (uint32)ack.head.src_sid,
        (uint32)ack.head.dst_inst, (uint32)ack.head.dst_sid, (uint32)req->req_mode);
    return DMS_SUCCESS;
}

static int dcs_owner_transfer_edp(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_LATCH, CM_TRUE);
    dms_buf_ctrl_t *ctrl = NULL;
    int ret = g_dms.callback.read_local_page4transfer(ctx->db_handle, req_info->resid, req_info->req_mode, &ctrl);
    dms_end_stat(ctx->sess_id);

    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_READ_LOCAL_PAGE);
        return ERRNO_DMS_DCS_READ_LOCAL_PAGE;
    }

    if (ctrl == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_READ_LOCAL_PAGE);
        LOG_DEBUG_ERR("[DCS][%s][owner transfer edp]: ctrl is NULL", cm_display_pageid(req_info->resid));
        return ERRNO_DMS_DCS_READ_LOCAL_PAGE;
    }

    ret = dcs_owner_transfer_page_ack(ctx, ctrl, req_info, MSG_ACK_EDP_READY);
    g_dms.callback.leave_local_page(ctx->db_handle, ctrl);
    return ret;
}

static int dcs_notify_remote_for_edp_r(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    int ret;

    if (req_info->owner_id != req_info->req_id) {
        dms_ask_res_req_t page_req = { 0 };
        uint32 send_proto_ver = dms_get_forward_request_proto_version(req_info->owner_id,
            req_info->req_proto_ver);
        DMS_INIT_MESSAGE_HEAD2(&page_req.head, MSG_REQ_ASK_EDP_REMOTE, 0, req_info->req_id, req_info->owner_id,
            req_info->req_sid, CM_INVALID_ID16, send_proto_ver, (uint16)sizeof(dms_ask_res_req_t));
        page_req.req_mode = req_info->req_mode;
        page_req.curr_mode = req_info->curr_mode;
        page_req.res_type = req_info->res_type;
        page_req.len = DMS_PAGEID_SIZE;
        ret = memcpy_s(page_req.resid, DMS_PAGEID_SIZE, req_info->resid, DMS_PAGEID_SIZE);
        DMS_SECUREC_CHECK(ret);

        page_req.head.ruid = req_info->req_ruid; /* forward edp request to owner */
        ret = mfc_forward_request(&page_req.head);
        if (ret == DMS_SUCCESS) {
            LOG_DEBUG_INF("[DCS][%s][%s] send ok: dest_id=%d, dest_sid=%d, mode=%u",
                cm_display_pageid(page_req.resid), "ASK EDP", page_req.head.dst_inst,
                page_req.head.dst_sid, page_req.req_mode);
            return ret;
        }

        LOG_DEBUG_ERR("[DCS][%s][%s]: send failed, dest_id=%d, dest_sid=%d, mode=%u",
            cm_display_pageid(page_req.resid), "ASK EDP", page_req.head.dst_inst,
            page_req.head.dst_sid, page_req.req_mode);
        return ret;
    }

    // asker is already owner, just notify requester(owner) page is ready
    dms_ask_res_ack_ld_t ack;
    dms_init_ack_head2(&ack.head, MSG_ACK_EDP_LOCAL, 0, (uint8)ctx->inst_id, req_info->req_id,
        (uint16)ctx->sess_id, req_info->req_sid, req_info->req_proto_ver);
    ack.head.ruid = req_info->req_ruid;
    ack.head.size = (uint16)sizeof(dms_ask_res_ack_ld_t);

    ret = mfc_send_data(&ack.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][%s]: failed, dest_id=%d, dest_sid=%d, mode=%u", cm_display_pageid(req_info->resid),
            "MASTER ACK EDP LOCAL", ack.head.dst_inst, ack.head.dst_sid, req_info->req_mode);
        return ret;
    }

    LOG_DEBUG_INF("[DCS][%s][%s]: dest_id=%d, dest_sid=%d, mode=%u", cm_display_pageid(req_info->resid),
        "MASTER ACK EDP LOCAL", ack.head.dst_inst, ack.head.dst_sid, req_info->req_mode);
    return DMS_SUCCESS;
}

static int dcs_notify_remote_for_edp(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    LOG_DEBUG_INF("[DCS][%s][dcs_notify_remote_for_edp]: owner_id=%d, curr_mode=%u, req_mode=%u",
        cm_display_pageid(req_info->resid), req_info->owner_id, req_info->curr_mode, req_info->req_mode);

    if (ctx->inst_id != req_info->owner_id) {
        // notify owner to transfer this page to requester
        return dcs_notify_remote_for_edp_r(ctx, req_info);
    }

    // this instance is owner, transfer local page, and requester must be on another instance
    int ret = dcs_owner_transfer_edp(ctx, req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DCS][%s][owner transfer edp]: failed, dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid,
            req_info->req_ruid, req_info->req_mode);
    }

    return ret;
}

int dcs_send_requester_edp_remote(dms_process_context_t *ctx, dms_ask_res_req_t *page_req,
    drc_req_owner_result_t *result)
{
    dms_res_req_info_t req_info = { 0 };
    req_info.owner_id = result->curr_owner_id;
    req_info.req_id = page_req->head.src_inst;
    req_info.req_sid = page_req->head.src_sid;
    req_info.req_ruid = page_req->head.ruid;
    req_info.curr_mode = page_req->curr_mode;
    req_info.req_mode = page_req->req_mode;
    req_info.res_type = page_req->res_type;
    req_info.len = DMS_PAGEID_SIZE;
    req_info.req_proto_ver = page_req->head.msg_proto_ver;
    int ret = memcpy_s(req_info.resid, DMS_PAGEID_SIZE, page_req->resid, DMS_PAGEID_SIZE);
    DMS_SECUREC_CHECK(ret);

    return dcs_notify_remote_for_edp(ctx, &req_info);
}

static void dcs_change_page_status(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl,
    dms_res_req_info_t *req_info)
{
    if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        ctrl->lock_mode = DMS_LOCK_NULL;
        // If multiple S-readings come later, BUF_LOAD_FAILED can ensure only one invokes DCS page request.
        g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_LOAD_FAILED);
        ctrl->is_remote_dirty = 0;
        ctrl->need_flush = 0;

        if (g_dms.callback.page_is_dirty(ctrl)) {
            ctrl->is_edp = CM_TRUE;
#ifndef OPENGAUSS
            ctrl->edp_scn = g_dms.callback.get_global_scn(ctx->db_handle);
#endif
            LOG_DEBUG_INF("[DCS][%s]: lock mode=%d, edp=%d",
                cm_display_pageid(req_info->resid), ctrl->lock_mode, ctrl->is_edp);
        }
    } else {
        cm_panic_log(req_info->req_mode == DMS_LOCK_SHARE, "page request mode error, req_mode=%u", req_info->req_mode);

        if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
            ctrl->lock_mode = DMS_LOCK_SHARE;
        }
    }
}

/*
* owner transfer local page to requester
*/
int dcs_owner_transfer_page(dms_process_context_t *ctx, dms_res_req_info_t *req_info)
{
    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_LATCH, CM_TRUE);

    dms_buf_ctrl_t *ctrl = NULL;
    int ret = g_dms.callback.read_local_page4transfer(ctx->db_handle, req_info->resid, req_info->req_mode, &ctrl);

    dms_end_stat(ctx->sess_id);

    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_READ_LOCAL_PAGE);
        return ERRNO_DMS_DCS_READ_LOCAL_PAGE;
    }

    if (ctrl == NULL) {
        return dcs_owner_send_granted_ack(ctx, req_info);
    }

    dcs_change_page_status(ctx, ctrl, req_info);

    ret = dcs_owner_transfer_page_ack(ctx, ctrl, req_info, MSG_ACK_PAGE_READY);

    g_dms.callback.leave_local_page(ctx->db_handle, ctrl);
    return ret;
}

void dcs_proc_try_ask_master_for_page_owner_id(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE);
    dms_ask_res_req_t page_req = { 0 };
    page_req = *(dms_ask_res_req_t *)(receive_msg->buffer);

    if (SECUREC_UNLIKELY(page_req.req_mode >= DMS_LOCK_MODE_MAX ||
        page_req.curr_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DCS]invalid req_mode=%u, curr_mode=%u", (uint32)page_req.req_mode, (uint32)page_req.curr_mode);
        return;
    }

    drc_req_owner_result_t result;
    drc_request_info_t req_info;
    dms_set_req_info(&req_info, page_req.head.src_inst, page_req.head.src_sid, page_req.head.ruid,
        page_req.curr_mode, page_req.req_mode, CM_TRUE, page_req.sess_type, page_req.req_time, page_req.srsn,
        page_req.head.msg_proto_ver);

    int ret = drc_request_page_owner(page_req.resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_send_error_ack(ctx->inst_id, ctx->sess_id, req_info.inst_id, req_info.sess_id, req_info.ruid, ret,
            req_info.req_proto_ver);
        return;
    }

    dms_message_head_t ack_head;
    ack_head.ruid = page_req.head.ruid;
    ack_head.cluster_ver = DMS_GLOBAL_CLUSTER_VER;

    if (result.type == DRC_REQ_OWNER_GRANTED) {
        // this page_req not in memory of other instance, notify requester to load from disk
        dms_init_ack_head(&page_req.head, &ack_head, MSG_ACK_GRANT_OWNER, sizeof(dms_message_head_t), ctx->sess_id);
        ret = mfc_send_data(&ack_head);
    } else {
        if (result.curr_owner_id == page_req.head.src_inst) {
            // asker is already owner, just notify requester(owner) page_req is ready
            dms_init_ack_head(&page_req.head, &ack_head, MSG_ACK_ALREADY_OWNER,
                sizeof(dms_message_head_t), ctx->sess_id);
            ret = mfc_send_data(&ack_head);
        } else {
            msg_ack_owner_id_t ack;
            dms_init_ack_head(&page_req.head, &ack.head, MSG_ACK_PAGE_OWNER_ID,
                sizeof(msg_ack_owner_id_t), ctx->sess_id);
            ack.owner_id = result.curr_owner_id;
            ret = mfc_send_data(&ack.head);
        }
    }

    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_INF("[DCS][%s][try ask master for page_req]: failed, dest_id=%d, dest_sid=%d, mode=%u",
            cm_display_pageid(page_req.resid), page_req.head.src_inst, page_req.head.src_sid,
            page_req.req_mode);
    }
}

static int dcs_try_get_page_owner_l(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t req_mode,
    uint8 self_id, uint8 *owner_id)
{
    drc_req_owner_result_t result;
    drc_request_info_t req_info;

    uint32 srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    dms_set_req_info(&req_info, self_id, (uint16)dms_ctx->sess_id, 0, ctrl->lock_mode, /* not a real request */
        req_mode, CM_TRUE, dms_ctx->sess_type, g_timer()->now, srsn, DMS_SW_PROTO_VER);

    int ret = drc_request_page_owner(dms_ctx->resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, &req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        return ret;
    }
    LOG_DEBUG_INF("[DCS][%s][dcs_try_get_page_owner_l]: inst_id=%u, sid=%u, owner_id=%u, type=%u",
        cm_display_pageid(dms_ctx->resid), dms_ctx->inst_id,
        dms_ctx->sess_id, (uint32)result.curr_owner_id, (uint32)result.type);

    *owner_id = result.curr_owner_id;

    if (result.type == DRC_REQ_OWNER_GRANTED) {
        return dcs_handle_ack_need_load(dms_ctx, ctrl, self_id, NULL, req_mode);
    }
    if (result.type == DRC_REQ_OWNER_ALREADY_OWNER) {
        return dcs_handle_ack_already_owner_for_try(dms_ctx, ctrl, self_id, req_mode);
    }
    return DMS_SUCCESS;
}

static inline void dcs_set_page_req_parameter(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t req_mode,
    dms_ask_res_req_t *page_req)
{
    page_req->head.size = (uint16)sizeof(dms_ask_res_req_t);
    page_req->req_mode = req_mode;
    page_req->curr_mode = ctrl->lock_mode;
}

static status_t dcs_try_get_page_owner_r(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t req_mode,
    uint8 master_id, uint8 *owner_id)
{
    dms_ask_res_req_t page_req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&page_req.head, MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID, 0, dms_ctx->inst_id, master_id,
        dms_ctx->sess_id, CM_INVALID_ID16);
    page_req.srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);

    dcs_set_page_req_parameter(dms_ctx, ctrl, req_mode, &page_req);
    page_req.len = DMS_PAGEID_SIZE;
    page_req.sess_type = dms_ctx->sess_type;
    int ret = memcpy_sp(page_req.resid, DMS_PAGEID_SIZE, dms_ctx->resid, DMS_PAGEID_SIZE);
    if (SECUREC_UNLIKELY(ret != EOK)) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_TRY, CM_TRUE);

    ret = mfc_send_data(&page_req.head);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR(
            "[DCS][%s][try ask master for page owner id]: failed to send msg, src_id=%d, src_sid=%d, dest_id=%d",
            cm_display_pageid(page_req.resid), page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID,
            page_req.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t msg;
    ret = mfc_get_response(page_req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[DCS][%s][try ask master for page owner id]: ack timeout, src_id=%d, src_sid=%d, dest_id=%d, "
            "ret=%d",
            cm_display_pageid(page_req.resid), page_req.head.src_inst, page_req.head.src_sid,
            page_req.head.dst_inst, ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    dms_end_stat(dms_ctx->sess_id);

    session_stat_t *sess_stat = DMS_GET_SESSION_STAT(dms_ctx->sess_id);
    sess_stat->stat[DMS_STAT_NET_TIME] += sess_stat->wait[sess_stat->level].usecs;

    dms_message_head_t *ack_dms_head = get_dms_head(&msg);
    if (SECUREC_UNLIKELY(ack_dms_head->cmd == MSG_ACK_GRANT_OWNER)) {
        *owner_id = (uint8)dms_ctx->inst_id;
        ret = dcs_handle_ack_need_load(dms_ctx, ctrl, master_id, NULL, req_mode);
    } else if (SECUREC_UNLIKELY(ack_dms_head->cmd == MSG_ACK_ALREADY_OWNER)) {
        *owner_id = (uint8)dms_ctx->inst_id;
        ret = dcs_handle_ack_already_owner_for_try(dms_ctx, ctrl, master_id, req_mode);
    } else if (SECUREC_UNLIKELY(ack_dms_head->cmd == MSG_ACK_PAGE_OWNER_ID)) {
        CM_CHK_RESPONSE_SIZE(&msg, (uint32)sizeof(msg_ack_owner_id_t), CM_FALSE);
        *owner_id = (uint8)(*(uint32 *)DMS_MESSAGE_BODY(&msg));
    } else {
        cm_print_error_msg(msg.buffer);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, msg.buffer + sizeof(msg_error_t));
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    LOG_DEBUG_INF("[DCS][%s][try ask master for page owner id]: src_id=%d, dest_id=%d, flag=%d, owner_id=%d"
        ", lock_mode=%d", cm_display_pageid(page_req.resid), msg.head->src_inst, msg.head->dst_inst, msg.head->flags,
        (*owner_id), ctrl->lock_mode);

    mfc_release_response(&msg);
    return ret;
}

int dms_try_ask_master_for_page_owner_id(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl,
    dms_lock_mode_t req_mode, unsigned char *owner_id)
{
    dms_reset_error();
    uint8 master_id = CM_INVALID_ID8;
    int ret = drc_get_page_master_id(dms_ctx->resid, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    LOG_DEBUG_INF("[DCS][%s][try get page owner]: req_mode=%u", cm_display_pageid(dms_ctx->resid), req_mode);

    if (master_id == dms_ctx->inst_id) {
        return dcs_try_get_page_owner_l(dms_ctx, ctrl, req_mode, (uint8)dms_ctx->inst_id, owner_id);
    } else {
        return dcs_try_get_page_owner_r(dms_ctx, ctrl, req_mode, master_id, owner_id);
    }
}

static int dcs_send_rls_owner_req(dms_context_t *dms_ctx, uint8 master_id, uint64 *ruid)
{
    msg_rls_owner_req_t req;
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_RELEASE_OWNER, 0, dms_ctx->inst_id, master_id, dms_ctx->sess_id,
        CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(msg_rls_owner_req_t);

    req.sess_type = dms_ctx->sess_type;
#ifndef OPENGAUSS
    req.owner_lsn = g_dms.callback.get_global_lsn(dms_ctx->db_handle);
    req.owner_scn = g_dms.callback.get_global_scn(dms_ctx->db_handle);
#endif
    if (memcpy_sp(req.pageid, DMS_PAGEID_SIZE, dms_ctx->resid, DMS_PAGEID_SIZE) != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_COMMON_COPY_PAGEID_FAIL;
    }

    int32 ret = mfc_send_data(&req.head);
    *ruid = req.head.ruid;
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][send release own req]:src_sid=%u, dest_id=%d, owner_lsn=%llu, owner_scn=%llu, ruid=%llu",
            cm_display_pageid(dms_ctx->resid), dms_ctx->sess_id, master_id, req.owner_lsn, req.owner_scn,
            req.head.ruid);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, req.head.cmd, req.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    LOG_DEBUG_INF("[DCS][%s][send release own req]:src_sid=%u, dest_id=%d, owner_lsn=%llu, owner_scn=%llu, ruid=%llu",
        cm_display_pageid(dms_ctx->resid), dms_ctx->sess_id, master_id, req.owner_lsn, req.owner_scn,
        req.head.ruid);
    return ret;
}

static int dcs_release_owner_r(dms_context_t *dms_ctx, uint8 master_id, unsigned char *released)
{
    dms_message_t msg;
    uint64 ruid = 0;

    int ret = dcs_send_rls_owner_req(dms_ctx, master_id, &ruid);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = mfc_get_response(ruid, &msg, DCS_WAIT_MSG_TIMEOUT);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][release owner ack fail] error: %d", cm_display_pageid(dms_ctx->resid), ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    CM_CHK_RESPONSE_SIZE(&msg, (uint32)sizeof(msg_rls_owner_ack_t), CM_FALSE);
    msg_rls_owner_ack_t *ack = (msg_rls_owner_ack_t *)msg.buffer;
    *released = ack->released;

    LOG_DEBUG_INF("[DCS][%s][release owner result]: released=%d", cm_display_pageid(dms_ctx->resid), (*released));
    mfc_release_response(&msg);
    return DMS_SUCCESS;
}

static inline int dcs_release_owner_l(dms_context_t *dms_ctx, unsigned char *released)
{
    *released = drc_chk_4_release(dms_ctx->resid, DMS_PAGEID_SIZE, (uint8)dms_ctx->inst_id);

    LOG_DEBUG_INF("[DCS][%s][local release owner]: src_id=%d, src_sid=%d, released=%d",
        cm_display_pageid(dms_ctx->resid), dms_ctx->inst_id, dms_ctx->sess_id, (int32)*released);
    return DMS_SUCCESS;
}

int dcs_release_owner(dms_context_t *dms_ctx, unsigned char *released)
{
    LOG_DEBUG_INF("[DCS][%s][dcs_release_owner] entry", cm_display_pageid(dms_ctx->resid));

    unsigned char master_id;
    int ret = DMS_SUCCESS;
    if (drc_get_page_master_id(dms_ctx->resid, &master_id) != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_PAGE_MASTER_ID);
        return ERRNO_DMS_DCS_PAGE_MASTER_ID;
    }

    if (master_id == dms_ctx->inst_id) {
        ret = dcs_release_owner_l(dms_ctx, released);
    } else {
        dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_RELEASE_OWNER, CM_TRUE);
        ret = dcs_release_owner_r(dms_ctx, master_id, released);
        dms_end_stat(dms_ctx->sess_id);
    }

    return ret;
}

static int dcs_send_rls_owner_ack(dms_process_context_t *ctx, msg_rls_owner_req_t *req, bool8 released)
{
    msg_rls_owner_ack_t ack;
    dms_init_ack_head(&req->head, &ack.head, MSG_ACK_RELEASE_PAGE_OWNER, sizeof(msg_rls_owner_ack_t), ctx->inst_id);
    ack.released = released;
    int ret = mfc_send_data(&ack.head);
    LOG_DEBUG_INF("[DCS][%s][proc release owner req]: src_id=%d, src_sid=%d, owner_lsn=%llu, owner_scn=%llu, "
        "ruid=%llu, released =%d", cm_display_pageid(req->pageid), req->head.src_inst, req->head.src_sid,
        req->owner_lsn, req->owner_scn, req->head.ruid, ack.released);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, ack.head.cmd, ack.head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }
    return ret;
}

void dcs_proc_release_owner_req(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(msg_rls_owner_req_t), CM_TRUE);
    msg_rls_owner_req_t req = *(msg_rls_owner_req_t *)(receive_msg->buffer);

    LOG_DEBUG_INF("[DCS][%s][proc release owner req]: src_id=%d, src_sid=%d, owner_lsn=%llu, owner_scn=%llu, ruid=%llu",
        cm_display_pageid(req.pageid), req.head.src_inst, req.head.src_sid, req.owner_lsn, req.owner_scn,
        req.head.ruid);

#ifndef OPENGAUSS
    // Need to sync scn/lsn with master when releasing ownership
    g_dms.callback.update_global_lsn(ctx->db_handle, req.owner_lsn);
    g_dms.callback.update_global_scn(ctx->db_handle, req.owner_scn);
#endif

    bool8 released = drc_chk_4_release(req.pageid, DMS_PAGEID_SIZE, req.head.src_inst);
    (void)dcs_send_rls_owner_ack(ctx, &req, released);
}

int dms_release_owner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, unsigned char *released)
{
    dms_reset_error();
    int ret = dcs_release_owner(dms_ctx, released);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (*released) {
        ctrl->lock_mode = DMS_LOCK_NULL;
    }
    return DMS_SUCCESS;
}

int dms_buf_res_rebuild_drc_parallel(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, unsigned char thread_index)
{
    dms_reset_error();
    uint8 master_id = CM_INVALID_ID8;
    int ret = drc_get_page_remaster_id(dms_ctx->resid, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DRC][%s]dms_buf_res_rebuild_drc, fail to get remaster id", cm_display_pageid(dms_ctx->resid));
        return ret;
    }
    LOG_DEBUG_INF("[DRC][%s]dms_buf_res_rebuild_drc, remaster(%d)", cm_display_pageid(dms_ctx->resid), master_id);
    return dms_reform_send_ctrl_info(dms_ctx, ctrl_info, master_id, thread_index);
}

void dcs_proc_ask_remote_for_edp(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
#else
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_ask_res_req_t), CM_TRUE);
    dms_ask_res_req_t page_req = *(dms_ask_res_req_t *)(receive_msg->buffer);

    LOG_DEBUG_INF("[DCS][%s][dcs_proc_ask_remote_for_edp]: started, owner_id=%d, req_id=%d, "
        "req_sid=%d, req_ruid=%llu, req_mode=%u, curr_mode=%u",
        cm_display_pageid(page_req.resid), ctx->inst_id, page_req.head.src_inst, page_req.head.src_sid,
        page_req.head.ruid, page_req.req_mode, page_req.curr_mode);

    dms_res_req_info_t req_info = { 0 };
    req_info.owner_id = page_req.head.dst_inst;
    req_info.req_id = page_req.head.src_inst;
    req_info.req_sid = page_req.head.src_sid;
    req_info.curr_mode = page_req.curr_mode;
    req_info.req_mode = page_req.req_mode;
    req_info.req_ruid = page_req.head.ruid;
    req_info.len = DMS_PAGEID_SIZE;
    req_info.req_proto_ver = page_req.head.msg_proto_ver;
    int ret = memcpy_sp(req_info.resid, DMS_RESID_SIZE, page_req.resid, DMS_PAGEID_SIZE);
    DMS_SECUREC_CHECK(ret);

    ret = dcs_owner_transfer_edp(ctx, &req_info);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_ERR("[DCS][%s][owner transfer edp]: failed, owner_id=%d, req_id=%d, req_sid=%d, req_ruid=%llu, "
            "mode=%u",
            cm_display_pageid(req_info.resid), req_info.owner_id, req_info.req_id, req_info.req_sid, req_info.req_ruid,
            req_info.req_mode);
    }
#endif
}

void drc_proc_buf_ctrl_recycle(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    LOG_DEBUG_INF("[DRC recycle]receive from inst: %d", receive_msg->head->src_inst);
    if (g_dms.callback.buf_ctrl_recycle != NULL) {
        g_dms.callback.buf_ctrl_recycle(ctx->db_handle);
    }
}

#ifdef __cplusplus
}
#endif
