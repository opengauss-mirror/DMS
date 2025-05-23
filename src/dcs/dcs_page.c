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
#include "dms_msg_protocol.h"
#include "cm_encrypt.h"
#include "dms_dynamic_trace.h"

#ifdef __cplusplus
extern "C" {
#endif
static inline bool8 dcs_is_reform_visit(dms_buf_ctrl_t *ctrl)
{
    return (bool8)ctrl->is_reform_visit;
}

static inline void dcs_set_ctrl_in_rcy(dms_context_t* dms_ctx, dms_buf_ctrl_t *ctrl)
{
    ctrl->in_rcy = (dms_ctx->sess_type == DMS_SESSION_RECOVER);
}

static inline int32 dcs_set_ctrl4already_owner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, dms_lock_mode_t mode)
{
    /* owner has no edp */
    ctrl->lock_mode = mode;
    ctrl->is_edp = 0;
    LOG_DEBUG_INF("[DCS][%s]: lock mode=%d, edp=%d, been_loaded=%d", cm_display_pageid(dms_ctx->resid),
        ctrl->lock_mode, ctrl->is_edp, ctrl->been_loaded);
    /*
     * 1. has processed x-mode historical transfer request,
     *  buf page does not swap out and in, so it is the latest in memory
     * 2. page is already owned by requester, S->X req_mode, no need to load from disk
     */
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    if (ctrl->been_loaded) {
        return g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_IS_LOADED);
    }
    /* 3.page swap out and in, but buf res not be recycled, need to load from disk */
    return g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_NEED_LOAD);
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
    ctrl->edp_map = 0;
    /* if no owner exists, master grants X; if owner exists on DRC but local ctrl null, grant S */
    ctrl->lock_mode = granted_mode;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
    g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_NEED_LOAD);
}

int32 dcs_handle_prepare_need_load(dms_context_t *dms_ctx, dms_message_t *msg, dms_buf_ctrl_t *ctrl,
    dms_lock_mode_t *granted_mode)
{
    dms_ask_res_ack_ld_t *ack = NULL;
    if (msg != NULL) {
        CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_ld_t), CM_FALSE);
        ack = (dms_ask_res_ack_ld_t *)msg->buffer;
#ifndef OPENGAUSS
        // load page from disk, need to sync scn/lsn with master
        g_dms.callback.update_global_lsn(dms_ctx->db_handle, ack->master_lsn);
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
        if (ack->node_count > 0) {
            g_dms.callback.update_node_lfns(dms_ctx->db_handle, &((dms_ask_res_ack_ld_wrapper_t *)ack)->node_lfn[0],
                ack->node_count);
        }
#endif
    }
    /*
     * if no existing owner, master grants to requestor locally/remotely, grant X;
     * if owner acks and grants owner, meaning sharer exists potentially, grant S.
     */
    if (ack == NULL || ack->master_grant == CM_TRUE) {
        *granted_mode = DMS_LOCK_EXCLUSIVE;
    }

    dcs_set_ctrl4granted(dms_ctx, ctrl, *granted_mode);
    LOG_DYN_TRC_INF("[HNL][%s]lmode=%u",
        cm_display_resid(dms_ctx->resid, dms_ctx->type), (uint32)ctrl->lock_mode);
    return DMS_SUCCESS;
}

int32 dcs_handle_ack_need_load(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode, uint64 seq)
{
    cm_spin_lock(&ctrl->lock_ss_read, NULL);
    if (dcs_is_reform_visit(ctrl)) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_REFORM_VISIT_RES, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_DCS_REFORM_VISIT_RES;
    }
    dms_lock_mode_t granted_mode = mode;
    int32 ret = dcs_handle_prepare_need_load(dms_ctx, msg, ctrl, &granted_mode);
    if (ret != DMS_SUCCESS) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        return ret;
    }
    ctrl->seq = MAX(seq, ctrl->seq);
    cm_spin_unlock(&ctrl->lock_ss_read);

    dms_claim_ownership(dms_ctx, master_id, granted_mode, CM_FALSE, CM_INVALID_ID64);

    return DMS_SUCCESS;
}

int32 dcs_handle_ack_already_owner(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode, uint64 seq)
{
    cm_spin_lock(&ctrl->lock_ss_read, NULL);
    if (dcs_is_reform_visit(ctrl)) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_REFORM_VISIT_RES, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_DCS_REFORM_VISIT_RES;
    }

#ifndef OPENGAUSS
    if (msg != NULL) {
        dms_already_owner_ack_t *ack = (dms_already_owner_ack_t *)(msg->buffer);
        g_dms.callback.update_global_scn(dms_ctx->db_handle, ack->scn);
    }
#endif

    int ret = dcs_set_ctrl4already_owner(dms_ctx, ctrl, mode);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        return ret;
    }
    ctrl->seq = MAX(seq, ctrl->seq);
    cm_spin_unlock(&ctrl->lock_ss_read);

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, page_lsn);
    return DMS_SUCCESS;
}

static int dcs_handle_page_from_owner(dms_context_t *dms_ctx,
    dms_buf_ctrl_t *ctrl, dms_message_t *msg, dms_lock_mode_t mode)
{
    CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_t), CM_FALSE);
    dms_ask_res_ack_t *ack = (dms_ask_res_ack_t *)(msg->buffer);

    uint32 node_data_size = 0;
#ifndef OPENGAUSS
    uint32 node_data_len = 0;
    uint64 *node_data = NULL;
    if (ack->node_cnt != 0) {
        node_data_len = DMS_STANDBY_GET_NODE_DATA_LEN(ack->node_cnt);
        node_data_size = node_data_len * (uint32)sizeof(uint64);
        node_data = (uint64 *)(msg->buffer + sizeof(dms_ask_res_ack_t));
    }
#endif

    if (ack->head.cmd == MSG_ACK_PAGE_READY && !(ack->head.flags & MSG_FLAG_NO_PAGE)) {
        CM_CHK_PROC_MSG_SIZE(msg, (uint32)(sizeof(dms_ask_res_ack_t) + node_data_size + g_dms.page_size), CM_FALSE);
#ifdef OPENGAUSS
        ctrl->seg_fileno = ack->seg_fileno;
        ctrl->seg_blockno = ack->seg_blockno;
        if (!ctrl->need_check_pincount) {
            ctrl->need_check_pincount = ack->need_check_pincount;
        }
        ctrl->lsn_on_disk = ack->lsn_on_disk;
        if (g_dms.callback.verify_page != NULL) {
            g_dms.callback.verify_page(ctrl, msg->buffer + sizeof(dms_ask_res_ack_t));
        }
#endif
        int ret = memcpy_s(g_dms.callback.get_page(ctrl), g_dms.page_size,
            msg->buffer + sizeof(dms_ask_res_ack_t) + node_data_size, g_dms.page_size);
        DMS_SECUREC_CHECK(ret);

#ifndef OPENGAUSS
        if (ack->enable_cks &&
            !g_dms.callback.verify_page_checksum(dms_ctx->db_handle, ctrl, g_dms.page_size, ack->checksum)) {
            LOG_RUN_ERR("[DCS][%s][%s]: page checksum failed", cm_display_pageid(dms_ctx->resid),
                dms_get_mescmd_msg(msg->head->cmd));
            DMS_THROW_ERROR(ERRNO_DMS_DCS_PAGE_CHECKSUM_FAILED);
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

    if (ack->node_cnt == 0) {
        g_dms.callback.update_node_lfn(dms_ctx->db_handle, ack->node_id, ack->node_lfn);
    } else {
        g_dms.callback.update_replay_lfns(dms_ctx->db_handle, node_data, node_data_len);
    }

#endif

    ctrl->lock_mode = mode;
    ctrl->edp_map = (ack->edp_map) & (~(1ULL << dms_ctx->inst_id));

    if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
        ctrl->is_edp = 0;
        LOG_DEBUG_INF("[DCS][%s][%s]: lock mode=%d, edp=%d, src_id=%d, src_sid=%d, dest_id=%d, dest_sid=%d, dirty=%d,"
            "remote diry=%d, global_lsn=%llu, global_scn=%llu", cm_display_pageid(dms_ctx->resid),
            dms_get_mescmd_msg(ack->head.cmd), ctrl->lock_mode, ctrl->is_edp, msg->head->src_inst, msg->head->src_sid,
            msg->head->dst_inst, msg->head->dst_sid, DCS_ACK_PAGE_IS_DIRTY(msg), DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg),
            ack->lsn, ack->scn);
#ifndef OPENGAUSS
        if (ctrl->edp_map != 0) {
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
    CM_MFENCE;
    dcs_set_ctrl_in_rcy(dms_ctx, ctrl);
#ifndef OPENGAUSS
    g_dms.callback.stats_buf(dms_ctx->db_handle, ctrl, DMS_BUF_STATS_LOAD);
#endif
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
    cm_spin_lock(&ctrl->lock_ss_read, NULL);
    dms_ask_res_ack_t *ack = (dms_ask_res_ack_t *)(msg->buffer);
    if (dcs_is_reform_visit(ctrl)) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_REFORM_VISIT_RES, cm_display_pageid(dms_ctx->resid));
        return ERRNO_DMS_DCS_REFORM_VISIT_RES;
    }

    int32 ret = dcs_handle_page_from_owner(dms_ctx, ctrl, msg, mode);
    if (ret != DMS_SUCCESS) {
        cm_spin_unlock(&ctrl->lock_ss_read);
        return ret;
    }
    uint64 seq = ack->head.seq;
    ctrl->seq = MAX(seq, ctrl->seq);
    cm_spin_unlock(&ctrl->lock_ss_read);

    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    dms_claim_ownership(dms_ctx, (uint8)master_id, mode, DCS_ACK_PAGE_IS_DIRTY(msg), page_lsn);
#ifndef OPENGAUSS
    g_dms.callback.inc_buffer_remote_reads(dms_ctx->db_handle);
#endif
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
    if (!reform_info->first_reform_finish && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
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
    dms_ctx->is_timeout = (ret == ERRNO_DMS_DCS_RECV_MSG_FAULT);
    return ret;
}

int32 dcs_send_ack_page(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl,
    dms_res_req_info_t *req_info, dms_ask_res_ack_t *page_ack)
{
    int32 ret;
    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE, CM_TRUE);
    dms_dyn_trc_begin(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE);

    if (page_ack->head.flags & MSG_FLAG_NO_PAGE) {
        ret = mfc_send_data(&page_ack->head);
    } else {
        uint32 node_data_size = 0;
#ifndef OPENGAUSS
        page_ack->enable_cks = (bool8)g_dms.callback.get_enable_checksum(ctx->db_handle);
        page_ack->checksum = (uint16)g_dms.callback.calc_page_checksum(ctx->db_handle, ctrl, g_dms.page_size);
        if (page_ack->node_cnt != 0) {
            node_data_size = DMS_STANDBY_GET_NODE_DATA_LEN(page_ack->node_cnt) * (uint32)sizeof(uint64);
        }
#endif
        ret = mfc_send_data3(&page_ack->head, sizeof(dms_ask_res_ack_t) + node_data_size,
            (void*)g_dms.callback.get_page(ctrl));
    }

    if (ret == DMS_SUCCESS) {
        DMS_STAT_INC_BUFFER_SENDS(ctx->sess_id);
    }

    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DYN_TRC_ERR("[SAP][%s]dstid=%d dsid=%d mode=%u lmode=%d isedp=%d plsn=%llu pscn=%llu edpmap=%llu",
            cm_display_pageid(req_info->resid), page_ack->head.dst_inst, page_ack->head.dst_sid,
            req_info->req_mode, ctrl->lock_mode, ctrl->is_edp, page_ack->lsn, page_ack->scn, page_ack->edp_map);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, page_ack->head.cmd, page_ack->head.dst_inst);
        dms_dyn_trc_end(ctx->sess_id);
        dms_end_stat(ctx->sess_id);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DYN_TRC_INF("[SAP][%s]sent dstid=%d dsid=%d rmode=%u cmode=%d is_edp=%d glsn=%llu gscn=%llu plsn=%llu"
        "edp_map=%llu flags=%u size=%d", cm_display_pageid(req_info->resid), page_ack->head.dst_inst,
        page_ack->head.dst_sid, req_info->req_mode, ctrl->lock_mode, ctrl->is_edp, page_ack->lsn,
        page_ack->scn, g_dms.callback.get_page_lsn(ctrl), page_ack->edp_map, page_ack->head.flags,
        page_ack->head.size);

    dms_dyn_trc_end(ctx->sess_id);
    dms_end_stat(ctx->sess_id);
    return ret;
}

static int dcs_owner_transfer_page_ack(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl, dms_res_req_info_t *req_info,
    uint32 cmd)
{
    dms_ask_res_ack_wrapper page_ack_wrapper = { 0 };
    dms_ask_res_ack_t *page_ack = &page_ack_wrapper.res_ack;
    dms_init_ack_head2(&page_ack->head, cmd, 0, req_info->owner_id,
        req_info->req_id, (uint16)ctx->sess_id, req_info->req_sid, req_info->req_proto_ver);
    page_ack->head.ruid = req_info->req_ruid;
    page_ack->head.seq = req_info->seq;
    uint32 node_data_size = 0;
#ifndef OPENGAUSS
    uint32 node_data_len = 0;
    unsigned int db_role;
    g_dms.callback.get_db_role(ctx->db_handle, &db_role);
    if (db_role != DMS_DB_ROLE_PRIMARY) {
        page_ack->node_cnt = g_dms.inst_cnt;
        node_data_len = DMS_STANDBY_GET_NODE_DATA_LEN(page_ack->node_cnt);
        node_data_size = node_data_len * (uint32)sizeof(uint64);
    } else {
        page_ack->node_cnt = 0;
    }
#endif

    if (req_info->curr_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        // page will not be sent with ack
        page_ack->head.flags |= MSG_FLAG_NO_PAGE;
        page_ack->head.size = (uint16)sizeof(dms_ask_res_ack_t) + node_data_size;
    } else {
        page_ack->head.size = (uint16)(g_dms.page_size + sizeof(dms_ask_res_ack_t)) + node_data_size;
    }

#ifdef OPENGAUSS
    page_ack->seg_fileno = ctrl->seg_fileno;
    page_ack->seg_blockno = ctrl->seg_blockno;
    page_ack->need_check_pincount = ctrl->need_check_pincount;
    page_ack->lsn_on_disk = ctrl->lsn_on_disk;
#endif
    page_ack->lsn = 0;
#ifndef OPENGAUSS
    page_ack->scn = g_dms.callback.get_global_scn(ctx->db_handle);
#endif
    page_ack->edp_map = 0;
    if (g_dms.callback.page_is_dirty(ctrl)) {
#ifdef OPENGAUSS
        unsigned long long int page_lsn = g_dms.callback.get_page_lsn(ctrl);
        g_dms.callback.log_wait_flush(ctx->db_handle, page_lsn);
#else
        /*
        * if current page's redo log hasn't been flushed to disk, we need to flush
        * the redo log first, and transfer the max lsn inside current log batch to next owner instance.
        */
        g_dms.callback.get_global_flushed_lfn(ctx->db_handle, &page_ack->node_id, &page_ack->node_lfn);
        unsigned long long flushed_lfn = page_ack->node_lfn;
        unsigned long long page_lfn = g_dms.callback.get_page_lfn(ctrl);
        if (flushed_lfn < page_lfn && db_role == DMS_DB_ROLE_PRIMARY) {
            dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_FLUSHLOG, CM_TRUE);
            int ret = g_dms.callback.log_conditional_flush(ctx->db_handle, page_lfn, &page_ack->lsn);
            if (ret != DMS_SUCCESS) {
                LOG_DEBUG_ERR("[DCS][%s][transfer owner]flush failed: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
                    cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
                    req_info->req_mode);
                dms_end_stat(ctx->sess_id);
                return ret;
            }
            dms_end_stat(ctx->sess_id);
        }
#endif
    }

#ifndef OPENGAUSS
    g_dms.callback.get_global_flushed_lfn(ctx->db_handle, &page_ack->node_id, &page_ack->node_lfn);
    if (page_ack->node_cnt != 0) {
        g_dms.callback.get_replay_lfns(ctx->db_handle, &page_ack_wrapper.data[0], node_data_len);
    }
    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_LSNDWAIT, CM_TRUE);
    g_dms.callback.lsnd_wait(ctx->db_handle, page_ack->node_lfn);
    dms_end_stat(ctx->sess_id);
#endif

    // it will transfer owner, so need to set EDP map
    if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        page_ack->edp_map = ctrl->edp_map;
        if (g_dms.callback.page_is_dirty(ctrl)) {
            page_ack->edp_map = page_ack->edp_map | (1ULL << g_dms.inst_id);
        }
    } else {
        page_ack->edp_map = 0;
    }

    if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        if (g_dms.callback.page_is_dirty(ctrl)) {
            page_ack->head.flags |= MSG_FLAG_DIRTY_PAGE;
        }
        if (ctrl->edp_map != 0) {
            page_ack->head.flags |= MSG_FLAG_REMOTE_DIRTY_PAGE;
        }

        LOG_DEBUG_INF("[DCS][%s][transfer owner]: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
            req_info->req_mode);
    } else {
        // send share copy, multiple share owners are supported on master
        // owner doesn't need to maintain any info. Just send page.
        page_ack->head.flags |= MSG_FLAG_SHARED_PAGE;

        LOG_DEBUG_INF("[DCS][%s][transfer share copy]: dest_id=%d, dest_sid=%d, dest_ruid=%llu, mode=%u",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid,
            req_info->req_mode);
    }

#ifndef OPENGAUSS
    if (page_ack->lsn == 0) {
        /* page is swapped out or page's redo log has been flushed */
        page_ack->lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
    }
#endif

    return dcs_send_ack_page(ctx, ctrl, req_info, page_ack);
}

static int32 dcs_owner_send_granted_ack(dms_process_context_t *ctx, dms_res_req_info_t *req)
{
    dms_ask_res_ack_ld_wrapper_t ack_wrapper;
    dms_ask_res_ack_ld_t *ack = &ack_wrapper.ack;
    unsigned short size = (unsigned short)sizeof(dms_ask_res_ack_ld_t);
    dms_init_ack_head2(&ack->head, MSG_ACK_GRANT_OWNER, 0, req->owner_id, req->req_id, (uint16)ctx->sess_id,
        req->req_sid, req->req_proto_ver);
    ack->head.ruid  = req->req_ruid;
    ack->head.seq = req->seq;
    ack->master_grant = CM_FALSE; /* owner has not loaded page, sharer might exist, grant requested mode only */
#ifndef OPENGAUSS
    size += g_dms.inst_cnt * sizeof(uint64);
    ack->master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
    ack->scn = g_dms.callback.get_global_scn(ctx->db_handle);
    g_dms.callback.get_node_lfns(ctx->db_handle, &ack_wrapper.node_lfn[0], g_dms.inst_cnt);
    ack->node_count = g_dms.inst_cnt;
#else
    ack->node_count = 0;
#endif
    ack->head.size = size;

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_GRANT_OWNER, MSG_ACK_GRANT_OWNER);
    int32 ret = mfc_send_data(&ack->head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s]send failed, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
            cm_display_pageid(req->resid), (uint32)ack->head.src_inst, (uint32)ack->head.src_sid,
            (uint32)ack->head.dst_inst, (uint32)ack->head.dst_sid, (uint32)req->req_mode);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, ack->head.cmd, ack->head.dst_inst);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    LOG_DEBUG_INF("[DCS][%s]send OK, src_inst=%u, src_sid=%u, dst_inst=%u, dst_sid=%u, req_mode=%u",
        cm_display_pageid(req->resid), (uint32)ack->head.src_inst, (uint32)ack->head.src_sid,
        (uint32)ack->head.dst_inst, (uint32)ack->head.dst_sid, (uint32)req->req_mode);
    return DMS_SUCCESS;
}

static void dcs_change_page_status(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl,
    dms_res_req_info_t *req_info)
{
    if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        ctrl->lock_mode = DMS_LOCK_NULL;
#ifndef OPENGAUSS
        g_dms.callback.stats_buf(ctx->db_handle, ctrl, DMS_BUF_STATS_EXPIRE);
#endif
        // If multiple S-readings come later, BUF_LOAD_FAILED can ensure only one invokes DCS page request.
        g_dms.callback.set_buf_load_status(ctrl, DMS_BUF_LOAD_FAILED);
        if (g_dms.callback.page_is_dirty(ctrl)) {
            ctrl->is_edp = CM_TRUE;
#ifndef OPENGAUSS
            unsigned long long page_lsn = g_dms.callback.get_page_lsn(ctrl);
            if (page_lsn > ctrl->edp_lsn) {
                ctrl->edp_lsn = page_lsn;
                ctrl->edp_scn = g_dms.callback.get_global_scn(ctx->db_handle);
            }
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
    int ret = g_dms.callback.read_local_page4transfer(ctx->db_handle, req_info->resid, req_info->req_mode, &ctrl,
        req_info->seq);

    dms_end_stat(ctx->sess_id);

    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_READ_LOCAL_PAGE);
        return ERRNO_DMS_DCS_READ_LOCAL_PAGE;
    }

    if (ctrl == NULL) {
        return dcs_owner_send_granted_ack(ctx, req_info);
    }

    dcs_change_page_status(ctx, ctrl, req_info);
    DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(DB_FI_CHANGE_STATUS_AFTER_TRANSFER_PAGE,
        cm_sleep(ddes_fi_get_entry_value(DDES_FI_TYPE_CUSTOM_FAULT)));
    ret = dcs_owner_transfer_page_ack(ctx, ctrl, req_info, MSG_ACK_PAGE_READY);

    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_PAGE_READY, MSG_ACK_PAGE_READY);
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

#ifndef OPENGAUSS
    if (ctx->db_handle != NULL) {
        g_dms.callback.update_global_scn(ctx->db_handle, page_req.scn);
    }
#endif

    drc_req_owner_result_t result;
    drc_request_info_t *req_info = &page_req.drc_reg_info;
    req_info->ruid = page_req.head.ruid;

    LOG_DEBUG_INF("[DMS][%s][dcs_proc_try_ask_master_for_page]: src_id=%d, src_sid=%d, req_mode=%u, curr_mode=%u",
        cm_display_resid(page_req.resid, page_req.res_type), page_req.head.src_inst, page_req.head.src_sid,
        page_req.req_mode, page_req.curr_mode);

    int ret = drc_request_page_owner(ctx, page_req.resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, req_info, &result);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        dms_send_error_ack(ctx, req_info->inst_id, req_info->sess_id, req_info->ruid, ret, req_info->req_proto_ver);
        return;
    }

    LOG_DEBUG_INF("[DMS][%s][dcs_proc_try_ask_master_for_page]success, type=%d",
        cm_display_resid(page_req.resid, page_req.res_type), result.type);

    if (result.type == DRC_REQ_OWNER_GRANTED) {
        // this page_req not in memory of other instance, notify requester to load from disk
        dms_ask_res_ack_ld_wrapper_t ack_wrapper;
        dms_ask_res_ack_ld_t *ack = &ack_wrapper.ack;
        unsigned short size = (unsigned short)sizeof(dms_ask_res_ack_ld_t);
#ifndef OPENGAUSS
        size += g_dms.inst_cnt * sizeof(uint64);
        ack->scn = g_dms.callback.get_global_scn(ctx->db_handle);
        ack->master_lsn = g_dms.callback.get_global_lsn(ctx->db_handle);
        g_dms.callback.get_node_lfns(ctx->db_handle, &ack_wrapper.node_lfn[0], g_dms.inst_cnt);
        ack->node_count = g_dms.inst_cnt;
#else
        ack->node_count = 0;
#endif
        ack->master_grant = CM_TRUE;
        dms_init_ack_head(&page_req.head, &ack->head, MSG_ACK_GRANT_OWNER, size, ctx->sess_id);
        ack->head.seq = result.seq;

        DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_GRANT_OWNER, MSG_ACK_GRANT_OWNER);
        ret = mfc_send_data(&ack->head);
    } else if (result.type == DRC_REQ_OWNER_ALREADY_OWNER) {
        // asker is already owner, just notify requester(owner) page_req is ready
        dms_already_owner_ack_t ack;
        ack.head.seq = result.seq;
        dms_init_ack_head(&page_req.head, &ack.head, MSG_ACK_ALREADY_OWNER,
            sizeof(dms_already_owner_ack_t), ctx->sess_id);
#ifndef OPENGAUSS
        ack.scn = g_dms.callback.get_global_scn(ctx->db_handle);
#endif
        DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_ALREADY_OWNER, MSG_ACK_ALREADY_OWNER);
        ret = mfc_send_data(&ack.head);
    } else {
        msg_ack_owner_id_t ack;
        dms_init_ack_head(&page_req.head, &ack.head, MSG_ACK_PAGE_OWNER_ID,
            sizeof(msg_ack_owner_id_t), ctx->sess_id);
        ack.owner_id = result.curr_owner_id;
        DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_PAGE_OWNER_ID, MSG_ACK_PAGE_OWNER_ID);
        ret = mfc_send_data(&ack.head);
    }

    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        LOG_DEBUG_INF("[DCS][%s][try ask master for page_req]: failed, dest_id=%d, dest_sid=%d, mode=%u",
            cm_display_pageid(page_req.resid), page_req.head.src_inst, page_req.head.src_sid,
            page_req.req_mode);
    }
}

typedef struct st_dms_ctrl_wrapper {
    dms_buf_ctrl_t *ctrl;
    unsigned long long ruid;
    uint8 master_id;
    uint8 owner_id;
    int32 result;
} dms_ctrl_wrapper_t;

static int32 dcs_try_get_page_owner_id_batch(dms_context_t *dms_ctx,
    dms_ctrl_wrapper_t *ctrl_wraps, uint32 req_count, dms_lock_mode_t req_mode)
{
    char *pageid = NULL;
    uint32 pageid_sz;
    int ret;

    for (uint32 i = 0; i < req_count; i++) {
        dms_buf_ctrl_t *ctrl = ctrl_wraps[i].ctrl;
        dms_ask_res_req_t page_req = { 0 };
        DMS_INIT_MESSAGE_HEAD(&page_req.head, MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID,
            0, dms_ctx->inst_id, ctrl_wraps[i].master_id, dms_ctx->sess_id, CM_INVALID_ID16);
        
        page_req.head.size = (uint16)sizeof(dms_ask_res_req_t);
        page_req.req_mode  = req_mode;
        page_req.curr_mode = ctrl->lock_mode;
        page_req.is_try = dms_ctx->is_try;
        page_req.inst_id = dms_ctx->inst_id;
        page_req.is_upgrade = dms_ctx->is_upgrade;
        page_req.sess_id = dms_ctx->sess_id;
        page_req.req_time = (date_t)g_timer()->monotonic_now;
        page_req.len = DMS_PAGEID_SIZE;
        page_req.sess_type = dms_ctx->sess_type;
        page_req.intercept_type = dms_ctx->intercept_type;
        page_req.req_proto_ver = page_req.head.msg_proto_ver;
        page_req.srsn = g_dms.callback.inc_and_get_srsn(dms_ctx->sess_id);
    #ifndef OPENGAUSS
        page_req.scn = (dms_ctx->db_handle != NULL) ? g_dms.callback.get_global_scn(dms_ctx->db_handle) : 0;
    #endif
        g_dms.callback.get_pageid(ctrl, &pageid, &pageid_sz);
        if (memcpy_sp(page_req.resid, DMS_PAGEID_SIZE, pageid, pageid_sz) != EOK) {
            continue;
        }

        dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DCS_REQ_MASTER4PAGE_TRY, CM_TRUE);
        DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID,
            MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID);
        ret = mfc_send_data(&page_req.head);
        dms_end_stat(dms_ctx->sess_id);
        if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
            LOG_DEBUG_ERR(
                "[DCS][%s][try ask master for page owner id]: "
                "failed to send msg, src_id=%d, src_sid=%d ,dest_id=%d",
                cm_display_pageid(page_req.resid), page_req.head.src_inst,
                page_req.head.src_sid, page_req.head.dst_inst);
        }
        ctrl_wraps[i].result = ret;
        ctrl_wraps[i].ruid = page_req.head.ruid;
    }

    for (uint32 i = 0; i < req_count; i++) {
        dms_buf_ctrl_t *ctrl = ctrl_wraps[i].ctrl;
        dms_message_t msg;
        if (ctrl_wraps[i].result != DMS_SUCCESS) {
            continue;
        }

        ret = mfc_get_response(ctrl_wraps[i].ruid, &msg, DMS_WAIT_MAX_TIME);
        ctrl_wraps[i].result = ret;
        if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
            char resid[DMS_PAGEID_SIZE] = { 0 };
            g_dms.callback.get_pageid(ctrl, &pageid, &pageid_sz);
            if (memcpy_sp(resid, DMS_PAGEID_SIZE, pageid, pageid_sz) == EOK) {
                LOG_DEBUG_ERR("[DCS][%s][try ask master for page owner id]: "
                    "ack timeout, src_id=%d, src_sid=%d, dest_id=%d, ret=%d",
                    cm_display_pageid(resid), dms_ctx->inst_id, dms_ctx->sess_id,
                    ctrl_wraps[i].master_id, ret);
            }
            continue;
        }

        g_dms.callback.get_pageid(ctrl, &pageid, &pageid_sz);
        if (memcpy_sp(dms_ctx->resid, DMS_PAGEID_SIZE, pageid, pageid_sz) != EOK) {
            ctrl_wraps[i].result = DMS_ERROR;
            mfc_release_response(&msg);
            continue;
        }

        dms_message_head_t *ack_dms_head = get_dms_head(&msg);
        if (ack_dms_head->cmd == MSG_ACK_GRANT_OWNER) {
            ctrl_wraps[i].owner_id = (uint8)dms_ctx->inst_id;
            ret = dcs_handle_ack_need_load(dms_ctx, ctrl,
                ctrl_wraps[i].master_id, &msg, req_mode, ack_dms_head->seq);
        } else if (ack_dms_head->cmd == MSG_ACK_ALREADY_OWNER) {
            ctrl_wraps[i].owner_id = (uint8)dms_ctx->inst_id;
            ret = dcs_handle_ack_already_owner(dms_ctx, ctrl,
                ctrl_wraps[i].master_id, &msg, req_mode, ack_dms_head->seq);
        } else if (ack_dms_head->cmd == MSG_ACK_PAGE_OWNER_ID) {
            ctrl_wraps[i].owner_id = (uint8)(*(uint32 *)DMS_MESSAGE_BODY(&msg));
            ret = DMS_SUCCESS;
        } else {
            ctrl_wraps[i].owner_id = CM_INVALID_ID8;
            ret = ERRNO_DMS_COMMON_MSG_ACK;
        }

        ctrl_wraps[i].result = ret;
        mfc_release_response(&msg);
    }

    return DMS_SUCCESS;
}

int dms_try_ask_master_for_page_owner_id_batch(dms_context_t *dms_ctx,
    dms_buf_ctrl_t **ctrls, unsigned int req_count, dms_lock_mode_t req_mode)
{
    dms_reset_error();
    char resid[DMS_PAGEID_SIZE] = { 0 };

    int ret;
    dms_ctrl_wrapper_t *ctrl_wraps = (dms_ctrl_wrapper_t *)g_dms.callback.mem_alloc(
        dms_ctx->db_handle, sizeof(dms_ctrl_wrapper_t) * req_count);
    if (ctrl_wraps == NULL) {
        LOG_DEBUG_ERR("[DCS][try ask master for page owner id batch] failed to allocate memory");
        return DMS_ERROR;
    }
    
    for (uint32 i = 0; i < req_count; i++) {
        cm_spin_lock(&ctrls[i]->lock_ss_read, NULL);
        ctrls[i]->is_reform_visit = CM_FALSE;
        cm_spin_unlock(&ctrls[i]->lock_ss_read);

        ctrl_wraps[i].ctrl = ctrls[i];
        char *pageid = NULL;
        uint32 pageid_sz;
        g_dms.callback.get_pageid(ctrls[i], &pageid, &pageid_sz);
        if (memcpy_sp(resid, DMS_PAGEID_SIZE, pageid, pageid_sz) != EOK) {
            g_dms.callback.mem_free(dms_ctx->db_handle, ctrl_wraps);
            return DMS_ERROR;
        }
        ret = drc_get_page_master_id(resid, &ctrl_wraps[i].master_id);
        if (ret != DMS_SUCCESS) {
            g_dms.callback.mem_free(dms_ctx->db_handle, ctrl_wraps);
            return ret;
        }

        ctrl_wraps[i].owner_id = CM_INVALID_ID8;
        ctrl_wraps[i].ruid = 0;
        ctrl_wraps[i].result = DMS_ERROR;
    }

    dcs_try_get_page_owner_id_batch(dms_ctx, ctrl_wraps, req_count, req_mode);
    g_dms.callback.mem_free(dms_ctx->db_handle, ctrl_wraps);
    LOG_DEBUG_INF("[DCS][try ask master for page owner id batch] success");
    return DMS_SUCCESS;
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

    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_RELEASE_OWNER, MSG_REQ_RELEASE_OWNER);
    int32 ret = mfc_send_data(&req.head);
    *ruid = req.head.ruid;
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][send release own req]:src_sid=%u, dest_id=%d,"
            "owner_lsn=%llu, owner_scn=%llu, ruid=%llu",
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

    ret = mfc_get_response(ruid, &msg, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][release owner ack fail] error: %d", cm_display_pageid(dms_ctx->resid), ret);
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    CM_CHK_RESPONSE_SIZE(&msg, (uint32)sizeof(msg_rls_owner_ack_t), CM_FALSE);
    msg_rls_owner_ack_t *ack = (msg_rls_owner_ack_t *)msg.buffer;
    *released = ack->released;

    LOG_DYN_TRC_INF("[ROR][%s]released=%d", cm_display_pageid(dms_ctx->resid), (*released));
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

int dms_can_release_owner(dms_context_t *dms_ctx, unsigned char *released)
{
    LOG_DEBUG_INF("[DCS][%s][dms_can_release_owner] entry", cm_display_pageid(dms_ctx->resid));

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
        dms_dyn_trc_begin(dms_ctx->sess_id, DMS_EVT_DCS_RELEASE_OWNER);
        ret = dcs_release_owner_r(dms_ctx, master_id, released);
        dms_dyn_trc_end(dms_ctx->sess_id);
        dms_end_stat(dms_ctx->sess_id);
    }

    return ret;
}

static int dcs_send_rls_owner_ack(dms_process_context_t *ctx, msg_rls_owner_req_t *req, bool8 released)
{
    msg_rls_owner_ack_t ack;
    dms_init_ack_head(&req->head, &ack.head, MSG_ACK_RELEASE_PAGE_OWNER, sizeof(msg_rls_owner_ack_t), ctx->inst_id);
    ack.released = released;
    DDES_FAULT_INJECTION_CALL(DMS_FI_ACK_RELEASE_PAGE_OWNER, MSG_ACK_RELEASE_PAGE_OWNER);
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
    int ret = dms_can_release_owner(dms_ctx, released);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (*released) {
        ctrl->lock_mode = DMS_LOCK_NULL;
    }
    return DMS_SUCCESS;
}

void drc_proc_buf_ctrl_recycle(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    LOG_DEBUG_INF("[DRC recycle]receive from inst: %d", receive_msg->head->src_inst);
    if (g_dms.callback.buf_ctrl_recycle != NULL) {
        g_dms.callback.buf_ctrl_recycle(ctx->db_handle);
    }
    /* There is no ack message. */
}

#ifdef __cplusplus
}
#endif
