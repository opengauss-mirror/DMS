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
 * dcs_page_v2.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_page_v2.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_page.h"
#include "dms_process.h"
#include "dms_stat.h"
#include "dms_error.h"

#ifdef __cplusplus
extern "C" {
#endif

static int dcs_owner_transfer_page_check_wal(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl,
    dms_res_req_info_t *req_info, dms_ask_res_ack_t *page_ack)
{
    if (!g_dms.callback.page_is_dirty(ctrl)) {
        return DMS_SUCCESS;
    }
#ifdef OPENGAUSS
    uint64 page_lsn = g_dms.callback.get_page_lsn(ctrl);
    g_dms.callback.log_wait_flush(ctx->db_handle, page_lsn);
    return DMS_SUCCESS;
#else
    uint64 flushed_lfn = g_dms.callback.get_global_flushed_lfn(ctx->db_handle);
    uint64 page_lfn = g_dms.callback.get_page_lfn(ctrl);
    // redo log has been flushed
    if (flushed_lfn >= page_lfn) {
        return DMS_SUCCESS;
    }
    // redo log has not been flushed and req_mode is S
    if (req_info->req_mode != DMS_LOCK_EXCLUSIVE) {
        page_ack->break_wal = CM_TRUE;
        LOG_DEBUG_WAR("[DCS][%s][transfer owner]break wal, flushed_lfn: %llu, page_lfn: %llu",
            cm_display_pageid(req_info->resid), flushed_lfn, page_lfn);
        return DMS_SUCCESS;
    }
    // req_mode is X, must flush redo before transfer
    dms_begin_stat(ctx->sess_id, DMS_EVT_DCS_TRANSFER_PAGE_FLUSHLOG, CM_TRUE);
    int ret = g_dms.callback.log_flush(ctx->db_handle, &page_ack->lsn);
    dms_end_stat(ctx->sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DCS][%s][transfer owner]flush failed: dest_id=%d, dest_sid=%d, dest_ruid=%llu",
            cm_display_pageid(req_info->resid), req_info->req_id, req_info->req_sid, req_info->req_ruid);
    }
    return ret;
#endif
}

int dcs_owner_transfer_page_ack_v2(dms_process_context_t *ctx, dms_buf_ctrl_t *ctrl, dms_res_req_info_t *req_info,
    uint32 cmd)
{
    dms_ask_res_ack_t page_ack = { 0 };

    DMS_INIT_MESSAGE_HEAD(&page_ack.head, cmd, 0, req_info->owner_id,
        req_info->req_id, ctx->sess_id, req_info->req_sid);
    page_ack.head.ruid = req_info->req_ruid;
    page_ack.break_wal = CM_FALSE;

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
    int ret = dcs_owner_transfer_page_check_wal(ctx, ctrl, req_info, &page_ack);
    DMS_RETURN_IF_ERROR(ret);

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
    if (page_ack.head.flags & MSG_FLAG_NO_PAGE) {
        ret = mfc_send_data(&page_ack.head);
    } else {
#ifndef OPENGAUSS
        page_ack.enable_cks = (bool8)g_dms.callback.get_enable_checksum(ctx->db_handle);
        page_ack.checksum = (uint16)g_dms.callback.calc_page_checksum(ctx->db_handle, ctrl, g_dms.page_size);
#endif
        ret = mfc_send_data3(&page_ack.head, sizeof(dms_ask_res_ack_t), (void *)g_dms.callback.get_page(ctrl));
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

#ifdef __cplusplus
}
#endif
