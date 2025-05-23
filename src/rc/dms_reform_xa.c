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
 * dms_reform_proc.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_msg.h"
#include "dms_reform_proc_stat.h"
#include "dms_msg_protocol.h"
#include "drc_tran.h"

static int32 dms_reform_rebuild_append_xid(dms_reform_req_rebuild_t *req_rebuild, drc_global_xid_t *xid,
    uint8 master_id, uint8 undo_set_id)
{
    /* fmt_id + gtrid_len + bqual_len + unso_set_id + gtrid + bqual 
     * 3 * sizeof(uint8): undo_set_id + gtrid_len + bqual_len
     */
    uint32 append_size = (uint32)(sizeof(uint64) + xid->bqual_len + xid->gtrid_len + 3 * sizeof(uint8));

    int ret = DMS_SUCCESS;
    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, g_dms.reform_ctx.sess_proc);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS][%s] send data failed when rebuilding xa res while reforming", cm_display_resid((char *)xid,
                DRC_RES_GLOBAL_XA_TYPE));
                DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_XA_REBUILD, req_rebuild->head.dst_inst);
            return ERRNO_DMS_SEND_MSG_FAILED;
        }
        req_rebuild->offset += (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    *(uint64 *)((char *)req_rebuild + req_rebuild->offset) = xid->fmt_id;
    req_rebuild->offset += sizeof(uint64);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = xid->gtrid_len;
    req_rebuild->offset += sizeof(uint8);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = xid->bqual_len;
    req_rebuild->offset += sizeof(uint8);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = undo_set_id;
    req_rebuild->offset += sizeof(uint8);

    ret = memcpy_sp((char *)req_rebuild + req_rebuild->offset, xid->gtrid_len, xid->gtrid, xid->gtrid_len);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }
    req_rebuild->offset += xid->gtrid_len;
    if (xid->bqual_len > 0) {
        ret = memcpy_sp((char *)req_rebuild + req_rebuild->offset, xid->bqual_len, xid->bqual, xid->bqual_len);
        if (ret != EOK) {
            return ret;
        }
        req_rebuild->offset += xid->bqual_len;
    }
     
    return DMS_SUCCESS;
}

static int32 dms_reform_req_xa_rebuild(dms_context_t *dms_ctx, drc_global_xid_t *xid, uint8 undo_set_id,
    uint8 master_id, uint8 thread_index)
{
    dms_reform_req_rebuild_t *req_rebuild = NULL;
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = &parallel_info->parallel[thread_index];

    if (thread_index == CM_INVALID_ID8) {
        req_rebuild = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[master_id];
    } else {
        req_rebuild = (dms_reform_req_rebuild_t *)parallel->data[master_id];
    }
    if (req_rebuild == NULL) {
        if (thread_index == CM_INVALID_ID8) {
            req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
                DMS_REFORM_MSG_MAX_LENGTH);
        } else {
            req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(parallel->handle, 
                DMS_REFORM_MSG_MAX_LENGTH);
        }
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }   
        if (thread_index == CM_INVALID_ID8) {
            rebuild_info->rebuild_data[master_id] = req_rebuild;
        } else {
            parallel->data[master_id] = req_rebuild;
        }

        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, MSG_REQ_XA_REBUILD, 0, g_dms.inst_id, master_id,
            g_dms.reform_ctx.sess_proc, CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }
    
    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_XA_REBUILD, MSG_REQ_XA_REBUILD);
    return dms_reform_rebuild_append_xid(req_rebuild, xid, master_id, undo_set_id);
}

int dms_reform_rebuild_one_xa(dms_context_t *dms_ctx, unsigned char undo_set_id, unsigned char thread_index)
{
    dms_reset_error();
    uint8 master_id = CM_INVALID_ID8;
    drc_global_xid_t *xid = &dms_ctx->global_xid;

    int ret = drc_get_master_id((char *)xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s] dms_reform_rebuild_one_xa, fail to get master id", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    LOG_DEBUG_INF("[DMS][%s] dms_reform_rebuild_xa_res, master_id:%d",
        cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), master_id);
    if (dms_dst_id_is_self(master_id)) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_XA_LOCAL);
        ret = drc_xa_create(dms_ctx->db_handle, DMS_SESSION_REFORM, dms_ctx->sess_id, xid, g_dms.inst_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_XA_LOCAL);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_XA_REMOTE);
        ret = dms_reform_req_xa_rebuild(dms_ctx, xid, undo_set_id, master_id, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_XA_REMOTE);
    }
    return ret;
}

void dms_reform_proc_xa_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    int32 ret = DMS_SUCCESS;
    drc_global_xid_t xid = { 0 };
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_rebuild_t), CM_TRUE);
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)receive_msg->buffer;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, req_rebuild->offset, CM_TRUE);
    if (!dms_reform_check_judge_time(&req_rebuild->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_MES_INVALID_MSG, "fail to check judge time");
        return;
    }
    uint8 owner_id = req_rebuild->head.src_inst;
    uint32 offset = (uint32)sizeof(dms_reform_req_rebuild_t);

    while (offset < req_rebuild->offset) {
        xid.fmt_id = *(uint64 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint64);
        xid.gtrid_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        xid.bqual_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        // undo_set_id
        offset += sizeof(uint8);
        ret = memcpy_sp(xid.gtrid, DMS_MAX_XA_BASE16_GTRID_LEN, (uint8 *)receive_msg->buffer + offset, xid.gtrid_len);
        DMS_SECUREC_CHECK(ret);
        offset += xid.gtrid_len;
        if (xid.bqual_len > 0) {
            ret = memcpy_sp(xid.bqual, DMS_MAX_XA_BASE16_BQUAL_LEN, (uint8 *)receive_msg->buffer + offset, xid.bqual_len);
            DMS_SECUREC_CHECK(ret);
            offset += xid.bqual_len;
        }

        ret = drc_xa_create(ctx->db_handle, DMS_SESSION_REFORM, ctx->sess_id, &xid, owner_id);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DRC][%s] dms_reform_proc_xa_rebuild", cm_display_resid((char *)&xid, DRC_RES_GLOBAL_XA_TYPE));
            break;
        }
    }

    dms_reform_ack_req_rebuild(ctx, receive_msg, ret);
}

void dms_reform_delete_xa_rms(void *db_handle, uint8 undo_set_id)
{
    g_dms.callback.dms_shrink_xa_rms(db_handle, undo_set_id);
}

int dms_reform_xa_drc_access(void)
{
    LOG_RUN_FUNC_ENTER;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_xa_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}