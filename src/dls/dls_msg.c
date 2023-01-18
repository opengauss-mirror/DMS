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
 * dls_msg.c
 *
 *
 * IDENTIFICATION
 *    src/dls/dls_msg.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_log.h"
#include "mes_type.h"
#include "dms_stat.h"
#include "dcs_msg.h"
#include "dls_msg.h"
#include "cm_encrypt.h"

static inline void dls_change_global_lock_mode(drc_local_lock_res_t *lock_res, uint8 req_mode)
{
    if (req_mode == DMS_LOCK_EXCLUSIVE) {
        lock_res->count = 0;
        lock_res->is_owner = CM_FALSE;
        lock_res->latch_stat.lock_mode = DMS_LOCK_NULL;
        return;
    }
    if (lock_res->latch_stat.lock_mode == DMS_LOCK_EXCLUSIVE) {
        lock_res->latch_stat.lock_mode = DMS_LOCK_SHARE;
        lock_res->latch_stat.shared_count = 1;
    }
}

static drc_local_lock_res_t* dls_get_lock_res_4_release(dms_drid_t *lockid, bool8 is_try)
{
    drc_local_lock_res_t *lock_res = drc_get_local_resx(lockid);
    CM_ASSERT(lock_res != NULL);

    if (is_try) {
        bool8 locked, is_owner;
        drc_get_local_lock_statx(lock_res, &locked, &is_owner);
        if (locked) {
            return NULL;
        }
        drc_lock_local_resx(lock_res);
        drc_get_local_lock_statx(lock_res, &locked, &is_owner);
        if (locked) {
            drc_unlock_local_resx(lock_res);
            return NULL;
        }
        return lock_res;
    }
    lock_res->releasing = CM_TRUE;
    while (CM_TRUE) {
        drc_lock_local_resx(lock_res);
        if (!lock_res->is_locked) {
            break;
        }
        drc_unlock_local_resx(lock_res);
#ifndef WIN32
        fas_cpu_pause();
#endif
    }
    return lock_res;
}

int32 dls_invld_lock_ownership(char *resid, uint8 req_mode, bool8 is_try, uint32 ver)
{
    dms_drid_t *lockid = (dms_drid_t*)resid;
    LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) try:%u", cm_display_lockid(lockid), (uint32)is_try);

    drc_local_lock_res_t *lock_res = dls_get_lock_res_4_release(lockid, is_try);
    if (lock_res == NULL) {
        LOG_DEBUG_INF("[DLS] try release lock(%s) failed", cm_display_lockid(lockid));
        DMS_THROW_ERROR(ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED);
        return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
    }

    if (ver != lock_res->ver) {
        LOG_DEBUG_WAR("[DLS] dls_invld_lock_ownership(%s) invalid req, req_ver:%u res_ver:%u",
            cm_display_lockid(lockid), ver, lock_res->ver);
        drc_unlock_local_resx(lock_res);
        return ERRNO_DMS_RES_INVALID_VERSION;
    }

    dls_change_global_lock_mode(lock_res, req_mode);

    lock_res->releasing = CM_FALSE;

    drc_unlock_local_resx(lock_res);

    LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) succeeded", cm_display_lockid(lockid));
    return DMS_SUCCESS;
}

int32 dls_owner_transfer_lock(dms_process_context_t *proc_ctx, dms_res_req_info_t *req_info)
{
    int32 ret = dls_invld_lock_ownership(req_info->resid, req_info->req_mode, req_info->is_try, req_info->ver);
    if (ret != DMS_SUCCESS) {
        dms_send_error_ack(proc_ctx->inst_id, proc_ctx->sess_id,
            req_info->req_id, req_info->req_sid, req_info->req_rsn, ret);
        return DMS_SUCCESS;
    }

    dms_ask_res_ack_t page_ack;
    MES_INIT_MESSAGE_HEAD(&page_ack.head, MSG_ACK_PAGE_READY, 0, req_info->owner_id,
        req_info->req_id, proc_ctx->sess_id, req_info->req_sid);
    page_ack.head.rsn = req_info->req_rsn;
    page_ack.head.flags |= MSG_FLAG_NO_PAGE;
    page_ack.head.size = (uint16)sizeof(dms_ask_res_ack_t);
    page_ack.ver = req_info->ver;
    ret = mfc_send_data(&page_ack.head);
    return ret;
}

int32 dls_handle_grant_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, mes_message_t *msg, dms_lock_mode_t mode)
{
    lock_res->ver = cm_random(CM_INVALID_ID32);
    return dms_claim_ownership_r(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64, lock_res->ver);
}

int32 dls_handle_already_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, mes_message_t *msg, dms_lock_mode_t mode)
{
    lock_res->ver = cm_random(CM_INVALID_ID32);
    return dms_claim_ownership_r(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64, lock_res->ver);
}

int32 dls_handle_lock_ready_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, mes_message_t *msg, dms_lock_mode_t mode)
{
    CM_CHK_RECV_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_t), CM_FALSE, CM_FALSE);
    dms_ask_res_ack_t *ack = (dms_ask_res_ack_t *)(msg->buffer);

    lock_res->ver = (mode == DMS_LOCK_EXCLUSIVE) ? cm_random(CM_INVALID_ID32) : ack->ver;
    return dms_claim_ownership_r(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64, lock_res->ver);
}

int32 dls_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t mode)
{
    dms_ctx->is_try = CM_FALSE;
    dms_ctx->len    = DMS_DRID_SIZE;
    dms_ctx->type   = DRC_RES_LOCK_TYPE;
    int32 ret = memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, (char*)&lock_res->resid, dms_ctx->len);
    DMS_SECUREC_CHECK(ret);
    return dms_request_res_internal(dms_ctx, (void*)lock_res, curr_mode, mode, lock_res->ver);
}

int32 dls_try_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t mode)
{
    dms_ctx->is_try = CM_TRUE;
    dms_ctx->len    = DMS_DRID_SIZE;
    dms_ctx->type   = DRC_RES_LOCK_TYPE;
    int32 ret = memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, (char*)&lock_res->resid, dms_ctx->len);
    DMS_SECUREC_CHECK(ret);
    return dms_request_res_internal(dms_ctx, (void*)lock_res, curr_mode, mode, lock_res->ver);
}

void dls_cancel_request_lock(dms_context_t *dms_ctx, dms_drid_t *lock_id)
{
    dms_ctx->len  = DMS_DRID_SIZE;
    dms_ctx->type = DRC_RES_LOCK_TYPE;
    int32 ret = memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, (char*)lock_id, dms_ctx->len);
    DMS_SECUREC_CHECK(ret);
    dms_cancel_request_res(dms_ctx);
}