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

#include "dms_error.h"
#include "mes_interface.h"
#include "dms_stat.h"
#include "dcs_msg.h"
#include "dls_msg.h"
#include "cm_encrypt.h"
#include "cm_timer.h"

bool8 g_lock_matrix[LATCH_STATUS_X + 1][LATCH_STATUS_X + 1] = {
    {1, 1, 1, 1},
    {1, 1, 0, 0},
    {1, 0, 0, 0},
    {1, 0, 0, 0}
};

static inline void dls_change_global_lock_mode(drc_local_lock_res_t *lock_res, uint8 req_mode)
{
    if (req_mode == DMS_LOCK_EXCLUSIVE) {
        lock_res->latch_stat.lock_mode = DMS_LOCK_NULL;
        return;
    }
    if (lock_res->latch_stat.lock_mode == DMS_LOCK_EXCLUSIVE) {
        lock_res->latch_stat.lock_mode = DMS_LOCK_SHARE;
    }
}

static int32 dls_get_lock_res_4_rls(dms_drid_t *lockid, bool8 is_try, uint8 lock_mode, drc_local_lock_res_t **lock_res)
{
    uint64 ver = 0;
    uint32 spin_times = 0;
    date_t begin = g_timer()->now;
    do {
        if (!drc_get_lock_resx_by_drid(lockid, lock_res, &ver)) {
            DLS_WAIT_FOR_LOCK_TRANSFER;
            continue;
        }
        cm_spin_lock(&(*lock_res)->lock, NULL);
        if ((*lock_res)->version != ver) {
            cm_spin_unlock(&(*lock_res)->lock);
            DLS_WAIT_FOR_LOCK_TRANSFER;
            continue;
        }
        if (g_lock_matrix[lock_mode][(*lock_res)->latch_stat.stat]) {
            return DMS_SUCCESS;
        }
        (*lock_res)->releasing = CM_TRUE;
        cm_spin_unlock(&(*lock_res)->lock);
        DLS_WAIT_FOR_LOCK_TRANSFER;
    } while (CM_TRUE);
}

int32 dls_invld_lock_ownership(void *db_handle, char *resid, uint8 res_type, uint8 req_mode, bool8 is_try)
{
    if (res_type == DRC_RES_LOCK_TYPE) {
        drc_local_lock_res_t *lock_res = NULL;
        dms_drid_t *lockid = (dms_drid_t *)resid;
        LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) try:%d", cm_display_lockid(lockid), is_try);
        if (DMS_DR_IS_TABLE_TYPE(lockid->type)) {
            if (g_dms.callback.invld_tlock_ownership(db_handle, (char *)lockid, req_mode, is_try) != CM_SUCCESS) {
                return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
            }
            LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) succeeded", cm_display_lockid(lockid));
            return DMS_SUCCESS;
        }
        uint8 lock_mode = (req_mode == DMS_LOCK_SHARE) ? LATCH_STATUS_S : LATCH_STATUS_X;
        if (dls_get_lock_res_4_rls(lockid, is_try, lock_mode, &lock_res) != DMS_SUCCESS) {
            return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
        }
        dls_change_global_lock_mode(lock_res, req_mode);
        lock_res->releasing = CM_FALSE;
        cm_spin_unlock(&lock_res->lock);
        LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) succeeded", cm_display_lockid(lockid));
        return DMS_SUCCESS;
    } else if (res_type == DRC_RES_ALOCK_TYPE) {
        alockid_t *alockid = (alockid_t *)resid;
        LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) try:%d", cm_display_alockid(alockid), is_try);
        if (g_dms.callback.invld_alock_ownership(db_handle, (char *)resid, req_mode, is_try) != CM_SUCCESS) {
            return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
        }
        LOG_DEBUG_INF("[DLS] dls_invld_lock_ownership(%s) succeeded", cm_display_alockid(alockid));
        return DMS_SUCCESS;
    }
    cm_panic_log(CM_FALSE, "invalid type: %d", res_type);
    return DMS_SUCCESS;
}

int32 dls_owner_transfer_lock(dms_process_context_t *proc_ctx, dms_res_req_info_t *req_info)
{
    int32 ret = dls_invld_lock_ownership(proc_ctx->db_handle, req_info->resid, req_info->res_type, req_info->req_mode,
        req_info->is_try);
    DMS_RETURN_IF_ERROR(ret);

    dms_ask_res_ack_t page_ack = { 0 };
    dms_init_ack_head2(&page_ack.head, MSG_ACK_PAGE_READY, 0, req_info->owner_id,
        req_info->req_id, (uint16)proc_ctx->sess_id, req_info->req_sid, req_info->req_proto_ver);
    page_ack.head.ruid = req_info->req_ruid;
    page_ack.head.flags |= MSG_FLAG_NO_PAGE;
    page_ack.head.size = (uint16)sizeof(dms_ask_res_ack_t);
    ret = mfc_send_data(&page_ack.head);
    return ret;
}
int32 dls_modify_lock_mode(drc_local_lock_res_t *lock_res, dms_lock_mode_t mode)
{
    cm_spin_lock(&lock_res->modify_mode_lock, NULL);
    if (lock_res->is_reform_visit == CM_TRUE) {
        cm_spin_unlock(&lock_res->modify_mode_lock);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_REFORM_VISIT_RES, cm_display_lockid(&lock_res->resid));
        return ERRNO_DMS_DCS_REFORM_VISIT_RES;
    }
    lock_res->latch_stat.lock_mode = mode;
    cm_spin_unlock(&lock_res->modify_mode_lock);
    return DMS_SUCCESS;
}

int32 dls_handle_grant_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    if (lock_res != NULL) {
        int ret = dls_modify_lock_mode(lock_res, mode);
        DMS_RETURN_IF_ERROR(ret);
    }
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64);
    return DMS_SUCCESS;
}

int32 dls_handle_already_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    if (lock_res != NULL) {
        int ret = dls_modify_lock_mode(lock_res, mode);
        DMS_RETURN_IF_ERROR(ret);
    }
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64);
    return DMS_SUCCESS;
}

int32 dls_handle_lock_ready_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode)
{
    CM_CHK_PROC_MSG_SIZE(msg, (uint32)sizeof(dms_ask_res_ack_t), CM_FALSE);
    if (lock_res != NULL) {
        int ret = dls_modify_lock_mode(lock_res, mode);
        DMS_RETURN_IF_ERROR(ret);
    }
    dms_claim_ownership(dms_ctx, master_id, mode, CM_FALSE, CM_INVALID_INT64);
    return DMS_SUCCESS;
}

int32 dls_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode)
{
    if (!dms_drc_accessible(dms_ctx->type) && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }
    if (lock_res != NULL) {
        lock_res->is_reform_visit = CM_FALSE;
    }
    return dms_request_res_internal(dms_ctx, (void*)lock_res, curr_mode, mode);
}

int32 dls_try_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode)
{
    if (lock_res != NULL) {
        lock_res->is_reform_visit = CM_FALSE;
    }
    return dms_request_res_internal(dms_ctx, (void*)lock_res, curr_mode, mode);
}

void dls_cancel_request_lock(dms_context_t *dms_ctx)
{
    dms_cancel_request_res(dms_ctx->resid, dms_ctx->len, dms_ctx->sess_id, dms_ctx->type);
}