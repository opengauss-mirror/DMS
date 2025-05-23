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
 * drc_page.c
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_page.c
 *
 * -------------------------------------------------------------------------
 */

#include "drc_page.h"
#include "cm_log.h"
#include "drc.h"
#include "drc_res_mgr.h"
#include "dms_cm.h"
#include "dms_error.h"
#include "dms_msg.h"
#include "dcs_page.h"
#include "dms_reform_proc.h"

static inline bool32 chk_conflict_with_x_lock(char *resid, uint8 type, drc_request_info_t *req1,
    drc_request_info_t *req2)
{
    if (req1->req_mode == DMS_LOCK_EXCLUSIVE &&
        req2->curr_mode == DMS_LOCK_SHARE && req2->req_mode == DMS_LOCK_EXCLUSIVE) {
        LOG_DEBUG_INF("[DRC][%s]:req conflict, [req1:id=%u, sid=%u, ruid=%llu, "
            "rmode=%u, cmode=%u], [req2:id=%u, sid=%u, ruid=%llu, rmode=%u, cmode=%u]",
            cm_display_resid(resid, type), (uint32)req1->inst_id, (uint32)req1->sess_id, req1->ruid,
            (uint32)req1->req_mode, (uint32)req1->curr_mode, (uint32)req2->inst_id, (uint32)req2->sess_id,
            req2->ruid, (uint32)req2->req_mode, (uint32)req2->curr_mode);
        return CM_TRUE;
    }
    return CM_FALSE;
}

static inline int32 chk_convertq_4_conflict_reverse(drc_head_t *drc, drc_request_info_t *req, drc_lock_item_t* next)
{
    while (next != NULL) {
        if (chk_conflict_with_x_lock(DRC_DATA(drc), drc->type, req, &next->req_info)) {
            DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        next = (drc_lock_item_t*)next->node.next;
    }
    return DMS_SUCCESS;
}

static int32 chk_if_valid_retry_request(drc_head_t *drc, drc_request_info_t *new_req, drc_request_info_t *old_req,
    drc_lock_item_t *next)
{
    if (new_req->req_time < old_req->req_time) {
        LOG_DEBUG_INF("[DRC][%s] invalid request, [new:inst_id=%d, sid=%d, ruid=%llu, req_mode=%d, "
            "curr_mode=%d, req_time=%lld], [old:inst_id=%d, sid=%d, ruid=%llu, req_mode=%d, curr_mode=%d, "
            "req_time=%lld]", cm_display_resid(DRC_DATA(drc), drc->type), new_req->inst_id, new_req->sess_id,
            new_req->ruid, new_req->req_mode, new_req->curr_mode, new_req->req_time, old_req->inst_id,
            old_req->sess_id, old_req->ruid, old_req->req_mode, old_req->curr_mode, old_req->req_time);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST);
        return ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST;
    }
    if (new_req->req_mode > old_req->req_mode) {
        return chk_convertq_4_conflict_reverse(drc, new_req, next);
    }
    return DMS_SUCCESS;
}

static int32 chk_convertq_4_conflict(drc_head_t *drc, drc_request_info_t* req, bool32 *is_retry)
{
    drc_lock_item_t* tmp = (drc_lock_item_t*)cm_bilist_head(&drc->convert_q);
    while (tmp != NULL) {
        // retry request
        if (tmp->req_info.inst_id == req->inst_id) {
            int32 ret = chk_if_valid_retry_request(drc, req, &tmp->req_info, (drc_lock_item_t*)tmp->node.next);
            if (ret != DMS_SUCCESS) {
                return ret;
            }
            *is_retry = CM_TRUE;
            tmp->req_info = *req;
            return DMS_SUCCESS;
        }

        if (chk_conflict_with_x_lock(DRC_DATA(drc), drc->type, &tmp->req_info, req)) {
            DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
    return DMS_SUCCESS;
}

static inline void drc_register_converting_simply(drc_head_t *drc, drc_cvt_item_t *converting)
{
    drc->lock_mode = converting->req_info.req_mode;
    if (drc->owner == CM_INVALID_ID8) {
        drc->copy_insts = 0;
        drc->owner = converting->req_info.inst_id;
    } else if (drc->owner != converting->req_info.inst_id) {
        bitmap64_set(&drc->copy_insts, converting->req_info.inst_id);
    }
}

static int32 drc_chk_conflict_4_upgrade(dms_process_context_t *ctx, drc_head_t *drc, drc_request_info_t *req,
    bool32 *can_cvt)
{
    drc_lock_item_t *curr = NULL;
    drc_lock_item_t *next = (drc_lock_item_t *)cm_bilist_head(&drc->convert_q);
    while (next != NULL) {
        curr = next;
        next = (drc_lock_item_t*)next->node.next;
        // upgrade req will be add to head, so we delete it here
        if (curr->req_info.inst_id == req->inst_id) {
            if (req->req_time < curr->req_info.req_time) {
                DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST);
                return ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST;
            }
            cm_bilist_del(&curr->node, &drc->convert_q);
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)curr);
            continue;
        }
        if (curr->req_info.is_upgrade) {
            DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        if (chk_conflict_with_x_lock(DRC_DATA(drc), drc->type, req, &curr->req_info)) {
            dms_send_error_ack(ctx, curr->req_info.inst_id, curr->req_info.sess_id,
                curr->req_info.ruid, ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER, curr->req_info.req_proto_ver);
            cm_bilist_del(&curr->node, &drc->convert_q);
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)curr);
        }
    }

    drc_cvt_item_t *converting = &drc->converting;

    if (req->inst_id == converting->req_info.inst_id) {
        if (req->req_time < converting->req_info.req_time) {
            DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST);
            return ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST;
        }
        // converting: request s mode, and has been granted, but claim request has not been processed
        // req: s->x
        if (req->curr_mode == converting->req_info.req_mode) {
            drc_register_converting_simply(drc, converting);
        }
        *can_cvt = CM_TRUE;
        converting->req_info   = *req;
        converting->begin_time = g_timer()->monotonic_now;
        return DMS_SUCCESS;
    }

    if (converting->req_info.is_upgrade) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }
    
    // converting node can only receive error ack or wait timeout
    // so we can remove it from converting directly
    if (converting->req_info.req_mode == DMS_LOCK_EXCLUSIVE) {
        if (converting->req_info.curr_mode == DMS_LOCK_SHARE) {
            dms_send_error_ack(ctx, converting->req_info.inst_id, converting->req_info.sess_id,
                converting->req_info.ruid, ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER, converting->req_info.req_proto_ver);
        } else {
            drc_lock_item_t *item = (drc_lock_item_t*)drc_res_pool_alloc_item(&DRC_RES_CTX->lock_item_pool);
            if (SECUREC_UNLIKELY(item == NULL)) {
                DMS_THROW_ERROR(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH);
                return ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH;
            }
            item->req_info = converting->req_info;
            cm_bilist_add_head(&item->node, &drc->convert_q);
        }
        *can_cvt = CM_TRUE;
        converting->req_info   = *req;
        converting->begin_time = g_timer()->monotonic_now;
    }
    return DMS_SUCCESS;
}

static int32 drc_chk_conflict_4_normal(drc_head_t *drc, drc_request_info_t *req, bool32 *is_retry, bool32 *can_cvt)
{
    drc_cvt_item_t *converting = &drc->converting;

    // retry request
    if (req->inst_id == converting->req_info.inst_id) {
        drc_lock_item_t *first_node = (drc_lock_item_t*)cm_bilist_head(&drc->convert_q);
        int32 ret = chk_if_valid_retry_request(drc, req, &converting->req_info, first_node);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
        // converting: request s mode, and has been granted, but claim request has not been processed
        // req: s->x
        if (req->curr_mode == converting->req_info.req_mode) {
            drc_register_converting_simply(drc, converting);
        }
        *can_cvt  = CM_TRUE;
        converting->req_info = *req;
        converting->begin_time = g_timer()->monotonic_now;
        return DMS_SUCCESS;
    }

    if (drc->lock_mode == DMS_LOCK_SHARE && converting->req_info.req_mode == DMS_LOCK_EXCLUSIVE &&
        bitmap64_exist(&drc->copy_insts, req->inst_id)) {
        LOG_DEBUG_INF("[DRC][%s]:conflicted with other, [drc:owner=%d, mode=%d, cvt:id=%d, rmode=%d], "
            "[req:id=%d, sid=%d, ruid=%llu, rmode=%d, cmode=%d]", cm_display_resid(DRC_DATA(drc), drc->type),
            drc->owner, drc->lock_mode, converting->req_info.inst_id, converting->req_info.req_mode, req->inst_id,
            req->sess_id, req->ruid, req->req_mode, req->curr_mode);
        /* expected, requester will retry, no need to throw error */
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }

    if (drc->owner == req->inst_id) {
        // for example: owner:0, converting:1, new request inst:0
        LOG_DEBUG_INF("[DRC][%s]:req conflict, [drc:owner=%d, mode=%d], "
            "[req:id=%d, sid=%d, ruid=%llu, rmode=%d, cmode=%d]", cm_display_resid(DRC_DATA(drc), drc->type),
            drc->owner, drc->lock_mode, req->inst_id, req->sess_id, req->ruid, req->req_mode, req->curr_mode);
        /* expected, requester will retry, no need to throw error */
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }
    return chk_convertq_4_conflict(drc, req, is_retry);
}

static inline int32 drc_check_req_4_conflict(dms_process_context_t *ctx, drc_head_t *drc, drc_request_info_t *req,
    bool32 *is_retry, bool32 *can_cvt)
{
    if (!req->is_upgrade) {
        return drc_chk_conflict_4_normal(drc, req, is_retry, can_cvt);
    }

    return drc_chk_conflict_4_upgrade(ctx, drc, req, can_cvt);
}

static int32 drc_enq_req_item(dms_process_context_t *ctx, drc_head_t *drc, drc_request_info_t *req_info,
    bool32 *converting)
{
    /* there is no waiting and converting */
    if (drc->converting.req_info.inst_id == CM_INVALID_ID8) {
        cm_panic(drc->convert_q.count == 0);
        drc->converting.req_info = *req_info;
        drc->converting.begin_time = g_timer()->monotonic_now;
        *converting = CM_TRUE;
        return DMS_SUCCESS;
    }

    // try lock request, abandon to try
    if (req_info->is_try && drc->type == DRC_RES_LOCK_TYPE) {
        LOG_DEBUG_WAR("[DMS][%s] abandon try", cm_display_resid(DRC_DATA(drc), drc->type));
        return ERRNO_DMS_DRC_LOCK_ABANDON_TRY;
    }

    bool32 is_retry_quest = CM_FALSE;
    int32 ret = drc_check_req_4_conflict(ctx, drc, req_info, &is_retry_quest, converting);
    if (ret != DMS_SUCCESS || is_retry_quest || *converting) {
        return ret;
    }

    drc_lock_item_t *req = (drc_lock_item_t*)drc_res_pool_alloc_item(&DRC_RES_CTX->lock_item_pool);
    if (SECUREC_UNLIKELY(req == NULL)) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH;
    }
    *converting   = CM_FALSE;
    req->req_info = *req_info;

    if (!req_info->is_upgrade) {
        cm_bilist_add_tail(&req->node, &drc->convert_q);
    } else {
        cm_bilist_add_head(&req->node, &drc->convert_q);
    }
    return DMS_SUCCESS;
}

int drc_get_no_owner_id(void *db_handle, drc_head_t *drc, uint8 *owner_id)
{
    if (drc->type != DRC_RES_PAGE_TYPE) {
        LOG_DEBUG_INF("[%s][drc_get_no_owner_id]type is not page", cm_display_resid(DRC_DATA(drc), drc->type));
        *owner_id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    drc_page_t *drc_page = (drc_page_t *)drc;
    if (drc_page->last_edp == CM_INVALID_ID8) {
        LOG_DEBUG_INF("[%s][drc_get_no_owner_id]last edp not exists", cm_display_resid(DRC_DATA(drc), drc->type));
        *owner_id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    uint64 disk_lsn = 0;
    if (g_dms.callback.disk_lsn(db_handle, drc_page->data, &disk_lsn) != DMS_SUCCESS) { // page id is invalid
        LOG_DEBUG_INF("[%s][drc_get_no_owner_id]fail to get disk lsn", cm_display_resid(DRC_DATA(drc), drc->type));
        DMS_THROW_ERROR(ERRNO_DMS_DCS_GET_DISK_LSN_FAILED, cm_display_resid(DRC_DATA(drc), drc->type));
        return ERRNO_DMS_DCS_GET_DISK_LSN_FAILED;
    }

    if (disk_lsn >= drc_page->last_edp_lsn) {
        LOG_DEBUG_INF("[%s][drc_get_no_owner_id]last edp:%d lsn:%llu less than disk lsn:%llu",
            cm_display_resid(DRC_DATA(drc), drc->type), drc_page->last_edp, drc_page->last_edp_lsn, disk_lsn);
        *owner_id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    drc->owner = drc_page->last_edp;
    drc->lock_mode = DMS_LOCK_EXCLUSIVE;
    *owner_id = drc->owner;
    LOG_DEBUG_INF("[%s][drc_get_no_owner_id]last edp:%d lsn:%llu greater than disk lsn:%llu",
        cm_display_resid(DRC_DATA(drc), drc->type), drc_page->last_edp, drc_page->last_edp_lsn, disk_lsn);
    return DMS_SUCCESS;
}

static int drc_get_page_no_owner(dms_process_context_t *ctx, drc_req_owner_result_t *result, drc_head_t *drc,
    drc_request_info_t* req_info)
{
    uint8 owner_id = CM_INVALID_ID8;
    int ret = drc_get_no_owner_id(ctx->db_handle, drc, &owner_id);
    DMS_RETURN_IF_ERROR(ret);
    if (owner_id == CM_INVALID_ID8) {
        result->type = DRC_REQ_OWNER_GRANTED;
        result->curr_owner_id = req_info->inst_id;
    } else {
        result->type = (owner_id == req_info->inst_id ? DRC_REQ_OWNER_ALREADY_OWNER : DRC_REQ_OWNER_CONVERTING);
        result->curr_owner_id = owner_id;
    }

    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        drc_page->need_recover = (req_info->sess_type == DMS_SESSION_RECOVER);
        LOG_DEBUG_INF("[DRC][%s][drc_get_page_no_owner]in_rcy:%d, owner:%d, type:%u",
            cm_display_resid(DRC_DATA(drc), drc->type), drc_page->need_recover, result->curr_owner_id, result->type);
    }
    return DMS_SUCCESS;
}

static void drc_try_confirm_cvt(drc_head_t *drc)
{
    drc_request_info_t *cvt_req = &drc->converting.req_info;

    if (cvt_req->inst_id == CM_INVALID_ID8 || !if_cvt_need_confirm(&drc->converting)) {
        return;
    }

    res_id_t res_id;
    res_id.type = drc->type;
    res_id.len = drc->len;
    int ret = memcpy_s(res_id.data, DMS_RESID_SIZE, DRC_DATA(drc), DMS_RESID_SIZE);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DRC]memcpy_s err: %d", ret);
        return;
    }
    drc->converting.begin_time = g_timer()->monotonic_now;
    LOG_DEBUG_WAR("[DRC][%s] converting [inst:%d sid:%d ruid:%llu req_mode:%d] prepare confirm",
        cm_display_resid(DRC_DATA(drc), drc->type), cvt_req->inst_id, cvt_req->sess_id, cvt_req->ruid,
        cvt_req->req_mode);
    (void)cm_chan_try_send(DRC_RES_CTX->chan, (void *)&res_id);
}

static int drc_set_req_result(dms_process_context_t *ctx, drc_req_owner_result_t *result, drc_head_t *drc,
    drc_request_info_t *req_info, bool32 can_cvt)
{
    if (can_cvt) {
        if (drc->owner == CM_INVALID_ID8) {
            return drc_get_page_no_owner(ctx, result, drc, req_info);
        }
        result->curr_owner_id = drc->owner;

        if (drc->owner == req_info->inst_id) {
            result->type = DRC_REQ_OWNER_ALREADY_OWNER;
        } else {
            if (drc->type == DRC_RES_LOCK_TYPE && req_info->req_mode == DMS_LOCK_SHARE &&
                drc->lock_mode == DMS_LOCK_SHARE) {
                // asker can get lock_s directly if owner hold lock_s, this scenario applies only to distributed locks.
                result->type = DRC_REQ_OWNER_GRANTED;
            } else {
                result->type = DRC_REQ_OWNER_CONVERTING;
            }
        }

        if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
            result->invld_insts = drc->copy_insts;
            bitmap64_clear(&result->invld_insts, req_info->inst_id); // don't invalidate self
        }

        if (drc->lock_mode == DMS_LOCK_EXCLUSIVE) {
            CM_ASSERT(drc->copy_insts == 0);
        }
    } else {
        result->type = DRC_REQ_OWNER_WAITING;
        result->curr_owner_id = CM_INVALID_ID8;
        drc_try_confirm_cvt(drc);
    }
    return DMS_SUCCESS;
}

static bool8 drc_page_check_for_prefetch(drc_request_info_t *req_info, drc_req_owner_result_t *result, drc_head_t *drc)
{
    drc_page_t *drc_page = (drc_page_t *)drc;
    drc_request_info_t *cvt_info = &drc->converting.req_info;

    // it indicates that drc has just been created
    if (drc->owner == CM_INVALID_ID8 && cvt_info->inst_id == CM_INVALID_ID8 && drc_page->last_edp == CM_INVALID_ID8) {
        return CM_TRUE;
    }

    // owner is request inst, but converting exist, just return waiting
    if (drc->owner == req_info->inst_id && cvt_info->inst_id == CM_INVALID_ID8) {
        return CM_TRUE;
    }

    result->type = DRC_REQ_OWNER_WAITING;
    result->curr_owner_id = CM_INVALID_ID8; // useless
    return CM_FALSE;
}

static int drc_request_page_owner_internal(dms_process_context_t *ctx, char *resid, uint8 type,
    drc_request_info_t *req_info, drc_req_owner_result_t *result, drc_head_t *drc)
{
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        result->seq = drc_page->seq;

        DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM_ALWAYS(DMS_FI_DRC_FROZEN, {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_RECOVERY_PAGE, cm_display_resid(resid, type));
        return ERRNO_DMS_DRC_RECOVERY_PAGE; });

        if (req_info->sess_type == DMS_SESSION_NORMAL && drc_page->need_recover) {
            LOG_DEBUG_ERR("[DRC][%s]: request page fail, page in recovery", cm_display_resid(resid, type));
            DMS_THROW_ERROR(ERRNO_DMS_DRC_RECOVERY_PAGE, cm_display_resid(resid, type));
            return ERRNO_DMS_DRC_RECOVERY_PAGE;
        }
        if (req_info->is_try && !drc_page_check_for_prefetch(req_info, result, drc)) {
            return DMS_SUCCESS;
        }
    }

    bool32 can_cvt = CM_FALSE;
    int32 ret = drc_enq_req_item(ctx, drc, req_info, &can_cvt);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        drc_try_confirm_cvt(drc);
        return ret;
    }

    ret = drc_set_req_result(ctx, result, drc, req_info, can_cvt);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        return ret;
    }

    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_shift_to_head(drc);
    }

    return DMS_SUCCESS;
}

int32 drc_request_page_owner(dms_process_context_t *ctx, char* resid, uint16 len, uint8 res_type,
    drc_request_info_t* req_info, drc_req_owner_result_t* result)
{
    result->invld_insts    = 0;
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_TRUE, req_info->sess_type, req_info->intercept_type, CM_TRUE);
    int ret = drc_enter(resid, len, res_type, options, &drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (drc == NULL) {
        LOG_DEBUG_ERR("[DMS][%s]alloc buf res failed", cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }
    if (drc->is_recycling) {
        drc_leave(drc, options);
        LOG_DYN_TRC_WAR("[RPO][%s]is recycling", cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_IS_RECYCLING;
    }
    ret = drc_request_page_owner_internal(ctx, resid, res_type, req_info, result, drc);
    drc_leave(drc, options);
    return ret;
}

void drc_add_edp_map(drc_page_t *drc_page, uint8 inst_id, uint64 lsn)
{
    bitmap64_set(&drc_page->edp_map, inst_id);
    if (lsn > drc_page->last_edp_lsn) {
        drc_page->last_edp = inst_id;
        drc_page->last_edp_lsn = lsn;
    }
}

static void drc_remove_edp_map(drc_page_t *drc_page, uint8 inst_id)
{
    bitmap64_clear(&drc_page->edp_map, inst_id);
    if (inst_id == drc_page->last_edp) {
        drc_page->last_edp = CM_INVALID_ID8;
    }
}

uint64 try_get_drc_page_seq(drc_head_t *drc)
{
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *page_drc = (drc_page_t *)drc;
        return page_drc->seq;
    }
    return 0;
}

void drc_get_convert_info(drc_head_t *drc, cvt_info_t *cvt_info)
{
    drc_request_info_t *req_info = &drc->converting.req_info;

    cvt_info->req_info = *req_info;
    cvt_info->res_type = drc->type;
    cvt_info->len = drc->len;
    cvt_info->owner_id = drc->owner;
    cvt_info->seq = try_get_drc_page_seq(drc);

    CM_ASSERT(cvt_info->req_mode == DMS_LOCK_EXCLUSIVE || cvt_info->req_mode == DMS_LOCK_SHARE);
    CM_ASSERT(cvt_info->req_id < DMS_MAX_INSTANCES);

    errno_t ret = memcpy_s(cvt_info->resid, DMS_RESID_SIZE, DRC_DATA(drc), drc->len);
    DMS_SECUREC_CHECK(ret);

    if (drc->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_SHARE) {
        cvt_info->invld_insts = 0;
    } else if (drc->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        cvt_info->invld_insts = drc->copy_insts;
        bitmap64_clear(&cvt_info->invld_insts, cvt_info->req_id);
    } else {
        CM_ASSERT(drc->copy_insts == 0);
    }

    if (drc->owner == CM_INVALID_ID8) {
        CM_ASSERT(drc->lock_mode == DMS_LOCK_NULL);
        cvt_info->type = DRC_REQ_OWNER_GRANTED;
        return;
    }

    if (drc->owner != req_info->inst_id) {
        if (drc->type == DRC_RES_LOCK_TYPE && req_info->req_mode == DMS_LOCK_SHARE &&
            drc->lock_mode == DMS_LOCK_SHARE) {
            // asker can get lock_s directly if owner hold lock_s, this scenario applies only to distributed locks.
            cvt_info->type = DRC_REQ_OWNER_GRANTED;
            return;
        }
        cvt_info->type = DRC_REQ_OWNER_CONVERTING;
        return;
    }

    cvt_info->type = DRC_REQ_OWNER_ALREADY_OWNER;
}

void drc_convert_page_owner(drc_head_t* drc, claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 ex_owner = drc->owner;
    claim_info->old_id = ex_owner;

    cvt_info->req_id = CM_INVALID_ID8;
    cvt_info->invld_insts = 0;

    if (drc->converting.req_info.inst_id != claim_info->new_id ||
        drc->converting.req_info.sess_id != claim_info->sess_id ||
        claim_info->srsn < drc->converting.req_info.srsn) {
        LOG_DEBUG_WAR("[DMS][%s]invalid claim req, drc:[inst=%d sid=%d srsn=%u] claim:[inst=%d sid=%d srsn=%u]",
            cm_display_resid(DRC_DATA(drc), drc->type), drc->converting.req_info.inst_id,
            drc->converting.req_info.sess_id, drc->converting.req_info.srsn, claim_info->new_id, claim_info->sess_id,
            claim_info->srsn);
        return;
    }

    drc->lock_mode = claim_info->req_mode;
    // X mode or first owner
    if (claim_info->req_mode == DMS_LOCK_EXCLUSIVE || drc->owner == CM_INVALID_ID8) {
        drc->copy_insts = 0;
        drc->owner = claim_info->new_id;
    } else if (drc->owner != claim_info->new_id){
        bitmap64_set(&drc->copy_insts, claim_info->new_id);
    }

    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        if (claim_info->req_mode == DMS_LOCK_EXCLUSIVE) {
            drc_remove_edp_map(drc_page, claim_info->new_id);
        }

        if (claim_info->has_edp) {
            drc_add_edp_map(drc_page, ex_owner, claim_info->lsn);
        }
        LOG_DEBUG_INF("[DCS][%s][drc_claim_page_owner]: last_edp=%d, last_edp_lsn=%llu, edp_map=%llu",
            cm_display_pageid(drc_page->data), drc_page->last_edp, drc_page->last_edp_lsn, drc_page->edp_map);
    }

    if (cm_bilist_empty(&drc->convert_q)) {
        init_drc_cvt_item(&drc->converting);
        return;
    }

    /* assign next lock request to converting */
    drc_lock_item_t *next_lock_item = (drc_lock_item_t *)cm_bilist_pop_first(&drc->convert_q);
    drc->converting.req_info = next_lock_item->req_info;
    drc->converting.begin_time = g_timer()->monotonic_now;
    drc_res_pool_free_item(&ctx->lock_item_pool, (char*)next_lock_item);

    /* get the detail converting information */
    drc_get_convert_info(drc, cvt_info);
}

int32 drc_claim_page_owner(claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, claim_info->sess_type, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(claim_info->resid, (uint16)claim_info->len, claim_info->res_type, options, &drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (drc == NULL) {
        LOG_DYN_TRC_ERR("[DCO][%s]drc is NULL",
            cm_display_resid(claim_info->resid, claim_info->res_type));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_NOT_FOUND, cm_display_resid(claim_info->resid, claim_info->res_type));
        return ERRNO_DMS_DRC_PAGE_NOT_FOUND;
    }
    drc_convert_page_owner(drc, claim_info, cvt_info);
    LOG_DEBUG_INF("[DCS][%s][drc_claim_page_owner]: mode=%d, owner=%d, copy_insts=%llu",
        cm_display_resid(claim_info->resid, claim_info->res_type), drc->lock_mode, drc->owner, drc->copy_insts);
    drc_leave(drc, options);
    return DMS_SUCCESS;
}

static inline bool8 if_req_can_be_canceled(drc_request_info_t *cvt_req, drc_request_info_t *req)
{
    if (req->inst_id != cvt_req->inst_id ||
        req->sess_id != cvt_req->sess_id ||
        req->srsn < cvt_req->srsn) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

bool8 drc_cancel_converting(drc_head_t *drc, drc_request_info_t *req, cvt_info_t* cvt_info)
{
    if (drc->converting.req_info.inst_id == CM_INVALID_ID8) {
        return CM_TRUE;
    }

    if (if_req_can_be_canceled(&drc->converting.req_info, req)) {
        LOG_DEBUG_INF("[DRC][%s][drc_cancel_converting]: cancel converting src_inst=%d, src_sid=%d, ruid=%llu",
            cm_display_resid(DRC_DATA(drc), drc->type), req->inst_id, req->sess_id, req->ruid);
        if (cm_bilist_empty(&drc->convert_q)) {
            init_drc_cvt_item(&drc->converting);
        } else {
            /* assign next lock request to converting */
            drc_lock_item_t *next_lock_item = (drc_lock_item_t *)cm_bilist_pop_first(&drc->convert_q);
            drc->converting.req_info = next_lock_item->req_info;
            drc->converting.begin_time = g_timer()->monotonic_now;
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)next_lock_item);
            /* get the detail converting information */
            drc_get_convert_info(drc, cvt_info);
        }
        return CM_TRUE;
    }
    return CM_FALSE;
}

static void drc_cancel_convert_q(drc_head_t *drc, drc_request_info_t *req)
{
    drc_lock_item_t *tmp = (drc_lock_item_t *)cm_bilist_head(&drc->convert_q);
    while (tmp != NULL) {
        if (if_req_can_be_canceled(&tmp->req_info, req)) {
            LOG_DEBUG_INF("[DRC][%s][drc_cancel_convert_q]: cancel convert_q src_inst=%d, src_sid=%d, ruid=%llu",
                cm_display_resid(DRC_DATA(drc), drc->type), req->inst_id, req->sess_id, req->ruid);
            cm_bilist_del(&tmp->node, &drc->convert_q);
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)tmp);
            return;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
}

void drc_cancel_request_res(char *resid, uint16 len, uint8 res_type, drc_request_info_t *req, cvt_info_t* cvt_info)
{
    LOG_DEBUG_INF("[DRC][%s][drc_cancel_request_res]: src_inst =%u, src_sid=%u, ruid=%llu",
        cm_display_resid(resid, res_type), (uint32)req->inst_id, (uint32)req->sess_id, req->ruid);

    cvt_info->req_id = CM_INVALID_ID8;
    cvt_info->invld_insts = 0;

    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, req->sess_type, req->intercept_type, CM_TRUE);
    int ret = drc_enter(resid, len, res_type, options, &drc);
    if (ret != DMS_SUCCESS) {
        return;
    }
    if (drc == NULL) {
        LOG_DEBUG_WAR("[DRC][%s][drc_cancel_request_res]: drc is NULL src_inst=%d, src_sid=%d, ruid=%llu",
            cm_display_resid(resid, res_type), req->inst_id, req->sess_id, req->ruid);
        return;
    }

    if (drc_cancel_converting(drc, req, cvt_info)) {
        drc_leave(drc, options);
        return;
    }

    drc_cancel_convert_q(drc, req);
    drc_leave(drc, options);
}

bool8 drc_can_release(drc_page_t *drc_page, uint8 inst_id)
{
    if (drc_page->head.is_recycling) { // recycling > release
        return CM_TRUE;
    }

    drc_cvt_item_t *converting = &drc_page->head.converting;
    // Not related to inst_id.
    if (drc_page->head.owner != inst_id && !bitmap64_exist(&drc_page->head.copy_insts, inst_id) &&
        converting->req_info.inst_id != inst_id) {
        return CM_TRUE;
    }

    // here, owner is inst_id || copy instances || converting is inst_id

    // converting == (inst_id, X), claim maybe msg lost, real owner is inst_id and modify page.
    // In other words, although it seems to be not related to inst_id, it may actually be related.
    if (converting->req_info.inst_id == inst_id && converting->req_info.req_mode == DMS_LOCK_EXCLUSIVE) {
        return CM_FALSE;
    }

    // here, owner is inst_id || copy instances || converting == (inst_id, S)
    if (drc_page->head.owner != inst_id) {
        // here, copy instances || converting == (inst_id, S)
        return CM_TRUE;
    }

    // here, owner is inst_id
    if (converting->req_info.inst_id != CM_INVALID_ID8 ||
        drc_page->edp_map != 0 ||
        drc_page->need_flush) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

bool8 drc_chk_4_release(char *resid, uint16 len, uint8 inst_id)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    options |= DRC_RES_RELEASE;
    if (drc_enter(resid, len, DRC_RES_PAGE_TYPE, options, &drc) != DMS_SUCCESS) {
        return CM_FALSE;
    }

    // DRC not exists, page can be released, Notice, it is abnormal
    if (drc == NULL) {
        LOG_DEBUG_WAR("[%s]drc_chk_4_release, but DRC not exists", cm_display_pageid(resid));
        return CM_TRUE;
    }

    bool8 release = drc_can_release((drc_page_t *)drc, inst_id);
    if (drc->owner == inst_id && release) {
        drc_shift_to_tail(drc);
    } else if (!release) {
        drc_try_confirm_cvt(drc);
    }
    
    drc_leave(drc, options);
    return release;
}

void drc_release_by_part(drc_part_list_t *part, uint8 type)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_res_bucket_t *bucket = NULL;
    drc_head_t *drc = NULL;

    while (node != NULL) {
        drc = DRC_RES_NODE_OF(drc_head_t, node, part_node);
        node = BINODE_NEXT(node);
        bucket = drc_res_map_get_bucket(res_map, DRC_DATA(drc), drc->len);
        cm_spin_lock(&bucket->lock, NULL);
        DRC_DISPLAY(drc, "release");
        drc_release(drc, res_map, bucket);
        cm_spin_unlock(&bucket->lock);
    }
}

int dms_recovery_page_need_skip(char *pageid, unsigned long long redo_lsn, unsigned char *skip)
{
    dms_reset_error();
    drc_page_t *drc_page = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, (drc_head_t **)&drc_page);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (redo_lsn > drc_page->owner_lsn || drc_page->owner_lsn == 0) { // just created or no owner
        drc_page->need_recover = CM_TRUE;
    }
    *skip = !drc_page->need_recover;
    drc_leave((drc_head_t *)drc_page, options);
    return DMS_SUCCESS;
}

static void dms_recovery_analyse_page_need_recover(drc_page_t *drc_page)
{
    drc_page->need_flush = CM_FALSE;
    drc_page->need_recover = CM_TRUE;

    // if page has been add to NORMAL_COPY_WITH_REDO, should remove, because the page will be dirty
    if (drc_page->rebuild_type == REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO) {
        dms_reform_rebuild_del_from_flush_copy(drc_page);
        drc_page->rebuild_type = REFORM_ASSIST_LIST_NORMAL_COPY;
    }
}

static void dms_recovery_analyse_page_skip_recover(drc_page_t *drc_page)
{
    if (drc_page->need_recover) {
        return;
    }
    // if page has not been add to NORMAL_COPY_WITH_REDO, should add to NORMAL_COPY_WITH_REDO
    if (drc_page->rebuild_type == REFORM_ASSIST_LIST_NORMAL_COPY) {
        dms_reform_rebuild_add_to_flush_copy(drc_page);
        drc_page->rebuild_type = REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO;
        drc_page->need_flush = CM_TRUE;
    }
}

int dms_recovery_analyse_page(char *pageid, unsigned long long redo_lsn)
{
    dms_reset_error();
    drc_page_t *drc_page = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, (drc_head_t **)&drc_page);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    CM_ASSERT(drc_page != NULL);
    if (drc_page->need_recover) {
        drc_leave((drc_head_t *)drc_page, options);
        return DMS_SUCCESS;
    }
    if (redo_lsn > drc_page->owner_lsn) {
        dms_recovery_analyse_page_need_recover(drc_page);
    } else {
        dms_recovery_analyse_page_skip_recover(drc_page);
    }
    drc_leave((drc_head_t *)drc_page, options);
    return DMS_SUCCESS;
}

void fill_dv_drc_buf_info(drc_head_t *drc, dv_drc_buf_info *res_buf_info)
{
    res_buf_info->master_id = g_dms.inst_id;
    res_buf_info->is_valid = CM_TRUE;
    res_buf_info->copy_promote = 0;

    cm_spin_lock(&drc->lock, NULL);
    res_buf_info->type = drc->type;
    res_buf_info->claimed_owner = drc->owner;
    res_buf_info->lock_mode = drc->lock_mode;
    res_buf_info->recycling = drc->is_recycling;
    res_buf_info->len = drc->len;
    res_buf_info->part_id = drc->part_id;
    res_buf_info->copy_insts = drc->copy_insts;
    res_buf_info->converting_req_info_inst_id = drc->converting.req_info.inst_id;
    res_buf_info->converting_req_info_curr_mode = drc->converting.req_info.curr_mode;
    res_buf_info->converting_req_info_req_mode = drc->converting.req_info.req_mode;
    char *drc_data = cm_display_resid(DRC_DATA(drc), drc->type);
    int ret = strcpy_s(res_buf_info->data, DMS_MAX_RESOURCE_NAME_LEN, drc_data);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DRC][fill_dv_drc_buf_info]:strcpy_s err: %d", ret);
        res_buf_info->is_valid = CM_FALSE;
        cm_spin_unlock(&drc->lock);
        return;
    }
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        res_buf_info->last_edp = drc_page->last_edp;
        res_buf_info->lsn = drc_page->last_edp_lsn;
        res_buf_info->edp_map = drc_page->edp_map;
        res_buf_info->in_recovery = drc_page->need_recover;
        res_buf_info->recovery_skip = drc_page->need_flush;
    } else {
        res_buf_info->last_edp = 0;
        res_buf_info->lsn = 0;
        res_buf_info->edp_map = 0;
        res_buf_info->in_recovery = 0;
        res_buf_info->recovery_skip = 0;
    }
    cm_spin_unlock(&drc->lock);
}

static void find_valid_drc_buf(drc_res_pool_t *pool, uint64 *index, dv_drc_buf_info *res_buf_info)
{
    while (*index < pool->item_hwm) {
        drc_head_t *drc_head = (drc_head_t *)drc_pool_find_item(pool, *index);
        if (drc_head == NULL) {
            res_buf_info->is_valid = CM_FALSE;
            return;
        }
        (*index)++;
        if (drc_head->is_using) {
            fill_dv_drc_buf_info(drc_head, res_buf_info);
            return;
        }
    }
    res_buf_info->is_valid = CM_FALSE;
}

drc_res_pool_t *get_buf_pool(int drc_type)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    switch (drc_type) {
        case DRC_RES_PAGE_TYPE:
            return &ctx->global_buf_res.res_map.res_pool;
        case DRC_RES_LOCK_TYPE:
            return &ctx->global_lock_res.res_map.res_pool;
        case DRC_RES_ALOCK_TYPE:
            return &ctx->global_alock_res.res_map.res_pool;
        case DRC_RES_GLOBAL_XA_TYPE:
            return &ctx->global_xa_res.res_map.res_pool;
        default:
            return NULL;
    }
}

void dms_get_buf_res(uint64 *index, dv_drc_buf_info *res_buf_info, int drc_type)
{
    dms_reset_error();

    if (res_buf_info == NULL || index == NULL) {
        LOG_DEBUG_ERR("[DRC][dms_get_buf_res]: param error");
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return;
    }

    if (!g_dms.dms_init_finish) {
        res_buf_info->is_valid = CM_FALSE;
        return;
    }

    drc_res_pool_t *pool = get_buf_pool(drc_type);
    if (pool == NULL) {
        res_buf_info->is_valid = CM_FALSE;
        return;
    }
    find_valid_drc_buf(pool, index, res_buf_info);
}

bool8 drc_chk_page_ownership(char* resid, uint16 len, uint8 inst_id, uint8 curr_mode)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    options |= DRC_RES_RELEASE;
    if (drc_enter(resid, len, DRC_RES_PAGE_TYPE, options, &drc) != DMS_SUCCESS || drc == NULL) {
        return CM_FALSE;
    }

    // owner has been transferred, but claim message has not been processed
    if (curr_mode == DMS_LOCK_NULL && drc->converting.req_info.inst_id != CM_INVALID_ID8 &&
        drc->converting.req_info.req_mode == DMS_LOCK_EXCLUSIVE) {
        drc_try_confirm_cvt(drc);
        drc_leave(drc, options);
        return CM_FALSE;
    }

    uint8 owner = drc->owner;
    drc_leave(drc, options);
    return owner == inst_id;
}