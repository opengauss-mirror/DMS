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
        LOG_DEBUG_INF("[DRC][%s] conflicted with other, [req1:inst_id=%u, sid=%u, ruid=%llu, "
            "req_mode=%u, curr_mode=%u], [req2:inst_id=%u, sid=%u, ruid=%llu, req_mode=%u, curr_mode=%u]",
            cm_display_resid(resid, type), (uint32)req1->inst_id, (uint32)req1->sess_id, req1->ruid,
            (uint32)req1->req_mode, (uint32)req1->curr_mode, (uint32)req2->inst_id, (uint32)req2->sess_id,
            req2->ruid, (uint32)req2->req_mode, (uint32)req2->curr_mode);
        return CM_TRUE;
    }
    return CM_FALSE;
}

static inline int32 chk_convertq_4_conflict_reverse(drc_buf_res_t *buf_res, drc_request_info_t *req,
    drc_lock_item_t* next)
{
    while (next != NULL) {
        if (chk_conflict_with_x_lock(buf_res->data, buf_res->type, req, &next->req_info)) {
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        next = (drc_lock_item_t*)next->node.next;
    }
    return DMS_SUCCESS;
}

static int32 chk_if_valid_retry_request(drc_buf_res_t *buf_res, drc_request_info_t *new_req,
    drc_request_info_t *old_req, drc_lock_item_t *next)
{
    if (new_req->req_time <= old_req->req_time) {
        LOG_DEBUG_INF("[DRC][%s] invalid request, [new:inst_id=%u, sid=%u, ruid=%llu, req_mode=%u, "
            "curr_mode=%u, req_time=%lld], [old:inst_id=%u, sid=%u, ruid=%llu, req_mode=%u, curr_mode=%u, "
            "req_time=%lld]", cm_display_resid(buf_res->data, buf_res->type), (uint32)new_req->inst_id,
            (uint32)new_req->sess_id, new_req->ruid, (uint32)new_req->req_mode, (uint32)new_req->curr_mode,
            new_req->req_time, (uint32)old_req->inst_id, (uint32)old_req->sess_id, old_req->ruid,
            (uint32)old_req->req_mode, (uint32)old_req->curr_mode, old_req->req_time);
        return ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST;
    }
    if (new_req->req_mode > old_req->req_mode) {
        return chk_convertq_4_conflict_reverse(buf_res, new_req, next);
    }
    return DMS_SUCCESS;
}

static int32 chk_convertq_4_conflict(drc_buf_res_t* buf_res, drc_request_info_t* req, bool32 *is_retry)
{
    drc_lock_item_t* tmp = (drc_lock_item_t*)cm_bilist_head(&buf_res->convert_q);
    while (tmp != NULL) {
        // retry request
        if (tmp->req_info.inst_id == req->inst_id) {
            int32 ret = chk_if_valid_retry_request(buf_res, req, &tmp->req_info, (drc_lock_item_t*)tmp->node.next);
            if (ret != DMS_SUCCESS) {
                return ret;
            }
            *is_retry = CM_TRUE;
            tmp->req_info = *req;
            return DMS_SUCCESS;
        }

        if (chk_conflict_with_x_lock(buf_res->data, buf_res->type, &tmp->req_info, req)) {
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
    return DMS_SUCCESS;
}

static int32 drc_check_req_4_conflict(drc_buf_res_t *buf_res, drc_request_info_t *req, bool32 *is_retry,
    bool32 *can_cvt)
{
    drc_cvt_item_t *converting = &buf_res->converting;

    // retry request
    if (req->inst_id == converting->req_info.inst_id) {
        drc_lock_item_t *first_node = (drc_lock_item_t*)cm_bilist_head(&buf_res->convert_q);
        int32 ret = chk_if_valid_retry_request(buf_res, req, &converting->req_info, first_node);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
        *can_cvt  = CM_TRUE;
        *is_retry = CM_TRUE;
        converting->req_info = *req;
        converting->begin_time = g_timer()->now;
        return DMS_SUCCESS;
    }

    if (buf_res->lock_mode == DMS_LOCK_SHARE && converting->req_info.req_mode == DMS_LOCK_EXCLUSIVE &&
        bitmap64_exist(&buf_res->copy_insts, req->inst_id)) {
        LOG_DEBUG_INF("[DRC][%s]:conflicted with other, [buf_res:owner=%u, mode=%u, cvt:inst_id=%u, req_mode=%u], "
            "[req:inst_id=%u, sid=%u, ruid=%llu, req_mode=%u, curr_mode=%u]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->claimed_owner,
            (uint32)buf_res->lock_mode, (uint32)converting->req_info.inst_id, (uint32)converting->req_info.req_mode,
            (uint32)req->inst_id, (uint32)req->sess_id, req->ruid, (uint32)req->req_mode, (uint32)req->curr_mode);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }

    if (buf_res->claimed_owner == req->inst_id) {
        // for example: owner:0, converting:1, new request inst:0
        LOG_DEBUG_INF("[DRC][%s]:conflicted with other, [buf_res:owner=%u, mode=%u], "
            "[req:inst_id=%u, sid=%u, ruid=%llu, req_mode=%u, curr_mode=%u]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->claimed_owner,
            (uint32)buf_res->lock_mode, (uint32)req->inst_id, (uint32)req->sess_id,
            req->ruid, (uint32)req->req_mode, (uint32)req->curr_mode);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }
    *can_cvt = CM_FALSE;
    return chk_convertq_4_conflict(buf_res, req, is_retry);
}

static int32 drc_enq_req_item(drc_buf_res_t *buf_res, drc_request_info_t *req_info, bool32 *converting)
{
    /* there is no waiting and converting */
    if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        cm_panic(buf_res->convert_q.count == 0);
        buf_res->converting.req_info = *req_info;
        buf_res->converting.begin_time = g_timer()->now;
        *converting = CM_TRUE;
        return DMS_SUCCESS;
    }

    // try lock request, abandon to try
    if (req_info->is_try && buf_res->type == DRC_RES_LOCK_TYPE) {
        LOG_DEBUG_WAR("[DMS][%s] abandon try", cm_display_resid(buf_res->data, buf_res->type));
        return ERRNO_DMS_DRC_LOCK_ABANDON_TRY;
    }

    bool32 is_retry_quest = CM_FALSE;
    int32 ret = drc_check_req_4_conflict(buf_res, req_info, &is_retry_quest, converting);
    if (ret != DMS_SUCCESS || is_retry_quest) {
        if (is_retry_quest) {
            LOG_DEBUG_INF("[DRC][%s][drc_enq_req_item] find the same req, is retry:%u",
                cm_display_resid(buf_res->data, buf_res->type), *converting);
        }
        return ret;
    }

    drc_lock_item_t *req = (drc_lock_item_t*)drc_res_pool_alloc_item(&DRC_RES_CTX->lock_item_pool);
    if (SECUREC_UNLIKELY(req == NULL)) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH;
    }

    *converting   = CM_FALSE;
    req->req_info = *req_info;
    cm_bilist_add_tail(&req->node, &buf_res->convert_q);
    return DMS_SUCCESS;
}

uint8 drc_lookup_owner_id(uint64 *owner_map)
{
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; ++i) {
        // currently, for multiple owners, return the owner with the smallest id
        if (bitmap64_exist(owner_map, i)) {
            return i;
        }
    }

    cm_panic(0);
    return 0;
}

static void drc_get_page_no_owner(drc_req_owner_result_t *result, drc_buf_res_t *buf_res, drc_request_info_t* req_info)
{
    if (req_info->sess_type == DMS_SESSION_RECOVER && buf_res->type == DRC_RES_PAGE_TYPE) {
        buf_res->in_recovery = CM_TRUE;
    }

    if (buf_res->last_edp == CM_INVALID_ID8) {
        result->type = DRC_REQ_OWNER_GRANTED;
        result->curr_owner_id = req_info->inst_id;
        LOG_DEBUG_INF("[DRC][%s][drc_get_page_no_owner]grant owner directly, in recovery: %d, owner: %d, type: %u",
            cm_display_resid(buf_res->data, buf_res->type), buf_res->in_recovery, result->curr_owner_id, result->type);
        return;
    }

    result->curr_owner_id = buf_res->last_edp;

    if (result->curr_owner_id == req_info->inst_id) {
        result->type = DRC_REQ_EDP_LOCAL;
    } else {
        result->type = DRC_REQ_EDP_REMOTE;
    }
    LOG_DEBUG_INF("[DRC][%s][drc_get_page_no_owner]read from edp, in recovery: %d, owner: %d, type: %u",
        cm_display_resid(buf_res->data, buf_res->type), buf_res->in_recovery, result->curr_owner_id, result->type);
}

static void drc_try_prepare_confirm_cvt(drc_buf_res_t *buf_res)
{
    drc_request_info_t *cvt_req = &buf_res->converting.req_info;
    
    if (!if_cvt_need_confirm(buf_res) || cvt_req->inst_id == CM_INVALID_ID8) {
        return;
    }
    
    res_id_t res_id;
    res_id.type = buf_res->type;
    res_id.len = buf_res->len;
    int ret = memcpy_s(res_id.data, DMS_RESID_SIZE, buf_res->data, DMS_RESID_SIZE);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DRC]memcpy_s err: %d", ret);
        return;
    }
    buf_res->converting.begin_time = g_timer()->now;
    LOG_DEBUG_WAR("[DRC][%s] converting [inst:%u sid:%u ruid:%llu req_mode:%u] prepare confirm",
        cm_display_resid(buf_res->data, buf_res->type), (uint32)cvt_req->inst_id,
        (uint32)cvt_req->sess_id, cvt_req->ruid, (uint32)cvt_req->req_mode);
    (void)cm_chan_try_send(DRC_RES_CTX->chan, (void *)&res_id);
}

static void drc_set_req_result(drc_req_owner_result_t *result, drc_buf_res_t *buf_res,
    drc_request_info_t *req_info, bool32 can_cvt)
{
    if (can_cvt) {
        if (buf_res->claimed_owner == CM_INVALID_ID8) {
            drc_get_page_no_owner(result, buf_res, req_info);
            return;
        }
        result->curr_owner_id = buf_res->claimed_owner;

        if (buf_res->claimed_owner == req_info->inst_id) {
            result->type = DRC_REQ_OWNER_ALREADY_OWNER;
        } else {
            result->type = DRC_REQ_OWNER_CONVERTING;
        }

        if (req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
            result->invld_insts = buf_res->copy_insts;
            bitmap64_clear(&result->invld_insts, req_info->inst_id); // don't invalidate self
        }

        if (buf_res->lock_mode == DMS_LOCK_EXCLUSIVE) {
            CM_ASSERT(buf_res->copy_insts == 0);
        }
    } else {
        result->type = DRC_REQ_OWNER_WAITING;
        result->curr_owner_id = CM_INVALID_ID8;
        drc_try_prepare_confirm_cvt(buf_res);
    }
}

static int drc_request_page_owner_internal(char *resid, uint8 type,
    drc_request_info_t *req_info, drc_req_owner_result_t *result, drc_buf_res_t *buf_res)
{
    if (req_info->sess_type == DMS_SESSION_NORMAL && buf_res->in_recovery) {
        LOG_DEBUG_ERR("[DRC][%s]: request page fail, page in recovery", cm_display_resid(resid, type));
        return ERRNO_DMS_DRC_RECOVERY_PAGE;
    }

    // only for try get page owner id, and currently have owner or converting
    // if has edp, no need to preload
    if (req_info->is_try && buf_res->type == DRC_RES_PAGE_TYPE &&
        (buf_res->claimed_owner != CM_INVALID_ID8 || buf_res->converting.req_info.inst_id != CM_INVALID_ID8 ||
         buf_res->last_edp != CM_INVALID_ID8)) {
        result->type = DRC_REQ_OWNER_WAITING;
        result->curr_owner_id = buf_res->claimed_owner;
        return DMS_SUCCESS;
    }

    bool32 can_cvt = CM_FALSE;
    int32 ret = drc_enq_req_item(buf_res, req_info, &can_cvt);
    if (SECUREC_UNLIKELY(ret != DMS_SUCCESS)) {
        drc_try_prepare_confirm_cvt(buf_res);
        return ret;
    }

    drc_set_req_result(result, buf_res, req_info, can_cvt);

    return DMS_SUCCESS;
}

int32 drc_request_page_owner(char* resid, uint16 len, uint8 res_type,
    drc_request_info_t* req_info, drc_req_owner_result_t* result)
{
    result->invld_insts    = 0;
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, req_info->sess_type, CM_TRUE);
    int ret = drc_enter_buf_res(resid, len, res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_ERR("[DMS][%s]alloc buf res failed", cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }
    if (buf_res->recycling) {
        drc_leave_buf_res(buf_res);
        LOG_DEBUG_WAR("[DMS][%s]buf res is recycling", cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_IS_RECYCLING;
    }
    ret = drc_request_page_owner_internal(resid, res_type, req_info, result, buf_res);
    drc_leave_buf_res(buf_res);
    return ret;
}

void drc_add_edp_map(drc_buf_res_t *buf_res, uint8 inst_id, uint64 lsn)
{
    bitmap64_set(&buf_res->edp_map, inst_id);
    if (lsn > buf_res->lsn) {
        buf_res->last_edp = inst_id;
        buf_res->lsn = lsn;
    }
}

static void drc_remove_edp_map(drc_buf_res_t *buf_res, uint8 inst_id)
{
    bitmap64_clear(&buf_res->edp_map, inst_id);
    if (inst_id == buf_res->last_edp) {
        buf_res->last_edp = CM_INVALID_ID8;
    }
}

void drc_get_convert_info(drc_buf_res_t *buf_res, cvt_info_t *cvt_info)
{
    drc_request_info_t *req_info = &buf_res->converting.req_info;

    cvt_info->req_id = req_info->inst_id;
    cvt_info->req_sid = req_info->sess_id;
    cvt_info->req_ruid = req_info->ruid;
    cvt_info->curr_mode = req_info->curr_mode;
    cvt_info->req_mode = req_info->req_mode;
    cvt_info->res_type = buf_res->type;
    cvt_info->len = buf_res->len;
    cvt_info->is_try = req_info->is_try;
    cvt_info->sess_type = req_info->sess_type;
    cvt_info->req_proto_ver = req_info->req_proto_ver;

    CM_ASSERT(cvt_info->req_mode == DMS_LOCK_EXCLUSIVE || cvt_info->req_mode == DMS_LOCK_SHARE);
    CM_ASSERT(cvt_info->req_id < DMS_MAX_INSTANCES);

    cvt_info->owner_id = buf_res->claimed_owner;

    errno_t ret = memcpy_s(cvt_info->resid, DMS_RESID_SIZE, buf_res->data, buf_res->len);
    DMS_SECUREC_CHECK(ret);

    if (buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_SHARE) {
        cvt_info->invld_insts = 0;
    } else if (buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        cvt_info->invld_insts = buf_res->copy_insts;
        bitmap64_clear(&cvt_info->invld_insts, cvt_info->req_id);
    } else {
        CM_ASSERT(buf_res->copy_insts == 0);
    }

    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        CM_ASSERT(buf_res->lock_mode == DMS_LOCK_NULL);
        cvt_info->type = DRC_REQ_OWNER_GRANTED;
        return;
    }

    if (buf_res->claimed_owner != req_info->inst_id) {
        cvt_info->type = DRC_REQ_OWNER_CONVERTING;
        return;
    }

    cvt_info->type = DRC_REQ_OWNER_ALREADY_OWNER;
}

void drc_convert_page_owner(drc_buf_res_t* buf_res, claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 ex_owner = buf_res->claimed_owner;
    claim_info->old_id = ex_owner;

    cvt_info->req_id = CM_INVALID_ID8;
    cvt_info->invld_insts = 0;

    if (buf_res->converting.req_info.inst_id != claim_info->new_id ||
        buf_res->converting.req_info.sess_id != claim_info->sess_id ||
        claim_info->srsn < buf_res->converting.req_info.srsn) {
        LOG_DEBUG_WAR("[DMS][%s]invalid claim req, drc:[inst=%u sid=%u srsn=%u] claim:[inst=%u sid=%u srsn=%u]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->converting.req_info.inst_id,
            (uint32)buf_res->converting.req_info.sess_id, buf_res->converting.req_info.srsn,
            (uint32)claim_info->new_id, claim_info->sess_id, claim_info->srsn);
        return;
    }

    buf_res->lock_mode = claim_info->req_mode;
    // X mode or first owner
    if (claim_info->req_mode == DMS_LOCK_EXCLUSIVE || buf_res->claimed_owner == CM_INVALID_ID8) {
        buf_res->copy_insts = 0;
        buf_res->claimed_owner = claim_info->new_id;
    } else if (buf_res->claimed_owner != claim_info->new_id){
        bitmap64_set(&buf_res->copy_insts, claim_info->new_id);
    }

    if (buf_res->type == DRC_RES_PAGE_TYPE) {
        if (claim_info->req_mode == DMS_LOCK_EXCLUSIVE) {
            drc_remove_edp_map(buf_res, claim_info->new_id);
        }

        if (claim_info->has_edp) {
            drc_add_edp_map(buf_res, ex_owner, claim_info->lsn);
        }
    }

    if (cm_bilist_empty(&buf_res->convert_q)) {
        init_drc_cvt_item(&buf_res->converting);
        return;
    }

    /* assign next lock request to converting */
    drc_lock_item_t *next_lock_item = (drc_lock_item_t *)cm_bilist_pop_first(&buf_res->convert_q);
    buf_res->converting.req_info = next_lock_item->req_info;
    buf_res->converting.begin_time = g_timer()->now;
    drc_res_pool_free_item(&ctx->lock_item_pool, (char*)next_lock_item);

    /* get the detail converting information */
    drc_get_convert_info(buf_res, cvt_info);
}

int32 drc_claim_page_owner(claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, claim_info->sess_type, CM_TRUE);
    int ret = drc_enter_buf_res(claim_info->resid, (uint16)claim_info->len, claim_info->res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_ERR("[DCS][%s][drc_claim_page_owner]: buf_res is NULL", cm_display_pageid(claim_info->resid));
        return ERRNO_DMS_DRC_PAGE_NOT_FOUND;
    }
    drc_convert_page_owner(buf_res, claim_info, cvt_info);
    LOG_DEBUG_INF("[DCS][%s][drc_claim_page_owner]: mode =%u, claimed_owner=%u, edp_map=%llu, copy_insts=%llu",
        cm_display_resid(claim_info->resid, claim_info->res_type), (uint32)buf_res->lock_mode,
        (uint32)buf_res->claimed_owner, buf_res->edp_map, buf_res->copy_insts);
    drc_leave_buf_res(buf_res);
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

bool8 drc_cancel_converting(drc_buf_res_t *buf_res, drc_request_info_t *req, cvt_info_t* cvt_info)
{
    if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        return CM_TRUE;
    }

    if (if_req_can_be_canceled(&buf_res->converting.req_info, req)) {
        LOG_DEBUG_INF("[DRC][%s][drc_cancel_converting]: cancel converting src_inst =%u, src_sid=%u, ruid=%llu",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->ruid);
        if (cm_bilist_empty(&buf_res->convert_q)) {
            init_drc_cvt_item(&buf_res->converting);
        } else {
            /* assign next lock request to converting */
            drc_lock_item_t *next_lock_item = (drc_lock_item_t *)cm_bilist_pop_first(&buf_res->convert_q);
            buf_res->converting.req_info = next_lock_item->req_info;
            buf_res->converting.begin_time = g_timer()->now;
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)next_lock_item);
            /* get the detail converting information */
            drc_get_convert_info(buf_res, cvt_info);
        }
        return CM_TRUE;
    }
    return CM_FALSE;
}

static void drc_cancel_convert_q(drc_buf_res_t *buf_res, drc_request_info_t *req)
{
    drc_lock_item_t *tmp = (drc_lock_item_t *)cm_bilist_head(&buf_res->convert_q);
    while (tmp != NULL) {
        if (if_req_can_be_canceled(&tmp->req_info, req)) {
            LOG_DEBUG_INF("[DRC][%s][drc_cancel_convert_q]: cancel convert_q src_inst =%u, src_sid=%u, ruid=%llu",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->ruid);
            cm_bilist_del(&tmp->node, &buf_res->convert_q);
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)tmp);
            LOG_DEBUG_INF("[DRC][%s][drc_cancel_convert_q]: cancel convert_q src_inst =%u, src_sid=%u, ruid=%llu",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->ruid);
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

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, req->sess_type, CM_TRUE);
    int ret = drc_enter_buf_res(resid, len, res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_WAR("[DRC][%s][drc_cancel_request_res]: buf_res is NULL src_inst =%u, src_sid=%u, ruid=%llu",
            cm_display_resid(resid, res_type), (uint32)req->inst_id, (uint32)req->sess_id, req->ruid);
        return;
    }

    if (drc_cancel_converting(buf_res, req, cvt_info)) {
        drc_leave_buf_res(buf_res);
        return;
    }

    drc_cancel_convert_q(buf_res, req);
    drc_leave_buf_res(buf_res);
}

void drc_release_buf_res(drc_buf_res_t *buf_res, drc_res_map_t *buf_map, drc_res_bucket_t *bucket)
{
    // remove convert_q
    drc_release_convert_q(&buf_res->convert_q);

    // remove buf_res from part list
    if (buf_res->type == DRC_RES_PAGE_TYPE) {
        drc_del_buf_res_in_part_list(buf_res);
    } else {
        drc_del_lock_res_in_part_list(buf_res);
    }
    // remove buf_res from hash bucket
    drc_res_map_del_res(buf_map, bucket, buf_res->data, buf_res->len);

    // free buf_res to resource pool, to be reused later
    drc_res_pool_free_item(&buf_map->res_pool, (char*)buf_res);
}

static bool8 drc_chk_4_recycle(char *resid, uint16 len)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = (DRC_RES_NORMAL | DRC_RES_CHECK_MASTER | DRC_RES_RELEASE | DRC_RES_CHECK_ACCESS);
    if (drc_enter_buf_res(resid, len, DRC_RES_PAGE_TYPE, options, &buf_res) != DMS_SUCCESS) {
        return CM_FALSE;
    }

    // DRC not exists, no need to recycle
    if (buf_res == NULL) {
        return CM_FALSE;
    }

    if (buf_res->recycling ||
        buf_res->converting.req_info.inst_id != CM_INVALID_ID8 ||
        buf_res->edp_map != 0 ||
        buf_res->recovery_skip ||
        buf_res->copy_promote != DMS_COPY_PROMOTE_NONE ||
        buf_res->in_recovery) {
        drc_leave_buf_res(buf_res);
        return CM_FALSE;
    }

    buf_res->recycling = CM_TRUE;
    drc_leave_buf_res(buf_res);
    return CM_TRUE;
}

bool8 drc_chk_4_release(char *resid, uint16 len, uint8 inst_id)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = (DRC_RES_NORMAL | DRC_RES_CHECK_MASTER | DRC_RES_RELEASE | DRC_RES_CHECK_ACCESS);
    if (drc_enter_buf_res(resid, len, DRC_RES_PAGE_TYPE, options, &buf_res) != DMS_SUCCESS) {
        return CM_FALSE;
    }

    // DRC not exists, page can be released, Notice, it is abnormal
    if (buf_res == NULL) {
        LOG_DEBUG_WAR("(%s)drc_chk_4_release, but DRC not exists", cm_display_pageid(resid));
        return CM_TRUE;
    }

    // copy instance or DRC is being recycled
    if (buf_res->claimed_owner != inst_id ||
        buf_res->recycling) {
        drc_leave_buf_res(buf_res);
        return CM_TRUE;
    }

    if (buf_res->converting.req_info.inst_id != CM_INVALID_ID8 ||
        buf_res->edp_map != 0 ||
        buf_res->recovery_skip ||
        buf_res->copy_promote != DMS_COPY_PROMOTE_NONE) {
        drc_leave_buf_res(buf_res);
        return CM_FALSE;
    }

    drc_leave_buf_res(buf_res);
    return CM_TRUE;
}

int32 drc_recycle_buf_res(dms_process_context_t *ctx, dms_session_e sess_type, char* resid, uint16 len)
{
    int32 ret = DMS_SUCCESS;

    drc_buf_res_t* buf_res = drc_get_buf_res(resid, len, DRC_RES_PAGE_TYPE, DRC_RES_NORMAL);
    if (buf_res == NULL) {
        LOG_RUN_WAR("[DRC][%s][drc_recycle_buf_res]: buf_res has already been recycled", cm_display_pageid(resid));
        return DMS_SUCCESS;
    }

    if (buf_res->copy_insts > 0) {
        ret = dms_invalidate_share_copy(ctx, resid, len, DRC_RES_PAGE_TYPE,
            buf_res->copy_insts, sess_type, CM_FALSE, CM_FALSE);
    }
    if (ret == DMS_SUCCESS && buf_res->claimed_owner != CM_INVALID_ID8) {
        ret = dms_invalidate_ownership(ctx, resid, len, DRC_RES_PAGE_TYPE, sess_type, buf_res->claimed_owner);
    }

    cm_spin_lock(&buf_res->lock, NULL);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_WAR("[DRC][%s][drc_recycle_buf_res]: invalid owner or copy insts failed", cm_display_pageid(resid));
        buf_res->recycling = CM_FALSE;
        drc_dec_buf_res_ref(buf_res);
        cm_spin_unlock(&buf_res->lock);
        return ret;
    }

    drc_res_bucket_t* bucket = drc_res_map_get_bucket(DRC_BUF_RES_MAP, resid, len);
    cm_spin_lock(&bucket->lock, NULL);
    while (buf_res->count > 1) {
        cm_spin_unlock(&buf_res->lock);
#ifndef WIN32
        fas_cpu_pause();
#endif
        cm_spin_lock(&buf_res->lock, NULL);
    }
    // no owner, no share copy, and no requester is using the buf_res now, so we can release it
    drc_release_buf_res(buf_res, DRC_BUF_RES_MAP, bucket);
    cm_spin_unlock(&bucket->lock);
    LOG_DEBUG_INF("[DRC][%s][drc_recycle_buf_res]:success", cm_display_pageid(resid));
    return ret;
}

/* 
 * Calc recycle target count for smon. It's healthy to maintain DRC usage below threshold,
 * hence greedy recycle is not currently adopted.
 */
static int32 dms_calc_buf_res_recycle_cnt(bool32* greedy)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(DRC_RES_PAGE_TYPE);
    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_pool_t *pool = &res_map->res_pool;
    *greedy = CM_FALSE;

    int32 res_shortage = (int32)(pool->used_num - pool->item_num * DRC_RECYCLE_THRESHOLD);
    if (res_shortage > 0 || pool->res_depleted) {
        LOG_DEBUG_WAR("[DRC][drc_recycle_buf_res_on_demand]: triggered,"
            " usage:%u, thrshd:%u, shortage:%d, depleted:%u", pool->used_num,
            (uint32)(pool->item_num * DRC_RECYCLE_THRESHOLD), res_shortage, (uint32)pool->res_depleted);
        return (res_shortage > 0) ? res_shortage : DRC_RECYCLE_ONE_CNT;
    }

    return -1;
}

uint32 drc_recycle_buf_res_by_part(bilist_t* part_list, uint8 res_type, uint32 target_cnt, bool32 greedy)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res = NULL;
    drc_res_ctx_t *resctx = DRC_RES_CTX;
    dms_process_context_t ctx;
    int32 ret = DMS_SUCCESS;
    uint32 recycled_cnt = 0;

    ctx.inst_id   = (uint8)g_dms.inst_id;
    ctx.sess_id   = resctx->smon_recycle_sid;
    ctx.db_handle = resctx->smon_recycle_handle;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        if (drc_chk_4_recycle(buf_res->data, DMS_PAGEID_SIZE)) {
            ret = drc_recycle_buf_res(&ctx, DMS_SESSION_NORMAL, buf_res->data, DMS_PAGEID_SIZE);
            if (ret == DMS_SUCCESS && ++recycled_cnt >= target_cnt && !greedy) {
                break;
            }
        }
    }
    return recycled_cnt;
}

void drc_recycle_buf_res_on_demand()
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(DRC_RES_PAGE_TYPE);
    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = NULL;
    uint32 part_recycled;
    uint32 total_recycled = 0;
    bool32 greedy;

    int32 target_cnt = dms_calc_buf_res_recycle_cnt(&greedy);
    if (target_cnt == -1) {
        return;
    }

    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part_list = &ctx->global_buf_res.res_parts[part_id];
        part_recycled = drc_recycle_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE, target_cnt, greedy);
        target_cnt -= (target_cnt == DRC_RECYCLE_GREEDY_CNT) ? 0 : part_recycled;
        total_recycled += part_recycled;
        LOG_DEBUG_INF("[DRC][drc_recycle_buf_res_on_demand%d]: part:%u recycled:%u, remaining:%u",
            (int32)(!greedy), (uint32)part_id, part_recycled, target_cnt);
        if (!greedy && target_cnt <= 0) {
            break;
        }
    }

    if (!greedy && total_recycled == 0) {
        /* triggered by res pool extension */
        LOG_DEBUG_ERR("[DRC][drc_recycle_buf_res_on_demand]: failed, target:%d, recycled:%d",
            target_cnt, total_recycled);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return;
    }

    res_map->res_pool.res_depleted = CM_FALSE;
    LOG_DEBUG_INF("[DRC][drc_recycle_buf_res_on_demand]: success, target:%d, recycled:%d",
        target_cnt, total_recycled);
}

void drc_release_buf_res_by_part(bilist_t *part_list, uint8 type)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_res_bucket_t *bucket = NULL;
    drc_buf_res_t *buf_res = NULL;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        bucket = drc_res_map_get_bucket(res_map, buf_res->data, buf_res->len);
        cm_spin_lock(&bucket->lock, NULL);
        DRC_DISPLAY(buf_res, "release");
        drc_release_buf_res(buf_res, res_map, bucket);
        cm_spin_unlock(&bucket->lock);
    }
}

int dms_recovery_page_need_skip(char pageid[DMS_PAGEID_SIZE], unsigned char *skip, unsigned int alloc)
{
    dms_reset_error();
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(alloc, DMS_SESSION_REFORM, CM_TRUE);
    int ret = drc_enter_buf_res(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        *skip = CM_FALSE;
        return DMS_SUCCESS;
    }
    if (buf_res->in_recovery || buf_res->claimed_owner == CM_INVALID_ID8) {
        buf_res->in_recovery = CM_TRUE;
        *skip = CM_FALSE;
    } else {
#ifndef OPENGAUSS
        buf_res->recovery_skip = CM_TRUE;
#endif
        *skip = CM_TRUE;
    }
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}
