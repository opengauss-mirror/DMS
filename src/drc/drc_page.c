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
#include "dms_log.h"
#include "dms_msg.h"
#include "dcs_page.h"
#include "dms_reform_proc.h"

static bool32 is_conflict_request(char *resid, uint8 type, drc_request_info_t *cvt_req, drc_request_info_t *req)
{
    if (cvt_req->inst_id == req->inst_id) {
        LOG_DEBUG_INF("[DRC][%s] conflicted with self, inst_id=%u, [req:sid=%u, rsn=%u, "
            "req_mode=%u, curr_mode=%u], [cvt:sid=%u, rsn=%u, req_mode=%u, curr_mode=%u]",
            cm_display_resid(resid, type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn,
            (uint32)req->req_mode, (uint32)req->curr_mode, (uint32)cvt_req->sess_id, cvt_req->rsn,
            (uint32)cvt_req->req_mode, (uint32)cvt_req->curr_mode);
        return CM_TRUE;
    }

    if (cvt_req->req_mode == DMS_LOCK_EXCLUSIVE &&
        req->curr_mode == DMS_LOCK_SHARE && req->req_mode == DMS_LOCK_EXCLUSIVE) {
        LOG_DEBUG_INF("[DRC][%s] conflicted with other, [req:inst_id=%u, sid=%u, rsn=%u, "
            "req_mode=%u, curr_mode=%u], [cvt:inst_id=%u, sid=%u, rsn=%u, req_mode=%u, curr_mode=%u]",
            cm_display_resid(resid, type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn,
            (uint32)req->req_mode, (uint32)req->curr_mode, (uint32)req->inst_id, (uint32)cvt_req->sess_id,
            cvt_req->rsn, (uint32)cvt_req->req_mode, (uint32)cvt_req->curr_mode);
        return CM_TRUE;
    }
    return CM_FALSE;
}

/* If the request is s->x, the request cannot be preceded by the x lock. */
static int32 check_conflict_with_x_lock(drc_buf_res_t *buf_res, drc_request_info_t *req_info)
{
    if (is_conflict_request(buf_res->data, buf_res->type, &buf_res->converting.req_info, req_info)) {
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }

    drc_lock_item_t *tmp = (drc_lock_item_t *)cm_bilist_head(&buf_res->convert_q);
    while (tmp != NULL) {
        if (is_conflict_request(buf_res->data, buf_res->type, &tmp->req_info, req_info)) {
            return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
    return DMS_SUCCESS;
}

static int32 check_conflict_request(drc_buf_res_t *buf_res, drc_request_info_t *req_info)
{
    drc_cvt_item_t *converting = &buf_res->converting;
    if (converting->req_info.inst_id == CM_INVALID_ID8) {
        // check owner and copy inst
        if (buf_res->claimed_owner == req_info->inst_id || bitmap64_exist(&buf_res->copy_insts, req_info->inst_id)) {
            if (!(req_info->curr_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE)) {
                LOG_DEBUG_ERR("[DRC][%s][invalid request] buf_res: mode=%u owner=%u copy_insts=%llu "
                    "req: inst_id=%u sid=%u rsn=%u curr_mode=%u req_mode=%u",
                    cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->lock_mode,
                    (uint32)buf_res->claimed_owner, buf_res->copy_insts, (uint32)req_info->inst_id,
                    (uint32)req_info->sess_id, req_info->rsn, (uint32)req_info->curr_mode, (uint32)req_info->req_mode);
                DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST);
                return ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST;
            }
        }
        return DMS_SUCCESS;
    }

    if (buf_res->claimed_owner == converting->req_info.inst_id &&
        bitmap64_exist(&buf_res->copy_insts, req_info->inst_id)) {
        LOG_DEBUG_INF("[DRC][%s]:conflicted with owner, [buf_res:owner=%u, mode=%u], "
            "[req:inst_id=%u, sid=%u, rsn=%u, req_mode=%u, curr_mode=%u]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->claimed_owner,
            (uint32)buf_res->lock_mode, (uint32)req_info->inst_id, (uint32)req_info->sess_id,
            req_info->rsn, (uint32)req_info->req_mode, (uint32)req_info->curr_mode);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OWNER);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OWNER;
    }

    if (buf_res->claimed_owner == req_info->inst_id) {
        // 1.s->x
        // 2.new owner claim msg hasn't arrived, req inst is old owner and need clean flag(need_master_chk) firstly
        LOG_DEBUG_INF("[DRC][%s]:conflicted with other, [buf_res:owner=%u, mode=%u], "
            "[req:inst_id=%u, sid=%u, rsn=%u, req_mode=%u, curr_mode=%u]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->claimed_owner,
            (uint32)buf_res->lock_mode, (uint32)req_info->inst_id, (uint32)req_info->sess_id,
            req_info->rsn, (uint32)req_info->req_mode, (uint32)req_info->curr_mode);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }

    if (check_conflict_with_x_lock(buf_res, req_info) != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER);
        return ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER;
    }
    return DMS_SUCCESS;
}

static inline bool32 is_the_same_req_4_res(drc_request_info_t* req1, drc_request_info_t* req2)
{
    if (req1->inst_id == req2->inst_id && req1->curr_mode == req2->curr_mode &&
        (req1->sess_id == req2->sess_id && req1->req_mode == req2->req_mode)) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static bool32 check_if_the_retry_req(drc_buf_res_t* buf_res, drc_request_info_t* req, bool32 *converting)
{
    // no converting and waiting request
    drc_request_info_t *cvt_req = &buf_res->converting.req_info;
    if (cvt_req->inst_id == CM_INVALID_ID8) {
        return CM_FALSE;
    }

    // check converting
    if (is_the_same_req_4_res(cvt_req, req)) {
        *converting = (cvt_req->rsn != req->rsn);
        if (*converting) {
            cvt_req->rsn = req->rsn;
            buf_res->converting.begin_time = g_timer()->now;
        }
        return CM_TRUE;
    }
    *converting = CM_FALSE;
    // check convert_q
    drc_lock_item_t *tmp = (drc_lock_item_t *)cm_bilist_head(&buf_res->convert_q);
    while (tmp != NULL) {
        if (is_the_same_req_4_res(&tmp->req_info, req)) {
            tmp->req_info = *req;
            return CM_TRUE;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
    return CM_FALSE;
}

static int32 drc_enq_req_item(drc_buf_res_t *buf_res, drc_request_info_t *req_info, bool32 *converting)
{
    if (check_if_the_retry_req(buf_res, req_info, converting)) {
        LOG_DEBUG_INF("[DRC][%s][drc_enq_req_item] find the same req, is retry:%u",
            cm_display_resid(buf_res->data, buf_res->type), *converting);
        return DMS_SUCCESS;
    }

    int32 ret = check_conflict_request(buf_res, req_info);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    /* there is no waiting and converting */
    if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        buf_res->converting.req_info = *req_info;
        buf_res->converting.begin_time = g_timer()->now;
        *converting = CM_TRUE;
        return DMS_SUCCESS;
    }

    // try lock request, abandon to try
    if (req_info->is_try && buf_res->type == DRC_RES_LOCK_TYPE) {
        LOG_DEBUG_WAR("[DMS][%s] abandon try", cm_display_resid(buf_res->data, buf_res->type));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_LOCK_ABANDON_TRY);
        return ERRNO_DMS_DRC_LOCK_ABANDON_TRY;
    }

    drc_lock_item_t *req = (drc_lock_item_t*)drc_res_pool_alloc_item(&DRC_RES_CTX->lock_item_pool);
    if (SECUREC_UNLIKELY(req == NULL)) {
        LOG_DEBUG_ERR("[DMS][%s]alloc convert item failed", cm_display_resid(buf_res->data, buf_res->type));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH;
    }

    *converting   = CM_FALSE;
    req->req_info = *req_info;
    cm_bilist_add_tail(&req->node, &buf_res->convert_q);
    return DMS_SUCCESS;
}

inline uint8 drc_lookup_owner_id(uint64 *owner_map)
{
    for (uint8 i = 0; i < CM_MAX_INSTANCES; ++i) {
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
    if (req_info->sess_rcy == DMS_SESSION_IN_RECOVERY && buf_res->type == DRC_RES_PAGE_TYPE) {
        buf_res->in_recovery = CM_TRUE;
    }

    if (buf_res->last_edp == CM_INVALID_ID8) {
        buf_res->ver = 0;
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
    if (!if_cvt_need_confirm(buf_res)) {
        return;
    }
    drc_request_info_t *cvt_req = &buf_res->converting.req_info;
    res_id_t res_id;
    res_id.type = buf_res->type;
    res_id.len = buf_res->len;
    int ret = memcpy_s(res_id.data, DMS_RESID_SIZE, buf_res->data, DMS_RESID_SIZE);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DRC]memcpy_s err: %d", ret);
        return;
    }
    LOG_DEBUG_WAR("[DRC][%s] converting [inst:%u sid:%u rsn:%u req_mode:%u] prepare confirm",
        cm_display_resid(buf_res->data, buf_res->type), (uint32)cvt_req->inst_id,
        (uint32)cvt_req->sess_id, cvt_req->rsn, (uint32)cvt_req->req_mode);
    if (cm_chan_send_timeout(DRC_RES_CTX->chan, (void *)&res_id, DMS_WAIT_MAX_TIME) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRC][%s]fail to add to confirm queue", cm_display_resid(buf_res->data, buf_res->type));
    }
}

static void drc_set_req_result(drc_req_owner_result_t *result, drc_buf_res_t *buf_res,
    drc_request_info_t *req_info, bool32 can_cvt)
{
    if (can_cvt) {
        if (buf_res->claimed_owner == CM_INVALID_ID8) {
            drc_get_page_no_owner(result, buf_res, req_info);
            return;
        }
        result->ver = buf_res->ver;
        result->curr_owner_id = buf_res->claimed_owner;

        if (buf_res->claimed_owner == req_info->inst_id) {
            result->type = DRC_REQ_OWNER_ALREADY_OWNER;
            result->has_share_copy = CM_TRUE;

            cm_panic_log(buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE,
                "[DRC][%s] buf res status error, curr mode = %u, req mode = %u",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->lock_mode, (uint32)req_info->req_mode);
        } else if (bitmap64_exist(&buf_res->copy_insts, req_info->inst_id)) {
            // share copy to X
            result->type = DRC_REQ_OWNER_CONVERTING;
            result->has_share_copy = CM_TRUE;

            cm_panic_log(req_info->curr_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE &&
                buf_res->lock_mode == DMS_LOCK_SHARE,
                "[DRC][%s] buf res status error, buf curr mode = %u, req curr mode = %u, req mode = %u",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->lock_mode,
                (uint32)req_info->curr_mode, (uint32)req_info->req_mode);
        } else {
            result->type = DRC_REQ_OWNER_CONVERTING;
        }

        if (buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
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
    if (req_info->sess_rcy == CM_FALSE && buf_res->in_recovery) {
        LOG_DEBUG_ERR("[DRC][%s]: request page fail, page in recovery", cm_display_resid(resid, type));
        return ERRNO_DMS_DRC_RECOVERY_PAGE;
    }

    // only for try get page owner id, and currently have owner
    if (req_info->is_try && buf_res->type == DRC_RES_PAGE_TYPE && buf_res->claimed_owner != CM_INVALID_ID8) {
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
    result->has_share_copy = CM_FALSE;

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, req_info->sess_rcy, CM_TRUE);
    int ret = drc_enter_buf_res(resid, len, res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_ERR("[DMS][%s]alloc buf res failed", cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
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
    cvt_info->req_rsn = req_info->rsn;
    cvt_info->curr_mode = req_info->curr_mode;
    cvt_info->req_mode = req_info->req_mode;
    cvt_info->has_share_copy = (bool8)bitmap64_exist(&buf_res->copy_insts, req_info->inst_id);
    cvt_info->res_type = buf_res->type;
    cvt_info->len = buf_res->len;
    cvt_info->is_try = req_info->is_try;
    CM_ASSERT(cvt_info->req_mode == DMS_LOCK_EXCLUSIVE || cvt_info->req_mode == DMS_LOCK_SHARE);
    CM_ASSERT(cvt_info->req_id < CM_MAX_INSTANCES);

    cvt_info->ver = buf_res->ver;
    cvt_info->owner_id = buf_res->claimed_owner;

    if (buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_SHARE) {
        cvt_info->invld_insts = 0;
    } else if (buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE) {
        cvt_info->invld_insts = buf_res->copy_insts;
        bitmap64_clear(&cvt_info->invld_insts, cvt_info->req_id);
    } else {
        CM_ASSERT(buf_res->copy_insts == 0);
    }

    if (buf_res->claimed_owner != req_info->inst_id) {
        cvt_info->type = DRC_REQ_OWNER_CONVERTING;
    } else {
        cvt_info->has_share_copy = CM_TRUE;
        cvt_info->type = DRC_REQ_OWNER_ALREADY_OWNER;
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_SHARE && req_info->req_mode == DMS_LOCK_EXCLUSIVE,
            "[DRC][%s] buf res status error, curr mode = %u, req mode = %u",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->lock_mode, (uint32)req_info->req_mode);
    }
    errno_t ret = memcpy_s(cvt_info->resid, DMS_RESID_SIZE, buf_res->data, buf_res->len);
    DMS_SECUREC_CHECK(ret);
}

int32 drc_convert_page_owner(drc_buf_res_t* buf_res, claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint8 ex_owner = buf_res->claimed_owner;
    claim_info->old_id = ex_owner;

    cvt_info->req_id = CM_INVALID_ID8;
    cvt_info->invld_insts = 0;

    if (buf_res->converting.req_info.inst_id != claim_info->new_id ||
        buf_res->converting.req_info.sess_id != claim_info->sess_id || claim_info->ver < buf_res->ver) {
        LOG_DEBUG_ERR("[DMS][%s]invalid claim req, drc:[inst=%u sid=%u ver=%llu] claim:[inst=%u sid=%u ver=%llu]",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)buf_res->converting.req_info.inst_id,
            (uint32)buf_res->converting.req_info.sess_id, buf_res->ver,
            (uint32)claim_info->new_id, claim_info->sess_id, claim_info->ver);
        return ERRNO_DMS_DRC_INVALID_CLAIM_REQUEST;
    }
    // X mode or first owner
    if (claim_info->req_mode == DMS_LOCK_EXCLUSIVE || buf_res->claimed_owner == CM_INVALID_ID8) {
        buf_res->copy_insts = 0;
        buf_res->claimed_owner = claim_info->new_id;
    } else {
        // share copy, or X->S
        bitmap64_set(&buf_res->copy_insts, claim_info->new_id);
    }

    buf_res->lock_mode = claim_info->req_mode;

    if (buf_res->type == DRC_RES_PAGE_TYPE) {
        if (buf_res->converting.req_info.req_mode == DMS_LOCK_EXCLUSIVE) {
            drc_remove_edp_map(buf_res, claim_info->new_id);
        }

        if (claim_info->has_edp) {
            drc_add_edp_map(buf_res, ex_owner, claim_info->lsn);
        }
    }

    buf_res->ver = claim_info->ver;

    if (cm_bilist_empty(&buf_res->convert_q)) {
        init_drc_cvt_item(&buf_res->converting);
        return DMS_SUCCESS;
    }

    /* assign next lock request to converting */
    drc_lock_item_t *next_lock_item = (drc_lock_item_t *)cm_bilist_pop_first(&buf_res->convert_q);
    buf_res->converting.req_info = next_lock_item->req_info;
    buf_res->converting.begin_time = g_timer()->now;
    drc_res_pool_free_item(&ctx->lock_item_pool, (char*)next_lock_item);

    /* get the detail converting information */
    drc_get_convert_info(buf_res, cvt_info);
    return DMS_SUCCESS;
}

int32 drc_claim_page_owner(claim_info_t* claim_info, cvt_info_t* cvt_info)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, claim_info->sess_rcy, CM_TRUE);
    int ret = drc_enter_buf_res(claim_info->resid, (uint16)claim_info->len, claim_info->res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_ERR("[DCS][%s][drc_claim_page_owner]: buf_res is NULL", cm_display_pageid(claim_info->resid));
        return ERRNO_DMS_DRC_PAGE_NOT_FOUND;
    }
    ret = drc_convert_page_owner(buf_res, claim_info, cvt_info);
    if (ret != DMS_SUCCESS) {
        drc_leave_buf_res(buf_res);
        return ret;
    }

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
        req->rsn <= cvt_req->rsn) {
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
        LOG_DEBUG_INF("[DRC][%s][drc_cancel_converting]: cancel converting src_inst =%u, src_sid=%u, rsn=%u",
            cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn);
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
            LOG_DEBUG_INF("[DRC][%s][drc_cancel_convert_q]: cancel convert_q src_inst =%u, src_sid=%u, rsn=%u",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn);
            cm_bilist_del(&tmp->node, &buf_res->convert_q);
            drc_res_pool_free_item(&DRC_RES_CTX->lock_item_pool, (char*)tmp);
            LOG_DEBUG_INF("[DRC][%s][drc_cancel_convert_q]: cancel convert_q src_inst =%u, src_sid=%u, rsn=%u",
                cm_display_resid(buf_res->data, buf_res->type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn);
            return;
        }
        tmp = (drc_lock_item_t*)tmp->node.next;
    }
}

void drc_cancel_request_res(char *resid, uint16 len, uint8 res_type, drc_request_info_t *req, cvt_info_t* cvt_info)
{
    LOG_DEBUG_INF("[DRC][%s][drc_cancel_request_res]: src_inst =%u, src_sid=%u, rsn=%u",
        cm_display_resid(resid, res_type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn);

    cvt_info->req_id = CM_INVALID_ID8;
    cvt_info->invld_insts = 0;

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, req->sess_rcy, CM_TRUE);
    int ret = drc_enter_buf_res(resid, len, res_type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return;
    }
    if (buf_res == NULL) {
        LOG_DEBUG_WAR("[DRC][%s][drc_cancel_request_res]: buf_res is NULL src_inst =%u, src_sid=%u, rsn=%u",
            cm_display_resid(resid, res_type), (uint32)req->inst_id, (uint32)req->sess_id, req->rsn);
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

inline static void drc_promote_share_copy2owner(drc_buf_res_t *buf_res)
{
    buf_res->claimed_owner = drc_lookup_owner_id(&buf_res->copy_insts);
    bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner);
}

int drc_release_page_owner(bool32 sess_rcy, char* resid, uint16 len, uint8 inst_id, bool8 *released)
{
    *released = CM_FALSE;

    drc_buf_res_t *buf_res = NULL;
    uint8 options = (DRC_RES_NORMAL | DRC_RES_CHECK_MASTER | DRC_RES_IGNORE_DATA | DRC_RES_CHECK_ACCESS);
    int ret = drc_enter_buf_res(resid, len, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        LOG_RUN_WAR("[DCS][%s][drc_release_page_owner]: buf_res is NULL", cm_display_pageid(resid));
        *released = CM_TRUE;
        return DMS_SUCCESS;
    }
    if (buf_res->converting.req_info.inst_id != CM_INVALID_ID8) {
        drc_try_prepare_confirm_cvt(buf_res);
        if (buf_res->converting.req_info.inst_id == inst_id || buf_res->claimed_owner == inst_id) {
            LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: can't release owner, owner:%u"
                "converting:%u inst_id:%u", cm_display_pageid(resid), (uint32)buf_res->claimed_owner,
                (uint32)buf_res->converting.req_info.inst_id, (uint32)inst_id);
            drc_leave_buf_res(buf_res);
            return DMS_SUCCESS;
        }
    }
    if (buf_res->claimed_owner == inst_id) {
        if (buf_res->need_flush || buf_res->edp_map != 0) {
            LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: can't release owner, need flush(%u) or edp_map(%llu)"
                "exists", cm_display_pageid(resid), (uint32)buf_res->need_flush, buf_res->edp_map);
            drc_leave_buf_res(buf_res);
            return DMS_SUCCESS;
        }
        buf_res->claimed_owner = CM_INVALID_ID8;
        *released = CM_TRUE;

        LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: claimed owner cleared, curr owner=%u, curr copy_insts=%llu",
            cm_display_pageid(resid), (uint32)buf_res->claimed_owner, buf_res->copy_insts);
    } else if (bitmap64_exist(&buf_res->copy_insts, inst_id)) {
        bitmap64_clear(&buf_res->copy_insts, inst_id);
        *released = CM_TRUE;

        LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: copy inst cleared, curr owner=%u, curr copy_insts=%llu",
            cm_display_pageid(resid), (uint32)buf_res->claimed_owner, buf_res->copy_insts);
    } else {
        *released = CM_TRUE;

        LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: owner flag is true, curr owner=%u",
            cm_display_pageid(resid), (uint32)buf_res->claimed_owner);
    }

    if (buf_res->claimed_owner != CM_INVALID_ID8 || buf_res->converting.req_info.inst_id != CM_INVALID_ID8) {
        drc_leave_buf_res(buf_res);
        return DMS_SUCCESS;
    }

    // no claimed owner, try to promote one share copy to owner
    if (buf_res->copy_insts != 0) {
        drc_promote_share_copy2owner(buf_res);
        LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: share copy promoted, curr owner=%d, curr copy_insts=%llu",
            cm_display_pageid(buf_res->data), buf_res->claimed_owner, buf_res->copy_insts);
        drc_leave_buf_res(buf_res);
        return DMS_SUCCESS;
    }

    drc_res_bucket_t *bucket = drc_res_map_get_bucket(DRC_BUF_RES_MAP, resid, len);
    cm_spin_lock(&bucket->lock, NULL);
    if (buf_res->count > 1) {
        cm_spin_unlock(&bucket->lock);
        drc_leave_buf_res(buf_res);
        return DMS_SUCCESS;
    }

    // no owner, no share copy, and no requester is using the buf_res now, so we can release it
    uint8 res_type = buf_res->type;
    drc_release_buf_res(buf_res, DRC_BUF_RES_MAP, bucket);
    cm_spin_unlock(&bucket->lock);

    // buf res has add into free list, so can not use drc_leave_buf_res here
    drc_buf_res_unlatch(res_type);
    LOG_DEBUG_INF("[DCS][%s][drc_release_page_owner]: success", cm_display_pageid(resid));

    return DMS_SUCCESS;
}

void drc_release_buf_res_by_part(bilist_t *part_list, uint8 type)
{
    drc_global_res_map_t *global_res_map = DRC_GLOBAL_RES_MAP(type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_res_bucket_t *bucket = NULL;
    drc_buf_res_t *buf_res = NULL;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        bucket = drc_res_map_get_bucket(res_map, buf_res->data, buf_res->len);
        cm_spin_lock(&bucket->lock, NULL);
        dms_reform_display_buf(buf_res, "full_clean");
        drc_release_buf_res(buf_res, res_map, bucket);
        cm_spin_unlock(&bucket->lock);
    }
}

int dms_recovery_page_need_skip(char pageid[DMS_PAGEID_SIZE], unsigned char *skip)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, CM_TRUE, CM_TRUE);
    int ret = drc_enter_buf_res(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        *skip = CM_FALSE;
        return DMS_SUCCESS;
    }
    if (buf_res->in_recovery || buf_res->claimed_owner == CM_INVALID_ID8) {
        *skip = CM_FALSE;
    } else {
        *skip = CM_TRUE;
    }
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}
