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
 * dms_reform_validate.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_validate.c
 *
 * -------------------------------------------------------------------------
 */

#include "drc_res_mgr.h"
#include "dms_reform_msg.h"
#include "dms_reform_proc.h"
#include "dms_reform_proc_stat.h"

// Check the uniqueness of the X lock and consider message reentrant.
static void dms_reform_validate_sx(drc_buf_res_t *buf_res, uint8 lock_mode, uint8 inst_id)
{
    if (buf_res->x_exists && buf_res->x_owner != inst_id) {
        cm_panic_log(CM_FALSE, "[DRC validate][%s]lock mode conflict: node%d is X, but node%d is %d",
            cm_display_resid(buf_res->data, buf_res->type), buf_res->x_owner, inst_id, lock_mode);
        return;
    }

    if (buf_res->s_exists && lock_mode != DMS_LOCK_SHARE) {
        cm_panic_log(CM_FALSE, "[DRC validate][%s]lock mode conflict: S exists, but node%d is X",
            cm_display_resid(buf_res->data, buf_res->type), inst_id);
        return;
    }

    if (lock_mode == DMS_LOCK_SHARE) {
        buf_res->s_exists = CM_TRUE;
    } else {
        buf_res->x_exists = CM_TRUE;
        buf_res->x_owner = inst_id;
    }
}

static void dms_reform_validate_page_cvt(drc_buf_res_t *drc, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    dms_buf_ctrl_t *ctrl = &ctrl_info->ctrl;
    drc_request_info_t *cvt = &drc->converting.req_info;

    if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
        cm_panic_log(
            (drc->lock_mode == DMS_LOCK_EXCLUSIVE && drc->claimed_owner == inst_id) ||
            (drc->lock_mode == DMS_LOCK_NULL && cvt->inst_id == inst_id) ||
            (drc->lock_mode != DMS_LOCK_NULL && cvt->inst_id == inst_id && cvt->req_mode == DMS_LOCK_EXCLUSIVE),
            "[DRC validate][%s][%d]owner:%d drc_lock:%d ctrl_lock:%d",
            cm_display_pageid(drc->data), inst_id, drc->claimed_owner, drc->lock_mode, ctrl->lock_mode);
    } else {
        cm_panic_log(
            (drc->lock_mode == DMS_LOCK_SHARE && drc->claimed_owner == inst_id) ||
            (drc->lock_mode == DMS_LOCK_SHARE && bitmap64_exist(&drc->copy_insts, inst_id)) ||
            (cvt->req_mode == DMS_LOCK_SHARE && cvt->inst_id == inst_id),
            "[DRC validate][%s][%d]owner:%d drc_lock:%d ctrl_lock:%d",
            cm_display_pageid(drc->data), inst_id, drc->claimed_owner, drc->lock_mode, ctrl->lock_mode);
    }
}

static void dms_reform_validate_page_lsn(drc_buf_res_t *drc, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    if (drc->group_lsn == 0 || drc->claimed_owner != inst_id || drc->in_recovery) {
        return;
    }
    cm_panic_log(ctrl_info->lsn >= drc->group_lsn, "[DRC validate][%s][%d]validate lsn, page:%llu, group:%llu",
        cm_display_pageid(drc->data), inst_id, ctrl_info->lsn, drc->group_lsn);
    if (ctrl_info->is_dirty) {
        drc->group_lsn = 0;
    }
}

int dms_reform_proc_page_validate(char *resid, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    dms_buf_ctrl_t *ctrl = &ctrl_info->ctrl;
    uint64 lsn = ctrl_info->lsn;
    bool8 is_dirty = ctrl_info->is_dirty;

    if (SECUREC_UNLIKELY(ctrl->lock_mode >= DMS_LOCK_MODE_MAX ||
        ctrl->is_edp > 1 || ctrl->need_flush > 1)) {
        LOG_DEBUG_ERR("[DRC validate] invalid request message, is_edp=%u, need_flush=%u",
            (uint32)ctrl->is_edp, (uint32)ctrl->need_flush);
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "ctrl_info");
        return ERRNO_DMS_PARAM_INVALID;
    }

    LOG_DEBUG_INF("[DRC validate][%s]remote_ditry: %d, lock_mode: %d, edp: %d, inst_id: %d, lsn: %llu, is_dirty: %d",
        cm_display_pageid(resid), ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp, inst_id, lsn, is_dirty);

    drc_buf_res_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_FALSE);
    int ret = drc_enter_buf_res(resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &drc);
    cm_panic_log(ret == DMS_SUCCESS, "[DRC validate][%s][%d]fail to enter drc", cm_display_pageid(resid), inst_id);
    cm_panic_log(drc != NULL, "[DRC validate][%s][%d]drc is NULL", cm_display_pageid(resid), inst_id);
    dms_reform_validate_sx(drc, ctrl->lock_mode, inst_id);
    dms_reform_validate_page_cvt(drc, ctrl_info, inst_id);
    dms_reform_validate_page_lsn(drc, ctrl_info, inst_id);
    drc_leave_buf_res(drc);
    return DMS_SUCCESS;
}

static void dms_reform_validate_lock_cvt(drc_buf_res_t *drc, uint8 lock_mode, uint8 inst_id)
{
    drc_request_info_t *cvt = &drc->converting.req_info;
    if (lock_mode == DMS_LOCK_EXCLUSIVE) {
        cm_panic_log(
            (drc->lock_mode == DMS_LOCK_EXCLUSIVE && drc->claimed_owner == inst_id) ||
            (cvt->req_mode == DMS_LOCK_EXCLUSIVE && cvt->inst_id == inst_id),
            "[DRC validate][%s][%d]owner:%d drc_lock:%d ctrl_lock:%d",
            cm_display_lockid((dms_drid_t *)drc->data), inst_id, drc->claimed_owner, drc->lock_mode, lock_mode);
    } else {
        cm_panic_log(
            (drc->lock_mode == DMS_LOCK_SHARE && drc->claimed_owner == inst_id) ||
            (drc->lock_mode == DMS_LOCK_SHARE && bitmap64_exist(&drc->copy_insts, inst_id)) ||
            (cvt->req_mode == DMS_LOCK_SHARE && cvt->inst_id == inst_id),
            "[DRC validate][%s][%d]owner:%d drc_lock:%d ctrl_lock:%d",
            cm_display_lockid((dms_drid_t *)drc->data), inst_id, drc->claimed_owner, drc->lock_mode, lock_mode);
    }
}

int dms_reform_proc_lock_validate(dms_drid_t *lockid, uint8 lock_mode, uint8 inst_id)
{
    if (SECUREC_UNLIKELY(lock_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DRC validate] invalid lock_mode: %u", lock_mode);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_LOCK_STATUS_FAIL);
        return ERRNO_DMS_DRC_LOCK_STATUS_FAIL;
    }

    if (lock_mode == DMS_LOCK_NULL) {
        LOG_DEBUG_INF("[DRC validate](%s) lock skip, lock_mode: %d, src_inst: %d",
            cm_display_lockid(lockid), lock_mode, inst_id);
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DRC][lock validate](%s), lock_mode: %d, src_inst: %d",
        cm_display_lockid(lockid), lock_mode, inst_id);

    drc_buf_res_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_FALSE);
    int ret = drc_enter_buf_res((char *)lockid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, options, &drc);
    cm_panic_log(ret == DMS_SUCCESS, "[DRC validate][%s][%d]fail to enter drc", cm_display_lockid(lockid), inst_id);
    cm_panic_log(drc != NULL, "[DRC validate][%s][%d]drc is NULL", cm_display_lockid(lockid), inst_id);
    dms_reform_validate_sx(drc, lock_mode, inst_id);
    dms_reform_validate_lock_cvt(drc, lock_mode, inst_id);
    drc_leave_buf_res(drc);
    return DMS_SUCCESS;
}

static int dms_reform_validate_page_inner(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, uint8 master_id,
    uint8 thread_index)
{
    int ret;
    if (master_id == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_PAGE_LOCAL);
        ret = dms_reform_proc_page_validate(dms_ctx->resid, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_PAGE_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
        ret = dms_reform_req_page_rebuild(MSG_REQ_PAGE_VALIDATE, dms_ctx, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
        ret = dms_reform_req_page_rebuild_parallel(MSG_REQ_PAGE_VALIDATE, dms_ctx, ctrl_info, master_id, thread_index);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
    }
    return ret;
}

int dms_reform_validate_page_parallel(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, unsigned char thread_index)
{
    dms_reset_error();
    uint8 master_id = CM_INVALID_ID8;
    int ret = drc_get_page_master_id(dms_ctx->resid, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DRC][%s]validate_page, fail to get master id", cm_display_pageid(dms_ctx->resid));
        return ret;
    }
    LOG_DEBUG_INF("[DRC][%s]validate_page, master(%d)", cm_display_pageid(dms_ctx->resid), master_id);
    return dms_reform_validate_page_inner(dms_ctx, ctrl_info, master_id, thread_index);
}

static int dms_reform_validate_page(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = g_dms.callback.validate_page(handle, thread_index, thread_num);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
    ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_PAGE_REMOTE);
    return ret;
}

static int dms_reform_validate_lock_inner(drc_local_lock_res_t *lock_res, uint8 master, uint8 thread_index)
{
    int ret = DMS_SUCCESS;
    uint32 append_size = (uint32)sizeof(drc_local_lock_res_t);
    if (master == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL);
        ret = dms_reform_proc_lock_validate(&lock_res->resid, lock_res->latch_stat.lock_mode, master);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock(MSG_REQ_LOCK_VALIDATE, lock_res, append_size, master);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock_parallel(MSG_REQ_LOCK_VALIDATE, lock_res, append_size, master,
            thread_index);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);
    }
    return ret;
}

static int dms_reform_validate_lock_by_bucket(drc_res_bucket_t *bucket, uint8 thread_index)
{
    bilist_node_t *node;
    drc_local_lock_res_t *lock_res;
    uint8 master;
    int ret = DMS_SUCCESS;

    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_BUCKET_LOCK);
    cm_spin_lock(&bucket->lock, NULL);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_BUCKET_LOCK);
    node = cm_bilist_head(&bucket->bucket_list);
    for (uint32 i = 0; i < bucket->bucket_list.count; i++) {
        lock_res = (drc_local_lock_res_t *)DRC_RES_NODE_OF(drc_local_lock_res_t, node, node);
        drc_get_lock_master_id(&lock_res->resid, &master);
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL_RES_LOCK);
        drc_lock_local_resx(lock_res, NULL, NULL);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_LOCAL_RES_LOCK);
        ret = dms_reform_validate_lock_inner(lock_res, master, thread_index);
        drc_unlock_local_resx(lock_res);
        DMS_BREAK_IF_ERROR(ret);
        node = BINODE_NEXT(node);
    }
    cm_spin_unlock(&bucket->lock);
    return ret;
}

static int dms_reform_validate_lock(uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    uint32 bucket_index = 0;
    uint32 step = 1;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    int ret;

    // if parallel
    if (thread_index != CM_INVALID_ID8) {
        bucket_index = thread_index;
        step = thread_num;
    }

    while (bucket_index < ctx->local_lock_res.bucket_num) {
        bucket = &ctx->local_lock_res.buckets[bucket_index];
        ret = dms_reform_validate_lock_by_bucket(bucket, thread_index);
        DMS_RETURN_IF_ERROR(ret);
        bucket_index += step;
    }

    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);
    ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK_REMOTE);

    return ret;
}

int dms_reform_validate_tlock(void *handle, uint8 thread_index, uint8 thread_num)
{
    return g_dms.callback.validate_table_lock(handle, thread_index, thread_num);
}

static int dms_validate_tlock_parallel(dms_tlock_info_t *lock_info, dms_drid_t *lockid, uint8 master,
    uint8 thread_index)
{
    int ret;
    uint32 append_size = (uint32)sizeof(dms_tlock_info_t);
    if (master == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_TLOCK_LOCAL);
        ret = dms_reform_proc_lock_validate(lockid, lock_info->lock_mode, master);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_TLOCK_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_TLOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock(MSG_REQ_TLOCK_VALIDATE, lock_info, append_size, master);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_TLOCK_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_TLOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock_parallel(MSG_REQ_TLOCK_VALIDATE, lock_info, append_size, master,
            thread_index);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_TLOCK_REMOTE);
    }
    return ret;
}

int dms_reform_validate_tlock_parallel(dms_context_t *dms_ctx, dms_tlock_info_t *lock_info, unsigned char thread_index)
{
    dms_reset_error();
    uint8 master;
    dms_drid_t *lock_id = (dms_drid_t *)&dms_ctx->resid;
    int ret = drc_get_lock_master_id(lock_id, &master);
    DMS_RETURN_IF_ERROR(ret);

    LOG_DEBUG_INF("[DRC][%s]dms_reform_validate_tlock_parallel, master(%d)", cm_display_lockid(lock_id), master);

    return dms_validate_tlock_parallel(lock_info, lock_id, master, thread_index);
}

int dms_reform_validate_lock_mode_inner(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = DMS_SUCCESS;

    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_PAGE);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_validate_page(handle, sess_id, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_PAGE);
    DMS_RETURN_IF_ERROR(ret);

    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_LOCK);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_validate_lock(sess_id, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_LOCK);
    DMS_RETURN_IF_ERROR(ret);

#ifndef OPENGAUSS
    dms_reform_proc_stat_start(DRPS_VALIDATE_LOCK_MODE_TLOCK);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_validate_tlock(handle, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_VALIDATE_LOCK_MODE_TLOCK);
    DMS_RETURN_IF_ERROR(ret);
#endif

    return DMS_SUCCESS;
}

int dms_reform_validate_lock_mode(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_validate_lock_mode_inner(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8,
        CM_INVALID_ID8);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

int dms_reform_lsn_validate_buf_res(drc_buf_res_t *buf_res, uint8 thread_index)
{
    lsn_validate_item_t item = { 0 };
    uint32 len = sizeof(lsn_validate_item_t);
    uint8 dst = buf_res->claimed_owner;

    if (dst == CM_INVALID_ID8) {
        cm_panic_log(buf_res->converting.req_info.inst_id <= DMS_MAX_INSTANCES,
            "[LSN validate][%s]no owner", cm_display_pageid(buf_res->data));
        dst = buf_res->converting.req_info.inst_id;
    }

    MEMS_RETURN_IFERR(memcpy_s(item.pageid, DMS_PAGEID_SIZE, buf_res->data, DMS_PAGEID_SIZE));
    item.lsn = buf_res->group_lsn;
    item.in_recovery = buf_res->in_recovery;
    return dms_reform_req_group(MSG_REQ_LSN_VALIDATE, dst, thread_index, (void *)&item, len);
}

static int dms_reform_lsn_validate_by_part_inner(uint16 part_id, uint8 thread_index)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[part_id];
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        if (buf_res->group_lsn == 0) {
            continue;
        }
        dms_reform_proc_stat_start(DRPS_VALIDATE_LSN_COUNT);
        ret = dms_reform_lsn_validate_buf_res(buf_res, thread_index);
        dms_reform_proc_stat_end(DRPS_VALIDATE_LSN_COUNT);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

int dms_reform_lsn_validate_by_partid(uint16 part_id, uint8 thread_index)
{
    dms_reform_req_group_init(thread_index);
    int ret = dms_reform_lsn_validate_by_part_inner(part_id, thread_index);
    if (ret == DMS_SUCCESS) {
        ret = dms_reform_req_group_send_rest(thread_index);
    }
    dms_reform_req_group_free(thread_index);
    return ret;
}

static int dms_reform_lsn_validate_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        ret = dms_reform_lsn_validate_by_partid(part_id, CM_INVALID_ID8);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }
    return DMS_SUCCESS;
}

int dms_reform_validate_lsn(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_lsn_validate_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}