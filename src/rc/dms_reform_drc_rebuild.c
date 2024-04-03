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
 * dms_reform_drc_rebuild.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_rebuild.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc.h"
#include "dms_reform_msg.h"
#include "drc_res_mgr.h"
#include "dms_error.h"
#include "drc_page.h"
#include "dms_reform_judge.h"
#include "dcs_page.h"
#include "dms_reform_health.h"
#include "cm_timer.h"
#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_xa.h"
#include "dms_reform_fault_inject.h"
#include "dms_reform_alock.h"

static void drc_rebuild_set_owner(drc_buf_res_t *buf_res, uint8 owner_id, bool8 is_edp)
{
    if (buf_res->claimed_owner == CM_INVALID_ID8 || buf_res->claimed_owner == owner_id) {
        buf_res->claimed_owner = owner_id;
        buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
        return;
    }

    // if page is not edp, it is considered to be owner as priority
    // if last owner has set copy_promote, use current inst instead of last owner
    if (!is_edp) {
        bitmap64_set(&buf_res->copy_insts, buf_res->claimed_owner);
        buf_res->claimed_owner = owner_id;
        buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
        bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner);
    } else {
        bitmap64_set(&buf_res->copy_insts, owner_id);
    }
}

static void drc_rebuild_set_copy(drc_buf_res_t* buf_res, uint8 owner_id, bool8 is_rdp)
{
    if (buf_res->claimed_owner == CM_INVALID_ID8 || buf_res->claimed_owner == owner_id) {
        buf_res->claimed_owner = owner_id;
        buf_res->copy_promote = (is_rdp ? DMS_COPY_PROMOTE_RDP : DMS_COPY_PROMOTE_NORMAL);
        return;
    }

    if (is_rdp) {
        bitmap64_set(&buf_res->copy_insts, buf_res->claimed_owner);
        buf_res->claimed_owner = owner_id;
        buf_res->copy_promote = DMS_COPY_PROMOTE_RDP;
        bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner);
    } else {
        bitmap64_set(&buf_res->copy_insts, owner_id);
    }
}

int dms_reform_proc_page_rebuild(char *resid, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    dms_buf_ctrl_t *ctrl = &ctrl_info->ctrl;
    uint64 lsn = ctrl_info->lsn;
    bool8 is_dirty = ctrl_info->is_dirty;

    if (SECUREC_UNLIKELY(ctrl->lock_mode >= DMS_LOCK_MODE_MAX ||
        ctrl->is_edp > 1 || ctrl->need_flush > 1)) {
        LOG_DEBUG_ERR("[DRC rebuild] invalid request message, is_edp=%u, need_flush=%u",
            (uint32)ctrl->is_edp, (uint32)ctrl->need_flush);
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "ctrl_info");
        return ERRNO_DMS_PARAM_INVALID;
    }

    LOG_DEBUG_INF("[DRC rebuild][%s]remote_ditry: %d, lock_mode: %d, is_edp: %d, inst_id: %d, lsn: %llu, is_dirty: %d",
        cm_display_pageid(resid), ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp, inst_id, lsn, is_dirty);

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_FALSE);
    int ret = drc_enter_buf_res(resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }
    if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->claimed_owner == inst_id,
            "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(resid), buf_res->lock_mode);
        buf_res->claimed_owner = inst_id;
        buf_res->lock_mode = ctrl->lock_mode;
        buf_res->in_recovery = ctrl->in_rcy;
    } else if (ctrl->lock_mode == DMS_LOCK_SHARE) {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == DMS_LOCK_SHARE,
            "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(resid), buf_res->lock_mode);
        buf_res->lock_mode = ctrl->lock_mode;
        if (is_dirty) {
            drc_rebuild_set_owner(buf_res, inst_id, ctrl->is_edp);
        } else { // is not dirty, should notify to flush copy
            drc_rebuild_set_copy(buf_res, inst_id, ctrl->is_remote_dirty);
        }
        buf_res->in_recovery = ctrl->in_rcy; // recover session may read page during recovery
    }

    if (ctrl->is_edp) {
        drc_add_edp_map(buf_res, inst_id, lsn);
    }

    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

static int dms_reform_rebuild_page_inner(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, uint8 master_id,
    uint8 thread_index)
{
    int ret;
    if (master_id == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_PAGE_LOCAL);
        ret = dms_reform_proc_page_rebuild(dms_ctx->resid, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_PAGE_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_PAGE_REMOTE);
        ret = dms_reform_req_page_rebuild(MSG_REQ_PAGE_REBUILD, dms_ctx, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_PAGE_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_PAGE_REMOTE);
        ret = dms_reform_req_page_rebuild_parallel(MSG_REQ_PAGE_REBUILD, dms_ctx, ctrl_info, master_id, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_PAGE_REMOTE);
    }
    return ret;
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
    return dms_reform_rebuild_page_inner(dms_ctx, ctrl_info, master_id, thread_index);
}

int dms_reform_rebuild_send_rest(unsigned int sess_id, unsigned char thread_index)
{
    dms_reform_req_rebuild_t *rebuild_data = NULL;
    int ret = DMS_SUCCESS;

    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
            rebuild_data = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[i];
            if (rebuild_data == NULL) {
                continue;
            }

            if (rebuild_data->offset != sizeof(dms_reform_req_rebuild_t)) {
                ret = dms_reform_send_data(&rebuild_data->head, sess_id);
                DMS_RETURN_IF_ERROR(ret);
                rebuild_data->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
            }
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
        for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
            rebuild_data = (dms_reform_req_rebuild_t *)parallel->data[i];
            if (rebuild_data == NULL) {
                continue;
            }

            if (rebuild_data->offset != sizeof(dms_reform_req_rebuild_t)) {
                ret = dms_reform_send_data(&rebuild_data->head, sess_id);
                DMS_RETURN_IF_ERROR(ret);
                rebuild_data->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
            }
        }
    }

    return DMS_SUCCESS;
}

int dms_reform_rebuild_buf_res(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = g_dms.callback.dms_reform_rebuild_parallel(handle, thread_index, thread_num);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_PAGE_REMOTE_REST);
    ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_PAGE_REMOTE_REST);
    return ret;
}

int drc_get_lock_remaster_id(dms_drid_t *lock_id, uint8 *master_id)
{
    uint16 part_id;
    uint8 inst_id;

    part_id = (uint16)drc_get_lock_partid((uint8 *)lock_id, sizeof(dms_drid_t), DRC_MAX_PART_NUM);
    inst_id = DRC_PART_REMASTER_ID(part_id);
    if (inst_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_LOCK_MASTER_NOT_FOUND, cm_display_lockid(lock_id));
        return ERRNO_DMS_DRC_LOCK_MASTER_NOT_FOUND;
    }

    *master_id = inst_id;
    return DMS_SUCCESS;
}

int dms_reform_proc_lock_rebuild(dms_drid_t *resid, uint8 lock_mode, uint8 src_inst)
{
    if (SECUREC_UNLIKELY(lock_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DRC][lock rebuild] invalid lock_mode: %u", lock_mode);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_LOCK_STATUS_FAIL);
        return ERRNO_DMS_DRC_LOCK_STATUS_FAIL;
    }

    if (lock_mode == DMS_LOCK_NULL) {
        LOG_DEBUG_INF("[DRC][lock rebuild](%s) lock skip, lock_mode: %d, src_inst: %d", cm_display_lockid(resid),
            lock_mode, src_inst);
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DRC][lock rebuild](%s), lock_mode: %d, src_inst: %d", cm_display_lockid(resid), lock_mode,
        src_inst);

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_FALSE);
    int ret = drc_enter_buf_res((char *)resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }

    cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == lock_mode,
        "lock mode not matched, drc: %d, local lock mode: %d", buf_res->lock_mode, lock_mode);

    if (lock_mode == DMS_LOCK_EXCLUSIVE) {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == DMS_LOCK_EXCLUSIVE,
            "lock X not matched");
        cm_panic_log(buf_res->claimed_owner == CM_INVALID_ID8 || buf_res->claimed_owner == src_inst,
            "lock owner(%d) not matched %d", buf_res->claimed_owner, src_inst);
        buf_res->claimed_owner = src_inst;
        buf_res->lock_mode = DMS_LOCK_EXCLUSIVE;
    } else {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == DMS_LOCK_SHARE,
            "lock S not matched");
        if (buf_res->claimed_owner == CM_INVALID_ID8 || buf_res->claimed_owner == src_inst) {
            buf_res->claimed_owner = src_inst;
        } else {
            bitmap64_set(&buf_res->copy_insts, src_inst);
        }
        buf_res->lock_mode = DMS_LOCK_SHARE;
    }
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

static int dms_reform_rebuild_lock_inner(drc_local_lock_res_t *lock_res, uint8 new_master, uint8 thread_index)
{
    int ret = DMS_SUCCESS;
    uint32 append_size = (uint32)sizeof(drc_local_lock_res_t);
    if (new_master == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_LOCAL);
        ret = dms_reform_proc_lock_rebuild(&lock_res->resid, lock_res->latch_stat.lock_mode, new_master);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock(MSG_REQ_LOCK_REBUILD, (void *)lock_res, append_size, new_master);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock_parallel(MSG_REQ_LOCK_REBUILD, (void *)lock_res, append_size, new_master,
            thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_REMOTE);
    }
    return ret;
}

int dms_reform_res_need_rebuild(char *res, unsigned char res_type, unsigned int *need_rebuild)
{
    uint8 master_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rebuild = &share_info->list_rebuild;

    if (share_info->full_clean) {
        *need_rebuild = CM_TRUE;
        return DMS_SUCCESS;
    }

    if (res_type == DRC_RES_PAGE_TYPE) {
        ret = drc_get_page_master_id(res, &master_id);
    } else {
        ret = drc_get_lock_master_id((dms_drid_t *)res, &master_id);
    }
    DMS_RETURN_IF_ERROR(ret);

    if (dms_reform_list_exist(list_rebuild, master_id)) {
        *need_rebuild = CM_TRUE;
    } else {
        *need_rebuild = CM_FALSE;
    }
    return DMS_SUCCESS;
}

static int dms_reform_rebuild_lock_by_bucket(drc_res_bucket_t *bucket, uint8 thread_index)
{
    bilist_node_t *node;
    drc_local_lock_res_t *lock_res;
    uint8 remaster_id;
    bool32 need_rebuild = CM_FALSE;
    int ret = DMS_SUCCESS;

    cm_spin_lock(&bucket->lock, NULL);
    node = cm_bilist_head(&bucket->bucket_list);
    for (uint32 i = 0; i < bucket->bucket_list.count; i++) {
        lock_res = (drc_local_lock_res_t *)DRC_RES_NODE_OF(drc_local_lock_res_t, node, node);
        ret = dms_reform_res_need_rebuild((char *)&lock_res->resid, DRC_RES_LOCK_TYPE, &need_rebuild);
        DMS_BREAK_IF_ERROR(ret);
        if (need_rebuild) {
            dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_RES);
            ret = drc_get_lock_remaster_id(&lock_res->resid, &remaster_id);
            if (ret != DMS_SUCCESS) {
                dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_RES);
                LOG_DEBUG_ERR("[lock rebuild][%s]rebuild_lock fail to get remaster id",
                    cm_display_lockid(&lock_res->resid));
                break;
            }
            drc_lock_local_resx(lock_res, NULL, NULL);
            LOG_DEBUG_INF("[lock rebuild][%s]local_lock_res lock_mode: %d",
                cm_display_lockid(&lock_res->resid), lock_res->latch_stat.lock_mode);
            ret = dms_reform_rebuild_lock_inner(lock_res, remaster_id, thread_index);
            drc_unlock_local_resx(lock_res);
            dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_RES);
            DMS_BREAK_IF_ERROR(ret);
        }
        node = BINODE_NEXT(node);
    }
    cm_spin_unlock(&bucket->lock);
    return ret;
}

int dms_reform_rebuild_lock(uint32 sess_id, uint8 thread_index, uint8 thread_num)
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
        ret = dms_reform_rebuild_lock_by_bucket(bucket, thread_index);
        DMS_RETURN_IF_ERROR(ret);
        bucket_index += step;
    }

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_REMOTE_REST);
    ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_REMOTE_REST);
    return ret;
}

int dms_reform_rebuild_tlock(void *handle, uint8 thread_index, uint8 thread_num)
{
    return g_dms.callback.dms_reform_rebuild_tlock_parallel(handle, thread_index, thread_num);
}

static int dms_tlock_rebuild_drc(dms_drid_t *resid, dms_tlock_info_t *lock_info, uint8 new_master, uint8 thread_index)
{
    int ret;
    uint32 append_size = (uint32)sizeof(dms_tlock_info_t);
    if (new_master == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_TLOCK_LOCAL);
        ret = dms_reform_proc_lock_rebuild(resid, lock_info->lock_mode, new_master);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_TLOCK_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_TLOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock(MSG_REQ_TLOCK_REBUILD, (void *)lock_info, append_size, new_master);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_TLOCK_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_TLOCK_REMOTE);
        ret = dms_reform_req_rebuild_lock_parallel(MSG_REQ_TLOCK_REBUILD, (void *)lock_info, append_size, new_master,
            thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_TLOCK_REMOTE);
    }
    return ret;
}

int dms_tlock_rebuild_drc_parallel(dms_context_t *dms_ctx, dms_tlock_info_t *lock_info, unsigned char thread_index)
{
    dms_reset_error();
    uint8 remaster_id;
    dms_drid_t *lock_id = (dms_drid_t *)&dms_ctx->resid;
    int ret = drc_get_lock_remaster_id(lock_id, &remaster_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DRC][%s]dms_tlock_rebuild_drc_parallel, fail to get remaster id", cm_display_lockid(lock_id));
        return ret;
    }
    

    LOG_DEBUG_INF("[DRC][%s]dms_tlock_rebuild_drc_parallel, remaster(%d)", cm_display_lockid(lock_id),
        remaster_id);

    return dms_tlock_rebuild_drc(lock_id, lock_info, remaster_id, thread_index);
}

void dms_reform_rebuild_buffer_init(uint8 thread_index)
{
    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            rebuild_info->rebuild_data[i] = NULL;
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel_thread = &parallel_info->parallel[thread_index];
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            parallel_thread->data[i] = NULL;
        }
    }
}

void dms_reform_rebuild_buffer_free(void *handle, uint8 thread_index)
{
    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            if (rebuild_info->rebuild_data[i] != NULL) {
                g_dms.callback.mem_free(handle, rebuild_info->rebuild_data[i]);
                rebuild_info->rebuild_data[i] = NULL;
            }
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel_thread = &parallel_info->parallel[thread_index];
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            if (parallel_thread->data[i] != NULL) {
                g_dms.callback.mem_free(handle, parallel_thread->data[i]);
                parallel_thread->data[i] = NULL;
            }
        }
    }
}

int dms_reform_rebuild_inner(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = DMS_SUCCESS;

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_PAGE);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_rebuild_buf_res(handle, sess_id, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_PAGE);
    DMS_RETURN_IF_ERROR(ret);

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_rebuild_lock(sess_id, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK);
    DMS_RETURN_IF_ERROR(ret);

#ifndef OPENGAUSS
    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_TABLE_LOCK);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_rebuild_tlock(handle, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_TABLE_LOCK);
    DMS_RETURN_IF_ERROR(ret);

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_ALOCK);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_rebuild_alock(handle, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_ALOCK);
    DMS_RETURN_IF_ERROR(ret);

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_XA);
    dms_reform_rebuild_buffer_init(thread_index);
    ret = dms_reform_rebuild_xa_res(handle, sess_id, thread_index, thread_num);
    dms_reform_rebuild_buffer_free(handle, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_XA);
    DMS_RETURN_IF_ERROR(ret);
#endif

    return DMS_SUCCESS;
}

int dms_reform_rebuild(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    cm_latch_x(&reform_ctx->res_ctrl_latch, CM_INVALID_INT32, NULL);
    ret = dms_reform_rebuild_inner(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    if (ret != DMS_SUCCESS) {
        cm_unlatch(&reform_ctx->res_ctrl_latch, NULL);
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    cm_unlatch(&reform_ctx->res_ctrl_latch, NULL);

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

int dms_reform_rebuild_xa_res(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = g_dms.callback.dms_reform_rebuild_xa_res(handle, thread_index, thread_num);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_XA_REMOTE_REST);
    ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_XA_REMOTE_REST);
    return ret;
}