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
#include "drc_page.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_alock.h"
#include "cm_num.h"

void dms_rebuild_assist_list_init(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint32 size = sizeof(drc_part_list_t) * DRC_MAX_PART_NUM;
    (void)memset_s((void *)reform_info->normal_copy_lists, size, 0, size);
}

void dms_reform_rebuild_add_to_flush_copy(drc_buf_res_t *buf_res)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_part_list_t *part_list = &reform_info->normal_copy_lists[buf_res->part_id];
    cm_spin_lock(&part_list->lock, NULL);
    cm_bilist_add_head(&buf_res->rebuild_node, &part_list->list);
    cm_spin_unlock(&part_list->lock);
}

void dms_reform_rebuild_del_from_flush_copy(drc_buf_res_t *buf_res)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_part_list_t *part_list = &reform_info->normal_copy_lists[buf_res->part_id];
    cm_spin_lock(&part_list->lock, NULL);
    cm_bilist_del(&buf_res->rebuild_node, &part_list->list);
    cm_spin_unlock(&part_list->lock);
}

bool8 dms_reform_rebuild_set_type_inner(drc_buf_res_t *buf_res, reform_assist_list_type_e type, bool8 recover_analyse)
{
    CM_ASSERT(buf_res->rebuild_type < REFORM_ASSIST_LIST_COUNT);
    CM_ASSERT(type < REFORM_ASSIST_LIST_COUNT);
    if (buf_res->rebuild_type >= type) {
        return CM_FALSE;
    }
    if (recover_analyse) {
        buf_res->rebuild_type = (uint8)type;
        return CM_TRUE;
    }

    // if there is no DMS_REFORM_STEP_RECOVERY_ANALYSE next, should add normal copy to flush_copy_list here
    // such as DMS_REFORM_TYPE_FOR_NORMAL_STANDBY
    if (buf_res->rebuild_type == REFORM_ASSIST_LIST_NORMAL_COPY) {
        dms_reform_rebuild_del_from_flush_copy(buf_res);
    }
    buf_res->rebuild_type = (uint8)type;
    if (buf_res->rebuild_type == REFORM_ASSIST_LIST_NORMAL_COPY) {
        dms_reform_rebuild_add_to_flush_copy(buf_res);
    }

    return CM_TRUE;
}

bool8 dms_reform_rebuild_set_type(drc_buf_res_t *buf_res, reform_assist_list_type_e type)
{
#ifdef OPENGAUSS
    return dms_reform_rebuild_set_type_inner(buf_res, type, CM_FALSE);
#else
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_STANDBY)) {
        return dms_reform_rebuild_set_type_inner(buf_res, type, CM_FALSE);
    } else {
        return dms_reform_rebuild_set_type_inner(buf_res, type, CM_TRUE);
    }
#endif
}

void dms_reform_page_rebuild_null(drc_buf_res_t *buf_res, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    CM_ASSERT(ctrl_info->ctrl.is_edp);
    drc_add_edp_map(buf_res, inst_id, ctrl_info->lsn);
}

void dms_reform_page_set_owner(drc_buf_res_t *buf_res, bool8 is_owner, uint8 inst_id)
{
    if (!is_owner) {
        bitmap64_set(&buf_res->copy_insts, inst_id);
    } else if (buf_res->claimed_owner == CM_INVALID_ID8) {
        buf_res->claimed_owner = inst_id;
    } else {
        bitmap64_set(&buf_res->copy_insts, buf_res->claimed_owner);
        buf_res->claimed_owner = inst_id;
    }
    bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner); // for msg retry
}

void dms_reform_page_set_owner_lsn(drc_buf_res_t *buf_res, uint64 lsn)
{
    // 1. buf_res->owner_lsn == 0, it is the most common situation
    if (buf_res->owner_lsn == 0) {
        buf_res->owner_lsn = lsn;
        return;
    }

    // 2. lsn == CM_MAX_UINT64, we can not get the real lsn of the page
    //  for example 1: rebuild page occurs between setting distributed locks and loading pages from disk
    //  for example 2: rebuild page after page format
    // owner_lsn is not 0, do not modify it
    if (lsn == CM_MAX_UINT64) {
        return;
    }

    // 3. the page in scenario 2 has been rebuilt
    // and there is page that we can get real lsn in another instance
    // modify owner_lsn use the real lsn
    if (buf_res->owner_lsn == CM_MAX_UINT64) {
        buf_res->owner_lsn = lsn;
        return;
    }

    // 4. owner_lsn is the real lsn and current lsn is the real lsn too, check them
    cm_panic_log(buf_res->owner_lsn == lsn, "rebuild_lsn:%llu is not equal lsn:%llu", buf_res->owner_lsn, lsn);
}

void dms_reform_page_rebuild_s(drc_buf_res_t *buf_res, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    uint64 lsn = ctrl_info->lsn;
    bool8 is_owner = CM_FALSE;

    cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == DMS_LOCK_SHARE,
        "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(buf_res->data), buf_res->lock_mode);

    if (ctrl_info->ctrl.is_edp) {
        is_owner = dms_reform_rebuild_set_type(buf_res, REFORM_ASSIST_LIST_EDP_COPY);
        drc_add_edp_map(buf_res, inst_id, lsn);
    } else if (ctrl_info->is_dirty) {
        is_owner = dms_reform_rebuild_set_type(buf_res, REFORM_ASSIST_LIST_OWNER);
    } else {
        is_owner = dms_reform_rebuild_set_type(buf_res, REFORM_ASSIST_LIST_NORMAL_COPY);
    }

    buf_res->lock_mode = DMS_LOCK_SHARE;
    dms_reform_page_set_owner(buf_res, is_owner, inst_id);
    dms_reform_page_set_owner_lsn(buf_res, lsn);
}

void dms_reform_page_rebuild_x(drc_buf_res_t *buf_res, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL ||
        (buf_res->lock_mode == DMS_LOCK_EXCLUSIVE && buf_res->claimed_owner == inst_id),
        "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(buf_res->data), buf_res->lock_mode);

    if (ctrl_info->is_dirty) {
        (void)dms_reform_rebuild_set_type(buf_res, REFORM_ASSIST_LIST_OWNER);
    } else {
        (void)dms_reform_rebuild_set_type(buf_res, REFORM_ASSIST_LIST_NORMAL_COPY);
    }

    buf_res->claimed_owner = inst_id;
    buf_res->lock_mode = DMS_LOCK_EXCLUSIVE;
    buf_res->owner_lsn = ctrl_info->lsn;
}

int dms_reform_proc_page_rebuild(char *resid, dms_ctrl_info_t *ctrl_info, uint8 inst_id)
{
    dms_buf_ctrl_t *ctrl = &ctrl_info->ctrl;
    uint64 lsn = ctrl_info->lsn;
    bool8 is_dirty = ctrl_info->is_dirty;

    if (SECUREC_UNLIKELY(ctrl->lock_mode >= DMS_LOCK_MODE_MAX || ctrl->is_edp > 1)) {
        LOG_DEBUG_ERR("[DRC rebuild] invalid request message, is_edp=%u", (uint32)ctrl->is_edp);
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "ctrl_info");
        return ERRNO_DMS_PARAM_INVALID;
    }

    LOG_DEBUG_INF("[DRC rebuild][%s]remote_dirty: %d, lock_mode: %d, is_edp: %d, inst_id: %d, lsn: %llu, is_dirty: %d",
        cm_display_pageid(resid), ctrl->edp_map > 0, ctrl->lock_mode, ctrl->is_edp, inst_id, lsn, is_dirty);

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
    switch (ctrl->lock_mode) {
        case DMS_LOCK_NULL:
            dms_reform_page_rebuild_null(buf_res, ctrl_info, inst_id);
            break;

        case DMS_LOCK_SHARE:
            dms_reform_page_rebuild_s(buf_res, ctrl_info, inst_id);
            break;

        case DMS_LOCK_EXCLUSIVE:
            dms_reform_page_rebuild_x(buf_res, ctrl_info, inst_id);
            break;

        default:
            CM_ASSERT(CM_FALSE);
            break;
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

int dms_reform_lock_res_need_rebuild(drc_local_lock_res_t *lock_res, unsigned int *need_rebuild)
{
    uint8 master_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rebuild = &share_info->list_rebuild;

    if (lock_res->latch_stat.lock_mode == DMS_LOCK_NULL) {
        *need_rebuild = CM_FALSE;
        return DMS_SUCCESS;
    }

    if (share_info->full_clean) {
        *need_rebuild = CM_TRUE;
        return DMS_SUCCESS;
    }

    ret = drc_get_lock_master_id((dms_drid_t *)(&lock_res->resid), &master_id);
    DMS_RETURN_IF_ERROR(ret);

    if (dms_reform_list_exist(list_rebuild, master_id)) {
        *need_rebuild = CM_TRUE;
    } else {
        *need_rebuild = CM_FALSE;
    }
    return DMS_SUCCESS;
}

static inline drc_local_lock_res_t *pool_get_local_lock_by_id(drc_res_pool_t *res_pool, uint64 drc_id)
{
    uint64 addr_id = drc_id / res_pool->extend_step;
    uint64 offset = drc_id - addr_id * (uint64)(res_pool->extend_step);
    return (drc_local_lock_res_t *)(res_pool->addr[addr_id] + offset * sizeof(drc_local_lock_res_t));
}

static int dms_reform_rebuild_drc_by_local_lock(drc_local_lock_res_t *lock_res, uint8 thread_index)
{
    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_RES);
    uint8 remaster_id;
    int ret = drc_get_lock_remaster_id(&lock_res->resid, &remaster_id);
    if (ret != DMS_SUCCESS) {
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_RES);
        LOG_DEBUG_ERR("[lock rebuild][%s]rebuild_lock fail to get remaster id",
            cm_display_lockid(&lock_res->resid));
        return ret;
    }
    LOG_DEBUG_INF("[lock rebuild][%s]local_lock_res lock_mode: %d",
        cm_display_lockid(&lock_res->resid), lock_res->latch_stat.lock_mode);
    ret = dms_reform_rebuild_lock_inner(lock_res, remaster_id, thread_index);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_RES);
    return ret;
}

int dms_reform_rebuild_lock(uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t *res_pool = &ctx->local_lock_res.res_pool;
    uint64 pool_begin = 0;
    uint64 pool_end = res_pool->item_num;

    // if parallel
    if (thread_index != CM_INVALID_ID8) {
        uint32 pool_task_num = (res_pool->item_num + thread_num - 1) / thread_num; // round up
        pool_begin = thread_index * pool_task_num;
        pool_end = MIN(pool_begin + pool_task_num, res_pool->item_num);
    }

    drc_local_lock_res_t *lock_res;
    bool32 need_rebuild = CM_FALSE;

    for (uint64 i = pool_begin; i < pool_end; ++i) {
        lock_res = pool_get_local_lock_by_id(res_pool, i);
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_LOCAL_RES);
        cm_spin_lock(&lock_res->modify_mode_lock, NULL);
        lock_res->is_reform_visit = CM_TRUE;
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCK_LOCAL_RES);
        if (dms_reform_lock_res_need_rebuild(lock_res, &need_rebuild) != CM_SUCCESS) {
            cm_spin_unlock(&lock_res->modify_mode_lock);
            break;
        }
        if (need_rebuild == CM_FALSE) {
            cm_spin_unlock(&lock_res->modify_mode_lock);
            continue;
        }
        if (dms_reform_rebuild_drc_by_local_lock(lock_res, thread_index) != CM_SUCCESS) {
            cm_spin_unlock(&lock_res->modify_mode_lock);
            break;
        }
        cm_spin_unlock(&lock_res->modify_mode_lock);
    }

    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCK_REMOTE_REST);
    int ret = dms_reform_rebuild_send_rest(sess_id, thread_index);
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
        LOG_DEBUG_ERR("[DRC][%s]dms_tlock_rebuild_drc_parallel, fail to get remaster id", cm_display_lockid(lock_id));
        return ret;
    }
    LOG_DEBUG_INF("[DRC][%s]dms_tlock_rebuild_drc_parallel, remaster(%d)", cm_display_lockid(lock_id), remaster_id);

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
    dms_reform_proc_stat_start(DRPS_DRC_REBUILD_WAIT_LATCH);
    cm_latch_x(&reform_ctx->res_ctrl_latch, CM_INVALID_INT32, NULL);
    dms_reform_proc_stat_end(DRPS_DRC_REBUILD_WAIT_LATCH);
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