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
 * dms_reform_flush_copy.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_flush_copy.c
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

#ifndef OPENGAUSS
static int dms_reform_set_edp_to_owner(drc_buf_res_t *buf_res, uint32 sess_id, bool8 *is_edp)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    uint64 lsn;
    uint8 dst_id = buf_res->last_edp;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_SET_EDP_TO_OWNER, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_set_edp_to_owner SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            dms_reform_proc_stat_times(DRPS_DRC_FLUSH_COPY_TIMEOUT);
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_set_edp_to_owner WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_set_edp_to_owner result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    return ret;
}

static int dms_reform_flush_copy_page(drc_buf_res_t *buf_res, uint32 sess_id)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint8 dst_id = buf_res->claimed_owner;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_FLUSH_COPY, sess_id);
        req.lsn = buf_res->group_lsn;
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_flush_copy_page SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            dms_reform_proc_stat_times(DRPS_DRC_FLUSH_COPY_TIMEOUT);
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_flush_copy_page WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_flush_copy_page result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    return ret;
}
#endif

#ifdef OPENGAUSS
static int dms_reform_flush_copy_by_drc(drc_buf_res_t *buf_res, uint8 thread_index, void *handle, uint32 sess_id)
{
    DRC_DISPLAY(buf_res, "flush_copy");
    int ret = DMS_SUCCESS;
    if (buf_res->copy_promote != DMS_COPY_PROMOTE_NONE) {
        ret = g_dms.callback.flush_copy(handle, buf_res->data);
    }
    buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
    return ret;
}
#else
static int dms_reform_flush_copy_by_drc(drc_buf_res_t *buf_res, uint8 thread_index, void *handle, uint32 sess_id)
{
    DRC_DISPLAY(buf_res, "flush_copy");
    int ret = DMS_SUCCESS;
    if (buf_res->claimed_owner == CM_INVALID_ID8 && buf_res->last_edp != CM_INVALID_ID8 && !buf_res->in_recovery) {
        bool8 is_edp = CM_FALSE;
        // no owner, has edp and no need to recover,
        // it shows that original owner does not modify the page before abort
        // we should change last edp to be owner, otherwise ckpt can not flush the pages
        if (dms_dst_id_is_self(buf_res->last_edp)) {
            dms_reform_proc_stat_start(DRPS_DRC_EDP_TO_OWNER_LOCAL);
            ret = g_dms.callback.edp_to_owner(handle, buf_res->data, &is_edp);
            dms_reform_proc_stat_end(DRPS_DRC_EDP_TO_OWNER_LOCAL);
        } else {
            dms_reform_proc_stat_start(DRPS_DRC_EDP_TO_OWNER_REMOTE);
            ret = dms_reform_set_edp_to_owner(buf_res, sess_id, &is_edp);
            dms_reform_proc_stat_end(DRPS_DRC_EDP_TO_OWNER_REMOTE);
        }
        DMS_RETURN_IF_ERROR(ret);
        if (is_edp) {
            buf_res->claimed_owner = buf_res->last_edp;
            buf_res->lock_mode = DMS_LOCK_EXCLUSIVE;
        }
        bitmap64_clear(&buf_res->edp_map, buf_res->last_edp);
        buf_res->last_edp = CM_INVALID_ID8;
    } else if (buf_res->copy_promote != DMS_COPY_PROMOTE_NONE && buf_res->recovery_skip) {
        if (dms_dst_id_is_self(buf_res->claimed_owner)) {
            dms_reform_proc_stat_start(DRPS_DRC_FLUSH_COPY_LOCAL);
            ret = g_dms.callback.flush_copy_check_lsn(handle, buf_res->data, buf_res->group_lsn);
            dms_reform_proc_stat_end(DRPS_DRC_FLUSH_COPY_LOCAL);
        } else {
            dms_reform_proc_stat_start(DRPS_DRC_FLUSH_COPY_REMOTE);
            ret = dms_reform_flush_copy_page(buf_res, sess_id);
            dms_reform_proc_stat_end(DRPS_DRC_FLUSH_COPY_REMOTE);
        }
        buf_res->group_lsn = 0;
    } else if (buf_res->claimed_owner != CM_INVALID_ID8 && buf_res->group_lsn != 0 && buf_res->recovery_skip) {
        dms_reform_proc_stat_start(DRPS_DRC_FLUSH_COPY_VALIDATE_LSN);
        ret = dms_reform_lsn_validate_buf_res(buf_res, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_FLUSH_COPY_VALIDATE_LSN);
        buf_res->group_lsn = 0;
    }
    buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
    buf_res->recovery_skip = CM_FALSE;
    return ret;
}
#endif

static int dms_reform_flush_copy_by_part_inner(uint16 part_id, uint8 thread_index)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[part_id];
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_buf_res_t *buf_res = NULL;
    void *handle = NULL;
    uint32 sess_id = 0;
    int ret = DMS_SUCCESS;

    if (thread_index == CM_INVALID_ID8) {
        handle = reform_ctx->handle_proc;
        sess_id = reform_ctx->sess_proc;
    } else {
        CM_ASSERT(thread_index < DMS_MAX_INSTANCES);
        handle = parallel_info->parallel[thread_index].handle;
        sess_id = parallel_info->parallel[thread_index].sess_id;
    }

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_flush_copy_by_drc(buf_res, thread_index, handle, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

int dms_reform_flush_copy_by_part(uint16 part_id, uint8 thread_index)
{
    dms_reform_req_group_init(thread_index);
    int ret = dms_reform_flush_copy_by_part_inner(part_id, thread_index);
    if (ret == DMS_SUCCESS) {
        ret = dms_reform_req_group_send_rest(thread_index);
    }
    dms_reform_req_group_free(thread_index);
    return ret;
}

static int dms_reform_flush_copy_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        ret = dms_reform_flush_copy_by_part(part_id, CM_INVALID_ID8);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

int dms_reform_flush_copy(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    ret = dms_reform_flush_copy_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}