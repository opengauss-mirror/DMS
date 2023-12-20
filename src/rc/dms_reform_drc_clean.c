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
 * dms_reform_drc_clean.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_clean.c
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

static void dms_reform_clean_buf_res_fault_inst_info_inner(drc_buf_res_t *buf_res)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (buf_res->last_edp != CM_INVALID_ID8 && 
        bitmap64_exist(&share_info->bitmap_clean, buf_res->last_edp)) {
        buf_res->last_edp = CM_INVALID_ID8;
        buf_res->lsn = 0;
    }

    bitmap64_minus(&buf_res->copy_insts, share_info->bitmap_clean);
    bitmap64_minus(&buf_res->edp_map, share_info->bitmap_clean);
    drc_release_convert_q(&buf_res->convert_q);
}

static int dms_reform_confirm_owner_inner(drc_buf_res_t *buf_res, uint32 sess_id, uint8 dst_id, uint8 *lock_mode,
    bool8 *is_edp, uint64 *lsn)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_CONFIRM_OWNER, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_owner_inner SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, lock_mode, is_edp, lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_confirm_owner_inner WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_owner_inner result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    return ret;
}

static int dms_reform_confirm_owner(drc_buf_res_t *buf_res, uint32 sess_id)
{
    uint8 lock_mode = 0;
    bool8 is_edp = 0;
    uint64 lsn = 0;
    uint8 dst_id = buf_res->claimed_owner;

    if (buf_res->lock_mode == DMS_LOCK_SHARE && buf_res->converting.req_info.req_mode == DMS_LOCK_SHARE) {
        init_drc_cvt_item(&buf_res->converting);
        return DMS_SUCCESS;
    }

    int ret = dms_reform_confirm_owner_inner(buf_res, sess_id, dst_id, &lock_mode, &is_edp, &lsn);
    DMS_RETURN_IF_ERROR(ret);

    if (lock_mode != DMS_LOCK_NULL) {
        buf_res->lock_mode = lock_mode;
    } else {
        buf_res->claimed_owner = CM_INVALID_ID8;
    }

    if (is_edp) {
        drc_add_edp_map(buf_res, dst_id, lsn);
    }
    init_drc_cvt_item(&buf_res->converting);
    return DMS_SUCCESS;
}

static int dms_reform_confirm_copy(drc_buf_res_t *buf_res, uint32 sess_id)
{
    uint8 lock_mode = 0;
    bool8 is_edp = 0;
    uint64 lsn = 0;
    int ret = DMS_SUCCESS;

    for (uint8 dst_id = 0; dst_id < DMS_MAX_INSTANCES; dst_id++) {
        if (!bitmap64_exist(&buf_res->copy_insts, dst_id) || dst_id == buf_res->converting.req_info.inst_id) {
            continue;
        }
        ret = dms_reform_confirm_owner_inner(buf_res, sess_id, dst_id, &lock_mode, &is_edp, &lsn);
        DMS_RETURN_IF_ERROR(ret);
        if (lock_mode == DMS_LOCK_NULL) {
            bitmap64_clear(&buf_res->copy_insts, dst_id);
        }
    }

    return DMS_SUCCESS;
}

static int dms_reform_confirm_converting(drc_buf_res_t *buf_res, uint32 sess_id)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint8 dst_id = buf_res->converting.req_info.inst_id;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_CONFIRM_CONVERTING, sess_id);
        req.sess_id = buf_res->converting.req_info.sess_id;
        req.ruid = buf_res->converting.req_info.ruid; /* ruid sent to discard response and free mes room */
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_converting SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_confirm_converting WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_converting result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (lock_mode != DMS_LOCK_NULL) {
        buf_res->claimed_owner = buf_res->converting.req_info.inst_id;
        buf_res->lock_mode = lock_mode;
    } else {
        buf_res->claimed_owner = CM_INVALID_ID8;
    }
    init_drc_cvt_item(&buf_res->converting);
    return DMS_SUCCESS;
}

static int dms_reform_clean_buf_res_fault_inst_info(drc_buf_res_t *buf_res, uint32 sess_id)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    DRC_DISPLAY(buf_res, "clean");
    dms_reform_clean_buf_res_fault_inst_info_inner(buf_res);
    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
            dms_reform_proc_stat_times(DRPS_DRC_CLEAN_NO_OWNER);
            return DMS_SUCCESS;
        } else if (bitmap64_exist(&share_info->bitmap_clean, buf_res->converting.req_info.inst_id)) {
            init_drc_cvt_item(&buf_res->converting);
            dms_reform_proc_stat_times(DRPS_DRC_CLEAN_NO_OWNER);
            return DMS_SUCCESS;
        } else {
            dms_reform_proc_stat_start(DRPS_DRC_CLEAN_CONFIRM_CVT);
            ret = dms_reform_confirm_converting(buf_res, sess_id);
            dms_reform_proc_stat_end(DRPS_DRC_CLEAN_CONFIRM_CVT);
            return ret;
        }
    }
    
    if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        if (bitmap64_exist(&share_info->bitmap_clean, buf_res->claimed_owner)) {
            buf_res->claimed_owner = CM_INVALID_ID8;
        }
        dms_reform_proc_stat_times(DRPS_DRC_CLEAN_NO_CVT);
        return DMS_SUCCESS;
    }

    // if converting request X and buf_res has copy_insts, should confirm copy_insts
    if (buf_res->lock_mode == DMS_LOCK_SHARE && buf_res->copy_insts != 0 &&
        buf_res->converting.req_info.req_mode == DMS_LOCK_EXCLUSIVE) {
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_CONFIRM_COPY);
        ret = dms_reform_confirm_copy(buf_res, sess_id);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_CONFIRM_COPY);
        DMS_RETURN_IF_ERROR(ret);
    }

    bool32 owner_fault = bitmap64_exist(&share_info->bitmap_clean, buf_res->claimed_owner);
    bool32 cvt_fault = bitmap64_exist(&share_info->bitmap_clean, buf_res->converting.req_info.inst_id);
    if (owner_fault && cvt_fault) {
        init_drc_cvt_item(&buf_res->converting);
        buf_res->claimed_owner = CM_INVALID_ID8;
        dms_reform_proc_stat_times(DRPS_DRC_CLEAN_OWNER_CVT_FAULT);
    } else if (!owner_fault && cvt_fault) {
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_CONFIRM_OWNER);
        ret = dms_reform_confirm_owner(buf_res, sess_id);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_CONFIRM_OWNER);
    } else if (owner_fault && !cvt_fault) {
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_CONFIRM_CVT);
        ret = dms_reform_confirm_converting(buf_res, sess_id);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_CONFIRM_CVT);
    }

    if (buf_res->claimed_owner != CM_INVALID_ID8 &&
        buf_res->lock_mode == DMS_LOCK_EXCLUSIVE) {
        buf_res->copy_insts = 0;
    }

    return ret;
}

int dms_reform_clean_buf_res_by_part(drc_part_list_t *part, uint32 sess_id)
{
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_clean_buf_res_fault_inst_info(buf_res, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }
    return DMS_SUCCESS;
}

static int dms_reform_drc_clean_fault_inst(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    drc_part_list_t *part = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part = &ctx->global_lock_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_LOCK);
        ret = dms_reform_clean_buf_res_by_part(part, reform_ctx->sess_proc);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_LOCK);
        DMS_RETURN_IF_ERROR(ret);
        part = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_PAGE);
        ret = dms_reform_clean_buf_res_by_part(part, reform_ctx->sess_proc);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_PAGE);
        DMS_RETURN_IF_ERROR(ret);
        part = &ctx->global_xa_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_XA);
        dms_reform_clean_xa_res_by_part(part);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_XA);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

static int dms_reform_drc_clean_full(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = NULL;

    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part = &ctx->global_lock_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_LOCK);
        drc_release_buf_res_by_part(part, DRC_RES_LOCK_TYPE);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_LOCK);
        part = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_PAGE);
        drc_release_buf_res_by_part(part, DRC_RES_PAGE_TYPE);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_PAGE);
        part = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_CLEAN_XA);
        drc_release_xa_by_part(part);
        dms_reform_proc_stat_end(DRPS_DRC_CLEAN_XA);
    }

    return DMS_SUCCESS;
}

int dms_reform_drc_clean(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (share_info->full_clean) {
        ret = dms_reform_drc_clean_full();
    } else {
        ret = dms_reform_drc_clean_fault_inst();
    }

    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}
