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
 * dms_reform_proc.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc.c
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

static void dms_reform_set_next_step(uint8 step)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_proc_stat_end(reform_info->current_step);
    dms_reform_proc_stat_start(step);
    reform_info->current_step = step;
}

void dms_reform_next_step(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 step = (uint8)share_info->reform_step[reform_info->reform_step_index++];


    if (step == DMS_REFORM_STEP_SYNC_WAIT) {
        reform_info->last_step = reform_info->current_step;
        reform_info->next_step = (uint8)share_info->reform_step[reform_info->reform_step_index];
        reform_info->sync_step = CM_INVALID_ID8;
        reform_info->sync_send_success = CM_FALSE;
    }
    dms_reform_set_next_step(step);
}

static int dms_reform_db_prepare(void)
{
#ifdef OPENGAUSS
    return DMS_SUCCESS;
#else
    int ret = g_dms.callback.db_prepare(g_dms.reform_ctx.handle_proc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    if (share_info->inst_bitmap[INST_LIST_NEW_JOIN] != 0) {
        uint64 bitmap_saved = share_info->bitmap_stable;
        bitmap64_union(&bitmap_saved, share_info->inst_bitmap[INST_LIST_NEW_JOIN]);

        ret = g_dms.callback.save_list_stable(g_dms.reform_ctx.handle_proc, bitmap_saved,
            share_info->reformer_id, share_info->bitmap_in, DMS_IS_SHARE_REFORMER);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]list_stable fail to save in ctrl");
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED);
            return ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED;
        }
    }

    return DMS_SUCCESS;

#endif
}

static int dms_reform_prepare(void)
{
    dms_reform_proc_stat_start(DRPS_REFORM);
    dms_reform_proc_stat_start(DMS_REFORM_STEP_PREPARE);
    LOG_RUN_FUNC_ENTER;
    dms_scrlock_stop_server();
    int ret = dms_reform_db_prepare();
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_start(void)
{
    LOG_RUN_FUNC_ENTER;
    if (!DMS_FIRST_REFORM_FINISH) {
        g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_REFORM);
    }
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->true_start = CM_TRUE;
#ifdef OPENGAUSS
    share_info_t* share_info = DMS_SHARE_INFO;
    g_dms.callback.reform_start_notify(g_dms.reform_ctx.handle_proc, reform_info->dms_role, share_info->reform_type,
        share_info->bitmap_online);
#endif
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_reconnect_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    int ret = mfc_add_instance_batch(list_online->inst_id_list, list_online->inst_id_count, CM_FALSE);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    reform_info->bitmap_connect = share_info->bitmap_online;
    reform_info->bitmap_in = share_info->bitmap_in;
    return DMS_SUCCESS;
}

static int dms_reform_disconnect(void)
{
    LOG_RUN_FUNC_ENTER;
    // Add mes_channel_entry dynamically is not allowed in openGauss, so can not destroy mes_channel_entry here
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
#ifndef OPENGAUSS
    instance_list_t *list_disconnect = &share_info->list_disconnect;

    cm_spin_lock(&reform_info->mes_lock, NULL);
    mfc_del_instance_batch(list_disconnect->inst_id_list, list_disconnect->inst_id_count);
    bitmap64_minus(&reform_info->bitmap_mes, share_info->bitmap_disconnect);
    cm_spin_unlock(&reform_info->mes_lock);
#endif
    reform_info->bitmap_connect = share_info->bitmap_online;
    reform_info->bitmap_in = share_info->bitmap_in;

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;

    return DMS_SUCCESS;
}

static int dms_reform_reconnect(void)
{
    LOG_RUN_FUNC_ENTER;

    int ret = dms_reform_reconnect_inner();
    if (ret == DMS_SUCCESS) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
    } else {
        LOG_RUN_FUNC_FAIL;
    }

    return ret;
}

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

static int dms_reform_may_need_flush(drc_buf_res_t *buf_res, uint32 sess_id, uint8 dst_id, bool8 *is_edp)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    uint64 lsn;

    if (buf_res->type != DRC_RES_PAGE_TYPE) {
        return DMS_SUCCESS;
    }

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_NEED_FLUSH, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_may_need_flush SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_may_need_flush WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    // if dst version less than VER_2, the value of is_edp can not be trusted
    if (dms_get_node_proto_version(dst_id) < DMS_PROTO_VER_2) {
        *is_edp = CM_FALSE;
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_may_need_flush result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    return ret;
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

int dms_reform_clean_buf_res_by_part(bilist_t *part_list, uint32 sess_id)
{
    bilist_node_t *node = cm_bilist_head(part_list);
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
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list, reform_ctx->sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list, reform_ctx->sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        part_list = &ctx->global_xa_res.res_parts[part_id];
        dms_reform_clean_xa_res_by_part(part_list);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

static int dms_reform_drc_clean_full(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = NULL;

    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_LOCK_TYPE);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        drc_release_xa_by_part(part_list);
    }

    return DMS_SUCCESS;
}

static int dms_reform_drc_clean(void)
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

static void dms_reform_part_info_print_single(int inst_id, char *buffer)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[inst_id];
    char temp_desc[DMS_TEMP_DESC_LEN] = { 0 };
    errno_t err;

    if (inst_part->count == 0) {
        return;
    }

    err = sprintf_s(temp_desc, DMS_TEMP_DESC_LEN, " [%d:%d]", inst_id, (int32)inst_part->count);
    DMS_SECUREC_CHECK_SS(err);
    err = strcat_s(buffer, DMS_INFO_DESC_LEN, temp_desc);
    DMS_SECUREC_CHECK(err);
}

static void dms_reform_part_info_print(void)
{
    char buffer[DMS_INFO_DESC_LEN] = { 0 };

    for (int i = 0; i < DMS_MAX_INSTANCES; i++) {
        dms_reform_part_info_print_single(i, buffer);
    }

    LOG_RUN_INF("[DMS REFORM]instance part info: %s", buffer);
}

static void dms_reform_remaster_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_global_res_map_t *page_res = drc_get_global_res_map(DRC_RES_PAGE_TYPE);
    drc_global_res_map_t *lock_res = drc_get_global_res_map(DRC_RES_LOCK_TYPE);
    drc_global_res_map_t *xa_res = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);

    cm_latch_x(&page_res->res_latch, g_dms.reform_ctx.sess_proc, NULL);
    cm_latch_x(&lock_res->res_latch, g_dms.reform_ctx.sess_proc, NULL);
    cm_latch_x(&xa_res->res_latch, g_dms.reform_ctx.sess_proc, NULL);

    dms_reform_part_info_print();

    uint32 size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
    errno_t err = memcpy_s(part_mngr->inst_part_tbl, size, remaster_info->inst_part_tbl, size);
    DMS_SECUREC_CHECK(err);

    size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
    err = memcpy_s(part_mngr->part_map, size, remaster_info->part_map, size);
    DMS_SECUREC_CHECK(err);

    dms_reform_part_info_print();

    cm_unlatch(&lock_res->res_latch, NULL);
    cm_unlatch(&page_res->res_latch, NULL);
    cm_unlatch(&xa_res->res_latch, NULL);
}

static int dms_reform_remaster(void)
{
    LOG_RUN_FUNC_ENTER;
    dms_reform_remaster_inner();
    if(g_dms.scrlock_ctx.enable){
        reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
        share_info_t *share_info = DMS_SHARE_INFO;
        uint8 server_id;
        if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
            server_id = share_info->promote_id;
        }else {
            server_id = share_info->reformer_id;
        }
        reform_ctx->scrlock_reinit_ctx.scrlock_server_id = server_id;
        reform_ctx->scrlock_reinit_ctx.recovery_node_num = share_info->list_online.inst_id_count;
        dms_scrlock_reinit();
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

void dms_reform_migrate_collect_local_task(migrate_info_t *local_migrate_info)
{
    migrate_info_t *global_migrate_info = DMS_MIGRATE_INFO;
    migrate_task_t *migrate_task = NULL;

    local_migrate_info->migrate_task_num = 0;
    for (uint8 i = 0; i < global_migrate_info->migrate_task_num; i++) {
        migrate_task = &global_migrate_info->migrate_task[i];
        if (dms_dst_id_is_self(migrate_task->export_inst)) {
            local_migrate_info->migrate_task[local_migrate_info->migrate_task_num++] = *migrate_task;
        }
    }
}

int dms_reform_migrate_inner(migrate_task_t *migrate_task, void *handle, uint32 sess_id)
{
    bilist_t *part_list = NULL;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    int ret = DMS_SUCCESS;

    LOG_DEBUG_INF("[DMS REFORM]dms_reform_migrate_inner, part_id: %d, inst: %d -> inst: %d",
        migrate_task->part_id, migrate_task->export_inst, migrate_task->import_inst);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_PAGE_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    part_list = &ctx->global_buf_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_LOCK_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part_list = &ctx->global_lock_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part_list, DRC_RES_LOCK_TYPE);
    
    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_GLOBAL_XA_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part_list = &ctx->global_xa_res.res_parts[migrate_task->part_id];
    drc_release_xa_by_part(part_list);
    return DMS_SUCCESS;
}

static int dms_reform_migrate(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    migrate_info_t local_migrate_info = { 0 };
    migrate_task_t *migrate_task = NULL;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    dms_reform_migrate_collect_local_task(&local_migrate_info);
    for (uint8 i = 0; i < local_migrate_info.migrate_task_num; i++) {
        migrate_task = &local_migrate_info.migrate_task[i];
        ret = dms_reform_migrate_inner(migrate_task, reform_ctx->handle_proc, reform_ctx->sess_proc);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

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
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, CM_FALSE);
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

// for rebuild: used for discriminate rebuild and validate
int dms_reform_send_ctrl_info(dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info, uint8 master_id, uint8 thread_index)
{
    int ret;
    if (master_id == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCAL);
        ret = dms_reform_proc_page_rebuild(dms_ctx->resid, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCAL);
    } else if (thread_index == CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_REMOTE);
        ret = dms_reform_req_page_rebuild(dms_ctx, ctrl_info, master_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_REMOTE);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_REMOTE);
        ret = dms_reform_req_page_rebuild_parallel(dms_ctx, ctrl_info, master_id, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_REMOTE);
    }
    return ret;
}

static int dms_reform_rebuild_send_rest(uint32 sess_id, uint8 thread_index)
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

    return dms_reform_rebuild_send_rest(sess_id, thread_index);
}

void dms_validate_drc(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, unsigned long long lsn, unsigned char is_dirty)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_REFORM, CM_TRUE);

    int ret = drc_enter_buf_res(dms_ctx->resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS || buf_res == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return;
    }
    if (buf_res->claimed_owner != g_dms.inst_id) {
        drc_leave_buf_res(buf_res);
        return;
    }
    LOG_DEBUG_INF("[DRC][%s]dms_validate_drc check", cm_display_pageid(dms_ctx->resid));

    cm_panic_log(memcmp(buf_res->data, dms_ctx->resid, DMS_PAGEID_SIZE) == 0,
        "[DRC validate]pageid unmatch(DRC:%s, buf:%s)",
        cm_display_pageid(buf_res->data),
        cm_display_pageid(dms_ctx->resid));

    drc_request_info_t *req_info = &buf_res->converting.req_info;
    if (req_info->inst_id != CM_INVALID_ID8) {
        /*
         * If lock modes unmatch, then either cvt matches ctrl, or cvt satisfies first time read,
         * or curr node was just promoted to primary with local buf and converting info unmatched.
         * If lock modes match, then the ack message of cvt request must be lost,
         * no need to check connverting info.
         */
        if (ctrl->lock_mode != buf_res->lock_mode) {
            share_info_t *share_info = DMS_SHARE_INFO;
            bool ctrl_matches_cvt = req_info->req_mode == ctrl->lock_mode;
            bool first_time_req = req_info->req_mode == DMS_LOCK_SHARE &&
                ctrl->lock_mode == DMS_LOCK_EXCLUSIVE && buf_res->lock_mode == DMS_LOCK_NULL;
            /*
             * Old priamry S->X, claim msg lost, current node promoted and remastered,
             * therefore current new primary has DRC=S, cvt=X and local ctrl NULL.
             */
            bool new_primary = share_info->promote_id == g_dms.inst_id &&
                req_info->req_mode == DMS_LOCK_EXCLUSIVE &&
                ctrl->lock_mode == DMS_LOCK_NULL && buf_res->lock_mode == DMS_LOCK_SHARE;
            cm_panic_log(ctrl_matches_cvt || first_time_req || new_primary,
                "[DRC validate][%s]lock mode unmatch with converting info(DRC:%d, buf:%d, cvt:%d)",
                cm_display_pageid(dms_ctx->resid), buf_res->lock_mode,
                ctrl->lock_mode, req_info->req_mode);
        }
    } else {
        cm_panic_log(buf_res->lock_mode == ctrl->lock_mode,
            "[DRC validate][%s]lock mode unmatch(DRC:%d, buf:%d)",
            cm_display_pageid(dms_ctx->resid), buf_res->lock_mode, ctrl->lock_mode);
    }

    drc_leave_buf_res(buf_res);
}

static void drc_get_lock_remaster_id(dms_drid_t *lock_id, uint8 *master_id)
{
    uint16 part_id;

    part_id = (uint16)drc_resource_id_hash((uint8 *)lock_id, sizeof(dms_drid_t), DRC_MAX_PART_NUM);
    *master_id = DRC_PART_REMASTER_ID(part_id);
}

int dms_reform_proc_lock_rebuild(drc_local_lock_res_t *lock_res, uint8 src_inst)
{
    if (SECUREC_UNLIKELY(lock_res->latch_stat.lock_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DRC][lock rebuild] invalid lock_mode: %u", lock_res->latch_stat.lock_mode);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_LOCK_STATUS_FAIL);
        return ERRNO_DMS_DRC_LOCK_STATUS_FAIL;
    }

    if (lock_res->latch_stat.lock_mode == DMS_LOCK_NULL) {
        LOG_DEBUG_INF("[DRC][lock rebuild](%s) lock skip, is_owner(%d), lock_mode: %d",
            cm_display_lockid(&lock_res->resid), lock_res->is_owner, lock_res->latch_stat.lock_mode);
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DRC][lock rebuild](%s), is_owner(%d), lock_mode: %d",
        cm_display_lockid(&lock_res->resid), lock_res->is_owner, lock_res->latch_stat.lock_mode);

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, CM_FALSE);
    int ret = drc_enter_buf_res((char *)&lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }

    cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == lock_res->latch_stat.lock_mode,
        "lock mode not matched, drc: %d, lock_res: %d", buf_res->lock_mode, lock_res->latch_stat.lock_mode);

    if (lock_res->latch_stat.lock_mode == DMS_LOCK_EXCLUSIVE) {
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
    if (new_master == g_dms.inst_id) {
        return dms_reform_proc_lock_rebuild(lock_res, new_master);
    } else if (thread_index == CM_INVALID_ID8) {
        return dms_reform_req_rebuild_lock(lock_res, new_master);
    } else {
        return dms_reform_req_rebuild_lock_parallel(lock_res, new_master, thread_index);
    }
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
            drc_get_lock_remaster_id(&lock_res->resid, &remaster_id);
            drc_lock_local_resx(lock_res);
            ret = dms_reform_rebuild_lock_inner(lock_res, remaster_id, thread_index);
            drc_unlock_local_resx(lock_res);
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

    return dms_reform_rebuild_send_rest(sess_id, thread_index);
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

static int dms_reform_rebuild(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;

    dms_reform_rebuild_buffer_init(CM_INVALID_ID8);
    ret = dms_reform_rebuild_buf_res(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_rebuild_buffer_free(reform_ctx->handle_proc, CM_INVALID_ID8);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_rebuild_buffer_init(CM_INVALID_ID8);
    ret = dms_reform_rebuild_lock(reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_rebuild_buffer_free(reform_ctx->handle_proc, CM_INVALID_ID8);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    
    dms_reform_rebuild_buffer_init(CM_INVALID_ID8);
    ret = dms_reform_rebuild_xa_res(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_rebuild_buffer_free(reform_ctx->handle_proc, CM_INVALID_ID8);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_repair_with_copy_insts_inner(drc_buf_res_t *buf_res, uint32 sess_id, bool32 *exists_owner,
    uint64 insts)
{
    bool8 is_edp = CM_FALSE;

    *exists_owner = CM_FALSE;
    if (insts == 0) {
        return DMS_SUCCESS;
    }

    for (uint8 i = 0; i < CM_MAX_INSTANCES; ++i) {
        if (!bitmap64_exist(&insts, i)) {
            continue;
        }
        // confirm page exist or not and set need_flush for edp
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH);
        int ret = dms_reform_may_need_flush(buf_res, sess_id, i, &is_edp);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH);
        if (ret == ERRNO_DMS_DRC_INVALID) {
            bitmap64_clear(&buf_res->copy_insts, i);
            continue;
        }
        DMS_RETURN_IF_ERROR(ret);
        bitmap64_clear(&buf_res->copy_insts, i);
        buf_res->claimed_owner = i;
        *exists_owner = CM_TRUE;
        if (!is_edp && buf_res->type == DRC_RES_PAGE_TYPE) {
            // edp no need to set promote because it is in ckpt queue already, but edp_map may be incorrect
            buf_res->copy_promote = DMS_COPY_PROMOTE_NORMAL;
        }
        return DMS_SUCCESS;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_copy_insts(drc_buf_res_t *buf_res, uint32 sess_id, bool32 *exists_owner)
{
    uint64 edp_copyinsts = bitmap64_intersect(buf_res->copy_insts, buf_res->edp_map);
    int ret = dms_reform_repair_with_copy_insts_inner(buf_res, sess_id, exists_owner, edp_copyinsts);
    DMS_RETURN_IF_ERROR(ret);
    if (*exists_owner) {
        return DMS_SUCCESS;
    }
    return dms_reform_repair_with_copy_insts_inner(buf_res, sess_id, exists_owner, buf_res->copy_insts);
}

static int dms_reform_repair_with_last_edp(drc_buf_res_t *buf_res, void *handle)
{
    uint64 disk_lsn = 0;
    int ret = DMS_SUCCESS;

    ret = g_dms.callback.disk_lsn(handle, buf_res->data, &disk_lsn);
    DMS_RETURN_IF_ERROR(ret);

    if (disk_lsn >= buf_res->lsn) {
        buf_res->last_edp = CM_INVALID_ID8;
        buf_res->lsn = 0;
        buf_res->edp_map = 0;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_edp_map_inner(drc_buf_res_t *buf_res, uint8 inst_id, uint32 sess_id)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, inst_id, DMS_REQ_EDP_LSN, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_repair_with_edp_map_inner SEND error: %d, dst_id: %d", ret, inst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_repair_with_edp_map_inner WAIT timeout, dst_id: %d", inst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_repair_with_edp_map_inner result: %d, dst_id: %d", result, inst_id);
        return result;
    }

    if (ret != DMS_SUCCESS) {
        return ret;
    }

    drc_add_edp_map(buf_res, inst_id, lsn);
    return DMS_SUCCESS;
}

static int dms_reform_repair_with_edp_map(drc_buf_res_t *buf_res, void *handle, uint32 sess_id)
{
    int ret = DMS_SUCCESS;

    buf_res->lsn = 0;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (!bitmap64_exist(&buf_res->edp_map, i)) {
            continue;
        }
        ret = dms_reform_repair_with_edp_map_inner(buf_res, i, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return dms_reform_repair_with_last_edp(buf_res, handle);
}

static int dms_reform_repair_by_part_inner(drc_buf_res_t *buf_res, void *handle, uint32 sess_id)
{
    int ret;
    DRC_DISPLAY(buf_res, "repair");

    if (buf_res->claimed_owner != CM_INVALID_ID8) {
        // set need_flush flag for pages which has been set edp flag.Otherwise ckpt will skip the pages
        if (bitmap64_exist(&buf_res->edp_map, buf_res->claimed_owner)) {
            bool8 is_edp;
            dms_reform_proc_stat_start(DRPS_DRC_REPAIR_NEED_FLUSH);
            ret = dms_reform_may_need_flush(buf_res, sess_id, buf_res->claimed_owner, &is_edp);
            dms_reform_proc_stat_end(DRPS_DRC_REPAIR_NEED_FLUSH);
            return ret;
        }
        dms_reform_proc_stat_times(DRPS_DRC_REPAIR_NEED_NOT_FLUSH);
        return DMS_SUCCESS;
    }

    if (buf_res->copy_insts != 0) {
        bool32 exists_owner = CM_FALSE;
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_WITH_COPY);
        ret = dms_reform_repair_with_copy_insts(buf_res, sess_id, &exists_owner);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_WITH_COPY);
        if (ret != DMS_SUCCESS || exists_owner) {
            return ret;
        }
    }

    if (buf_res->last_edp != CM_INVALID_ID8) {
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_WITH_LAST_EDP);
        ret = dms_reform_repair_with_last_edp(buf_res, handle);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_WITH_LAST_EDP);
        return ret;
    }

    if (buf_res->edp_map != 0) {
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_WITH_EDP_MAP);
        ret = dms_reform_repair_with_edp_map(buf_res, handle, sess_id);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_WITH_EDP_MAP);
        return ret;
    }

    return DMS_SUCCESS;
}

int dms_reform_repair_by_part(bilist_t *part_list, void *handle, uint32 sess_id)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_repair_by_part_inner(buf_res, handle, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

static int dms_reform_repair_inner(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        // lock
        part_list = &ctx->global_lock_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_LOCK);
        ret = dms_reform_repair_by_part(part_list, reform_ctx->handle_proc, reform_ctx->sess_proc);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_LOCK);
        DMS_RETURN_IF_ERROR(ret);
        // page
        part_list = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_proc_stat_start(DRPS_DRC_REPAIR_PAGE);
        ret = dms_reform_repair_by_part(part_list, reform_ctx->handle_proc, reform_ctx->sess_proc);
        dms_reform_proc_stat_end(DRPS_DRC_REPAIR_PAGE);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_repair_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_recovery_analyse_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.recovery_analyse(g_dms.reform_ctx.handle_proc, (void *)&share_info->list_recovery,
        DMS_IS_SHARE_REFORMER);
}

static int dms_reform_recovery_analyse(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_analyse_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_flush_copy_by_part_inner(drc_buf_res_t *buf_res, void *handle, uint32 sess_id)
{
    int ret = DMS_SUCCESS;

#ifdef OPENGAUSS
    if (buf_res->copy_promote != DMS_COPY_PROMOTE_NONE) {
        ret = g_dms.callback.flush_copy(handle, buf_res->data);
    }
    buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
#else
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
            ret = g_dms.callback.flush_copy(handle, buf_res->data);
            dms_reform_proc_stat_end(DRPS_DRC_FLUSH_COPY_LOCAL);
        } else {
            dms_reform_proc_stat_start(DRPS_DRC_FLUSH_COPY_REMOTE);
            ret = dms_reform_flush_copy_page(buf_res, sess_id);
            dms_reform_proc_stat_end(DRPS_DRC_FLUSH_COPY_REMOTE);
        }
    }
    buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
    buf_res->recovery_skip = CM_FALSE;
#endif
    return ret;
}

int dms_reform_flush_copy_by_part(bilist_t *part_list, void *handle, uint32 sess_id)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_flush_copy_by_part_inner(buf_res, handle, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

static int dms_reform_flush_copy_inner(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_flush_copy_by_part(part_list, reform_ctx->handle_proc, reform_ctx->sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

static int dms_reform_flush_copy(void)
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

static int dms_reform_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.recovery(g_dms.reform_ctx.handle_proc, (void *)&share_info->list_recovery,
        share_info->reform_type, DMS_IS_SHARE_REFORMER);
}

static int dms_reform_dw_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.dw_recovery(g_dms.reform_ctx.handle_proc,
        (void *)&share_info->dw_recovery_info, DMS_IS_SHARE_REFORMER);
}

static int dms_reform_df_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    if (DMS_IS_SHARE_REFORMER) {
        return g_dms.callback.df_recovery(g_dms.reform_ctx.handle_proc,
		    share_info->bitmap_in, (void *)&share_info->list_recovery);
    }
    return DMS_SUCCESS;
}

static void dms_reform_recovery_set_flag_by_part_inner(drc_buf_res_t *buf_res)
{
    DRC_DISPLAY(buf_res, "rcy_clean");
    buf_res->in_recovery = CM_FALSE;
    buf_res->recovery_skip = CM_FALSE;
}

void dms_reform_recovery_set_flag_by_part(bilist_t *part_list)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        dms_reform_recovery_set_flag_by_part_inner(buf_res);
    }
}

static int dms_reform_switch_lock(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_cm_res_trans_lock(share_info->promote_id);

    // wait reform_info->reformer_id change to share_info->promote_id and DMS_ROLE change to correct role
    // otherwise, dms_reform_sync_wait may get error role
    if (reform_info->reformer_id != share_info->promote_id) {
        DMS_REFORM_SHORT_SLEEP;
        return DMS_SUCCESS;
    }

    if ((dms_dst_id_is_self(share_info->promote_id) && DMS_IS_REFORMER) ||
        (!dms_dst_id_is_self(share_info->promote_id) && DMS_IS_PARTNER)) {
        share_info->reformer_id = share_info->promote_id;
#ifdef OPENGAUSS
        g_dms.callback.reform_set_dms_role(g_dms.reform_ctx.handle_normal, share_info->promote_id);
#endif
        LOG_RUN_FUNC_SUCCESS;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    DMS_REFORM_SHORT_SLEEP;
    return DMS_SUCCESS;
}

static int dms_reform_switchover_demote(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->demote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.switchover_demote(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    dms_scrlock_stop_server();
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_switchover_promote(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->promote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.switchover_promote(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_switchover_promote_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;
    unsigned char orig_primary_id = share_info->demote_id;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->promote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.switchover_promote_opengauss(g_dms.reform_ctx.handle_proc, orig_primary_id);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_failover_promote_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->promote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.failover_promote_opengauss(g_dms.reform_ctx.handle_proc);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_recovery_inner_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 self_id = (uint8)g_dms.inst_id;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
        if (DMS_IS_SHARE_REFORMER) {
            return g_dms.callback.opengauss_recovery_primary(g_dms.reform_ctx.handle_proc, share_info->last_reformer);
        }

        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_standby(g_dms.reform_ctx.handle_proc, self_id);
        }
        return DMS_SUCCESS;
    }

    if (DMS_IS_SHARE_REFORMER) {
        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_primary(g_dms.reform_ctx.handle_proc, self_id);
        }
    } else {
        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_standby(g_dms.reform_ctx.handle_proc, self_id);
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_recovery_opengauss(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_inner_opengauss();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_drc_rcy_clean(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;

    LOG_RUN_FUNC_ENTER;
    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_recovery_set_flag_by_part(part_list);
        part_id = part_mngr->part_map[part_id].next;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_ctl_rcy_clean(void)
{
    reform_context_t* reform_ctx = DMS_REFORM_CONTEXT;

    LOG_RUN_FUNC_ENTER;
    g_dms.callback.dms_ctl_rcy_clean_parallel(reform_ctx->handle_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static bool32 dms_reform_wait_rollback(uint8 inst_id)
{
    uint8 deposit_id = drc_get_deposit_id(inst_id);
    // if current instance has deposit other instance txn, should wait rollback finish
    if (dms_dst_id_is_self(deposit_id) && inst_id != deposit_id) {
        return (bool32)g_dms.callback.tx_rollback_finish(g_dms.reform_ctx.handle_proc, inst_id);
    }
    return CM_TRUE;
}

static int dms_reform_txn_deposit(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    instance_list_t *list_withdraw = &share_info->list_withdraw;
    uint8 inst_id = CM_INVALID_ID8;

    for (uint8 i = 0; i < list_withdraw->inst_id_count; i++) {
        inst_id = list_withdraw->inst_id_list[i];
        if (!dms_reform_wait_rollback(inst_id)) {
            return DMS_SUCCESS;
        }

        dms_reform_delete_xa_rms(inst_id);
    }

    int ret = memcpy_s(ctx->deposit_map, DMS_MAX_INSTANCES, remaster_info->deposit_map, DMS_MAX_INSTANCES);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

int dms_reform_undo_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.undo_init(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_UNDO_INIT);
            return ERRNO_DMS_CALLBACK_RC_UNDO_INIT;
        }
    }
    return DMS_SUCCESS;
}

int dms_reform_tx_area_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_init(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT);
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT;
        }
    }
    return DMS_SUCCESS;
}

int dms_reform_tx_area_load(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_load(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD);
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD;
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_convert_to_readwrite(void)
{
#ifndef OPENGAUSS
    return g_dms.callback.convert_to_readwrite(g_dms.reform_ctx.handle_normal);
#else
    return DMS_SUCCESS;
#endif
}

static int dms_reform_rollback(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;

    LOG_RUN_FUNC_ENTER;
    if (share_info->reform_type == DMS_REFORM_TYPE_FOR_FAILOVER) {
        for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
            g_drc_res_ctx.deposit_map[inst_id] = share_info->reformer_id;
        }
    }

    if (DMS_IS_SHARE_PARTNER || list_rollback->inst_id_count == 0) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    int ret = dms_reform_undo_init(list_rollback);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_init(list_rollback);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_load(list_rollback);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_convert_to_readwrite();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

// set sync wait before done
static int dms_reform_success(void)
{
    LOG_RUN_FUNC_ENTER;
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static void dms_reform_proc_set_pause(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    CM_ASSERT(reform_info->thread_status == DMS_THREAD_STATUS_RUNNING);
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc pausing");
    reform_info->thread_status = DMS_THREAD_STATUS_PAUSING;
}

static void dms_reform_set_switchover_result(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    // if current reform is SWITCHOVER,should set switchover result for the new primary
    // clean switchover request in the original primary
    // if current reform is OTHERS, should set switchover result for the session which has request switchover
    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        LOG_RUN_INF("[DMS REFORM]dms_reform_set_switchover_result, reform_type: %u, promote_id: %d, current_id: %u",
            share_info->reform_type, share_info->promote_id, g_dms.inst_id);
        if (dms_dst_id_is_self(share_info->promote_id)) {
            cm_spin_lock(&switchover_info->lock, NULL);
            switchover_info->switch_start = CM_FALSE;
            cm_spin_unlock(&switchover_info->lock);
            g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, reform_info->err_code);
        }
        if (dms_dst_id_is_self(share_info->demote_id)) {
            // only clean switchover request in the original primary,
            // because the new primary may have receive new switchover request
            cm_spin_lock(&switchover_info->lock, NULL);
            switchover_info->switch_req = CM_FALSE;
            switchover_info->inst_id = CM_INVALID_ID8;
            switchover_info->sess_id = CM_INVALID_ID16;
            cm_spin_unlock(&switchover_info->lock);
        }
    } else {
        cm_spin_lock(&switchover_info->lock, NULL);
        if (switchover_info->switch_start) {
            if (!dms_reform_version_same(&switchover_info->reformer_version, &reform_info->reformer_version)) {
                switchover_info->switch_start = CM_FALSE;
                g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, ERRNO_DMS_REFORM_FAIL);
            }
        }
        cm_spin_unlock(&switchover_info->lock);
    }
}

static void dms_reform_end(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t share_info;

    dms_reform_set_switchover_result();
    // health check should pause before clear share info
    dms_reform_health_set_pause();
    dms_reform_proc_set_pause();

#ifdef OPENGAUSS
    dms_reform_handle_fail_in_special_scenario();
#endif
    int ret = memset_s(&share_info, sizeof(share_info_t), 0, sizeof(share_info_t));
    DMS_SECUREC_CHECK(ret);

    reform_info->file_unable = CM_FALSE;
    reform_info->reform_done = CM_TRUE;
    reform_info->reform_fail =  CM_FALSE;
    reform_ctx->last_reform_info = reform_ctx->reform_info;
    reform_ctx->last_share_info = reform_ctx->share_info;
    reform_ctx->share_info = share_info;
}

#ifndef OPENGAUSS
static void dms_reform_set_idle_behavior(void)
{
    g_dms.callback.set_inst_behavior(g_dms.reform_ctx.handle_proc, DMS_INST_BEHAVIOR_IN_IDLE);
}
#endif

static int dms_reform_done(void)
{
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    LOG_RUN_FUNC_ENTER;
    bool32 save_ctrl = CM_FALSE;
    if (DMS_IS_SHARE_REFORMER) {
        save_ctrl = CM_TRUE;
    }

#ifndef OPENGAUSS
    g_dms.callback.ckpt_unblock_rcy_local(g_dms.reform_ctx.handle_proc, share_info->bitmap_in);
#endif

    ret = g_dms.callback.save_list_stable(g_dms.reform_ctx.handle_proc, share_info->bitmap_online,
        share_info->reformer_id, share_info->bitmap_in, save_ctrl);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]list_stable fail to save in ctrl");
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED);
        return ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED;
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_done_check()
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_check_reform_done();
        // for ERRNO_DMS_REFORM_NOT_FINISHED, just return DMS_SUCCESS for enter this method again
        if (ret == ERRNO_DMS_REFORM_NOT_FINISHED) {
            return DMS_SUCCESS;
        } else if (ret != DMS_SUCCESS) {
            return ret;
        }
    }
#ifdef OPENGAUSS
    g_dms.callback.reform_done_notify(g_dms.reform_ctx.handle_proc);
#endif

    dms_reform_end();
    reform_info->last_fail = CM_FALSE;
    reform_info->first_reform_finish = CM_TRUE;
    if (!reform_info->rst_recover) { // maintain reeform after rst recover
        reform_info->first_reform_finish = CM_TRUE;
    }

#ifndef OPENGAUSS
    dms_reform_set_idle_behavior();
#endif
    LOG_RUN_FUNC_SUCCESS;
    return ret;
}

static int dms_reform_set_phase(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_FIRST_REFORM_FINISH) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info->reform_pause = CM_TRUE;
    CM_MFENCE;
    reform_info->reform_phase = (uint8)share_info->reform_phase[reform_info->reform_phase_index++];
    LOG_RUN_INF("[DMS REFORM]dms_reform_set_phase: %s", dms_reform_phase_desc(reform_info->reform_phase));
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_wait_db(void)
{
    if (DMS_FIRST_REFORM_FINISH) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (reform_info->reform_pause) {
        return DMS_SUCCESS;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_bcast_enable(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    LOG_RUN_FUNC_ENTER;
    reform_info->bitmap_in = share_info->bitmap_online;
    reform_info->file_unable = CM_FALSE;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_bcast_unable(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_FUNC_ENTER;
    cm_latch_x(&reform_info->file_latch, g_dms.reform_ctx.sess_proc, NULL);
    reform_info->file_unable = CM_TRUE;
    cm_unlatch(&reform_info->file_latch, NULL);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_update_scn(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.update_global_scn(g_dms.reform_ctx.handle_proc, reform_info->max_scn);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_wait_ckpt(void)
{
    if ((bool8)g_dms.callback.wait_ckpt(g_dms.reform_ctx.handle_proc)) {
        LOG_RUN_FUNC_SUCCESS;
        dms_reform_next_step();
    }
    return DMS_SUCCESS;
}

// if has not run step dms_reform_start, no need to set last fail
static void dms_reform_set_last_fail(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (reform_info->true_start) {
        reform_info->last_fail = CM_TRUE;
    }

#ifndef OPENGAUSS
    if (!DMS_FIRST_REFORM_FINISH) {
        LOG_RUN_ERR("[DMS REFORM]dms reform fail in first reform, abort");
        cm_exit(0);
    }
#endif
}

static int dms_reform_sync_step_send(void)
{
    dms_reform_req_sync_step_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_sync_step(&req);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_step SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_sync_step_wait(req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_sync_step WAIT timeout, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }

    if (ret == DMS_SUCCESS) {
        reform_info->sync_send_success = CM_TRUE;
    }

    return ret;
}

static void dms_reform_sync_fail_r(uint8 dst_id)
{
    dms_reform_req_sync_step_t req;
    dms_reform_init_req_sync_next_step(&req, dst_id);
    (void)mfc_send_data(&req.head); // try to notify partner set reform fail
}

static void dms_reform_remote_fail(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 inst_id = CM_INVALID_ID8;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        inst_id = list_online->inst_id_list[i];
        if (!dms_dst_id_is_self(inst_id)) {
            dms_reform_sync_fail_r(inst_id);
        }
    }
}

// reform fail cause by self
static int dms_reform_self_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    } else {
        (void)dms_reform_sync_step_send();
    }
    dms_reform_set_last_fail();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

// reform fail cause by notification from reformer
static int dms_reform_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    }
    dms_reform_set_last_fail();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_sync_next_step_r(uint8 dst_id)
{
    dms_reform_req_sync_step_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_sync_next_step(&req, dst_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_sync_next_step_r send error: %d, dst_id: %d", ret, dst_id);
            break;
        }

        ret = dms_reform_req_sync_next_step_wait(req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_sync_next_step_r WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }
    return ret;
}

static int dms_reform_sync_next_step(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            continue;
        }
        ret = dms_reform_sync_next_step_r(dst_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return DMS_SUCCESS;
}

static int dms_reform_sync_wait_reformer(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;
    instance_list_t *list_onlie = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    uint8 ret_flag = CM_FALSE;
    int ret = DMS_SUCCESS;
#ifndef OPENGAUSS
    uint64 scn = g_dms.callback.get_global_scn(g_dms.reform_ctx.handle_proc);
    reform_info->max_scn = MAX(reform_info->max_scn, scn);
#endif
    reformer_ctrl->instance_step[g_dms.inst_id] = reform_info->last_step;
    for (uint8 i = 0; i < list_onlie->inst_id_count; i++) {
        dst_id = list_onlie->inst_id_list[i];
        // can not wait here, return the function, sleep thread and check fail flag at the upper-layer function
        if (reformer_ctrl->instance_step[dst_id] != reform_info->last_step) {
            ret_flag = CM_TRUE;
        }
        if (reformer_ctrl->instance_fail[dst_id]) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait_reformer receive partner(%d) fail", dst_id);
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "receive fail reform partner");
            return ERRNO_DMS_REFORM_FAIL;
        }
    }

    if (ret_flag) {
        return DMS_SUCCESS;
    }

    ret = dms_reform_sync_next_step();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait reformer success");
    return DMS_SUCCESS;
}

static int dms_reform_sync_step_wait(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (reform_info->sync_step == reform_info->next_step) {
        dms_reform_next_step();
        LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait partner success");
    }
    return DMS_SUCCESS;
}

static int dms_reform_sync_wait_partner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    if (!reform_info->sync_send_success) {
        ret = dms_reform_sync_step_send();
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }

    return dms_reform_sync_step_wait();
}

static int dms_reform_sync_wait(void)
{
    int ret = DMS_SUCCESS;

    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_sync_wait_reformer();
    } else {
        ret = dms_reform_sync_wait_partner();
    }

    return ret;
}

static int dms_reform_page_access(void)
{
    LOG_RUN_FUNC_ENTER;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_buf_res.data_access = CM_TRUE;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_drc_access(void)
{
    LOG_RUN_FUNC_ENTER;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_lock_res.drc_access = CM_TRUE;
    ctx->global_buf_res.drc_access = CM_TRUE;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_dw_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_dw_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_df_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_df_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_drc_inaccess(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    if (!dms_reform_type_is(DMS_REFORM_TYPE_FOR_MAINTAIN)) {
        drc_buf_res_set_inaccess(&ctx->global_lock_res);

        if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL)) {
            drc_buf_res_set_inaccess(&ctx->global_xa_res);
        }
    }
    
    drc_buf_res_set_inaccess(&ctx->global_buf_res);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();

    return DMS_SUCCESS;
}

static int dms_reform_drc_validate()
{
    LOG_RUN_FUNC_ENTER;
#ifdef OPENGAUSS
    g_dms.callback.drc_validate(g_dms.reform_ctx.handle_proc);
#else
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    dms_reform_rebuild_buffer_init(CM_INVALID_ID8);
    (void)dms_reform_rebuild_buf_res(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_rebuild_buffer_free(reform_ctx->handle_proc, CM_INVALID_ID8);
#endif

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();

    return DMS_SUCCESS;
}

static bool32 dms_reform_check_partner_fail(void)
{
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;

    if (DMS_IS_SHARE_PARTNER) {
        return CM_FALSE;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (reformer_ctrl->instance_fail[i]) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

bool32 dms_reform_version_same(version_info_t *v1, version_info_t *v2)
{
    return (v1->inst_id == v2->inst_id) && (v1->start_time == v2->start_time);
}

static int dms_reform_startup_opengauss(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;

    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 self_id = (uint8)g_dms.inst_id;

    // for failover: startup thread will init in promote pharse
    if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
        if (DMS_IS_SHARE_REFORMER && dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS)) {
            LOG_DEBUG_INF("[DMS REFORM] init startup");
            ret = g_dms.callback.opengauss_startup(g_dms.reform_ctx.handle_proc);
        } else if (DMS_IS_SHARE_PARTNER) {
            LOG_DEBUG_INF("[DMS REFORM] init startup");
            ret = g_dms.callback.opengauss_startup(g_dms.reform_ctx.handle_proc);
        }
    }

    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

/*
 * Put X on instance lock to push GCV. Partner needs lock too, to prevent concurrent iusses
 * such as DRC rebuild and invalidate msg happens at the same time. The timed lock
 * waits 1s since we need preserve reform RTO. Usually it latches instantly.
 */
static int dms_reform_lock_instance(void)
{
    LOG_RUN_FUNC_ENTER;
    date_t begin_time = g_timer()->now;
    int ticks = 400; /* let each latch take ~0.1s, as each tick measures ~0.25ms on 72-core x86 */
    uint32 sess_pid = g_dms.reform_ctx.sess_proc;

    reform_info_t *reform_info = DMS_REFORM_INFO;
    LOG_DEBUG_INF("[DMS REFORM][GCV PUSH]dms_reform_lock_instance try lock, gcv:%d",
        DMS_GLOBAL_CLUSTER_VER);
    while (cm_latch_timed_x(&reform_info->instance_lock, sess_pid, ticks, NULL) == CM_FALSE) {
        if (g_timer()->now - begin_time >= DMS_REFORM_LOCK_INST_TIMEOUT) {
            LOG_RUN_ERR("[DMS REFORM][GCV PUSH]dms_reform_lock_instance timeout error, inst:%d exits now",
                g_dms.inst_id);
#ifdef _DEBUG
            cm_panic(0);
#else
            cm_exit(0);
#endif
        }
    }
    LOG_DEBUG_INF("[DMS REFORM][GCV PUSH]dms_reform_lock_instance lock success");

    /* push reform version here; if wrapped, reset to zero */
    if (DMS_GLOBAL_CLUSTER_VER == CM_INVALID_ID32) {
        g_dms.cluster_ver = 0;
    }
    g_dms.cluster_ver++;
    LOG_DEBUG_INF("[DMS REFORM][GCV PUSH]GCV++:%u, inst_id:%u",
            DMS_GLOBAL_CLUSTER_VER, g_dms.inst_id);

    cm_unlatch(&reform_info->instance_lock, NULL);

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_set_remove_point(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t inst_list;
    int ret = DMS_SUCCESS;

    if (!DMS_IS_SHARE_REFORMER) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    LOG_RUN_FUNC_ENTER;
    dms_reform_bitmap_to_list(&inst_list, share_info->bitmap_remove);
    for (uint32 i = 0; i < inst_list.inst_id_count; i++) {
        uint32 inst = (uint32)inst_list.inst_id_list[i];
        ret = g_dms.callback.set_remove_point(g_dms.reform_ctx.handle_proc, inst, &reform_info->curr_points[inst]);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_reset_user()
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    g_dms.callback.reset_user(g_dms.reform_ctx.handle_proc, share_info->bitmap_in);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

dms_reform_proc_t g_dms_reform_procs[DMS_REFORM_STEP_COUNT] = {
    [DMS_REFORM_STEP_DONE] = { "DONE", dms_reform_done, NULL },
    [DMS_REFORM_STEP_PREPARE] = { "PREPARE", dms_reform_prepare, NULL },
    [DMS_REFORM_STEP_START] = { "START", dms_reform_start, NULL },
    [DMS_REFORM_STEP_DISCONNECT] = { "DISCONN", dms_reform_disconnect, NULL },
    [DMS_REFORM_STEP_RECONNECT] = { "RECONN", dms_reform_reconnect, dms_reform_reconnect_parallel },
    [DMS_REFORM_STEP_DRC_CLEAN] = { "DRC_CLEAN", dms_reform_drc_clean, dms_reform_drc_clean_parallel },
    [DMS_REFORM_STEP_MIGRATE] = { "MIGRATE", dms_reform_migrate, dms_reform_migrate_parallel },
    [DMS_REFORM_STEP_REBUILD] = { "REBUILD", dms_reform_rebuild, dms_reform_rebuild_parallel },
    [DMS_REFORM_STEP_REMASTER] = { "REMASTER", dms_reform_remaster, NULL },
    [DMS_REFORM_STEP_REPAIR] = { "REPAIR", dms_reform_repair, dms_reform_repair_parallel },
    [DMS_REFORM_STEP_RECOVERY_ANALYSE] = { "RECOVERY_ANALYSE", dms_reform_recovery_analyse, NULL },
    [DMS_REFORM_STEP_SWITCH_LOCK] = { "SWITCH_LOCK", dms_reform_switch_lock, NULL },
    [DMS_REFORM_STEP_SWITCHOVER_DEMOTE] = { "DEMOTE", dms_reform_switchover_demote, NULL },
    [DMS_REFORM_STEP_SWITCHOVER_PROMOTE] = { "PROMOTE", dms_reform_switchover_promote, NULL },
    [DMS_REFORM_STEP_RECOVERY] = { "RECOVERY", dms_reform_recovery, NULL },
    [DMS_REFORM_STEP_RECOVERY_OPENGAUSS] = { "RECOVERY_OPENGAUSS", dms_reform_recovery_opengauss, NULL },
    [DMS_REFORM_STEP_DRC_RCY_CLEAN] = { "DRC_RCY_CLEAN", dms_reform_drc_rcy_clean, dms_reform_drc_rcy_clean_parallel },
    [DMS_REFORM_STEP_CTL_RCY_CLEAN] = { "DRC_CTL_CLEAN", dms_reform_ctl_rcy_clean, dms_reform_ctl_rcy_clean_parallel },
    [DMS_REFORM_STEP_TXN_DEPOSIT] = { "TXN_DEPOSIT", dms_reform_txn_deposit, NULL },
    [DMS_REFORM_STEP_ROLLBACK] = { "ROLLBACK", dms_reform_rollback, NULL },
    [DMS_REFORM_STEP_SUCCESS] = { "SUCCESS", dms_reform_success, NULL },
    [DMS_REFORM_STEP_SELF_FAIL] = { "SELF_FAIL", dms_reform_self_fail, NULL },
    [DMS_REFORM_STEP_REFORM_FAIL] = { "REFORM_FAIL", dms_reform_fail, NULL },
    [DMS_REFORM_STEP_SYNC_WAIT] = { "SYNC_WAIT", dms_reform_sync_wait, NULL },
    [DMS_REFORM_STEP_PAGE_ACCESS] = { "PAGE_ACCESS", dms_reform_page_access, NULL },
    [DMS_REFORM_STEP_DW_RECOVERY] = { "DW_RECOVERY", dms_reform_dw_recovery, NULL },
    [DMS_REFORM_STEP_DF_RECOVERY] = { "DF_RECOVERY", dms_reform_df_recovery, NULL },
    [DMS_REFORM_STEP_DRC_ACCESS] = { "DRC_ACCESS", dms_reform_drc_access, NULL },
    [DMS_REFORM_STEP_DRC_INACCESS] = { "DRC_INACCESS", dms_reform_drc_inaccess, NULL },
    [DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS] = { "S_PROMOTE", dms_reform_switchover_promote_opengauss, NULL },
    [DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS] = { "F_PROMOTE", dms_reform_failover_promote_opengauss, NULL },
    [DMS_REFORM_STEP_STARTUP_OPENGAUSS] = { "STARTUP", dms_reform_startup_opengauss, NULL },
    [DMS_REFORM_STEP_FLUSH_COPY] = { "FLUSH_COPY", dms_reform_flush_copy, dms_reform_flush_copy_parallel },
    [DMS_REFORM_STEP_DONE_CHECK] = { "DONE_CHECK", dms_reform_done_check, NULL },
    [DMS_REFORM_STEP_SET_PHASE] = { "SET_PHASE", dms_reform_set_phase, NULL },
    [DMS_REFORM_STEP_WAIT_DB] = { "WAIT_DB", dms_reform_wait_db, NULL },
    [DMS_REFORM_STEP_BCAST_ENABLE] = { "BCAST_ENABLE", dms_reform_bcast_enable, NULL },
    [DMS_REFORM_STEP_BCAST_UNABLE] = { "BCAST_UNABLE", dms_reform_bcast_unable, NULL },
    [DMS_REFORM_STEP_UPDATE_SCN] = { "UPDATE_SCN", dms_reform_update_scn, NULL },
    [DMS_REFORM_STEP_WAIT_CKPT] = { "WAIT_CKPT", dms_reform_wait_ckpt, NULL },
    [DMS_REFORM_STEP_DRC_VALIDATE] = { "DRC_VALIDATE", dms_reform_drc_validate, NULL },
    [DMS_REFORM_STEP_LOCK_INSTANCE] = { "LOCK_INSTANCE", dms_reform_lock_instance, NULL },
    [DMS_REFORM_STEP_SET_REMOVE_POINT] = { "SET_REMOVE_POINT", dms_reform_set_remove_point, NULL},
    [DMS_REFORM_STEP_RESET_USER] = { "RESET_USER", dms_reform_reset_user, NULL },
    [DMS_REFORM_STEP_COLLECT_XA_OWNER] = { "COLLECT_XA_OWNER", dms_reform_collect_xa_owner, NULL },
    [DMS_REFORM_STEP_MERGE_XA_OWNERS] = { "SYNC_XA_OWNER", dms_reform_merge_xa_owners, NULL },
    [DMS_REFORM_STEP_RECOVERY_XA] = { "RECOVERY_XA", dms_reform_recovery_xa, NULL },
    [DMS_REFORM_STEP_XA_DRC_ACCESS] = { "XA_DRC_ACCESS", dms_reform_xa_drc_access, NULL },
};

static void dms_reform_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    reform_info->proc_time = (uint64)g_timer()->now; // record time for check if dms_reform_proc is active
    if (reform_info->current_step >= DMS_REFORM_STEP_COUNT) {
        LOG_RUN_ERR("dms_reform_inner, error step: %d", reform_info->current_step);
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
    }

    dms_reform_proc_t reform_proc = g_dms_reform_procs[reform_info->current_step];
    if (reform_info->parallel_enable && reform_proc.proc_parallel != NULL) {
        ret = reform_proc.proc_parallel();
    } else {
        ret = reform_proc.proc();
    }

    if (reform_info->reform_done) {
        return;
    }

    if (reform_info->reform_fail) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_REFORM_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }

    if (ret != DMS_SUCCESS) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ret;
        return;
    }

    if (dms_reform_check_partner_fail()) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }
}

void dms_reform_proc_thread(thread_t *thread)
{
    cm_set_thread_name("reform_proc");
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
#ifdef OPENGAUSS
    // this thread will invoke startup method in opengauss
    // need_startup flag need set to be true
    g_dms.callback.dms_thread_init(CM_TRUE, (char **)&thread->reg_data);
#endif

    dms_reform_proc_stat_bind_proc();
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc thread started");
    while (!thread->closed) {
        if (reform_info->thread_status == DMS_THREAD_STATUS_RUNNING) {
            dms_reform_inner();
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            reform_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            cm_sem_wait(&reform_ctx->sem_proc);
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_proc paused");
            reform_info->thread_status = DMS_THREAD_STATUS_PAUSED;
            dms_reform_proc_stat_end(reform_info->current_step);
            dms_reform_proc_stat_end(DRPS_REFORM);
            dms_reform_proc_stat_collect_current();
            dms_reform_proc_stat_collect_total();
            dms_reform_proc_stat_log_current();
            continue;
        }
    }
}

char *dms_reform_get_step_desc(uint32 step)
{
    if (step >= DMS_REFORM_STEP_COUNT) {
        return "UNKNOWN STEP";
    } else {
        return g_dms_reform_procs[step].desc;
    }
}

void dms_reform_cache_curr_point(unsigned int node_id, void *curr_point)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    if (DMS_IS_SHARE_REFORMER) {
        if (bitmap64_exist(&share_info->bitmap_remove, (uint8)node_id)) {
            log_point_t *point = (log_point_t *)curr_point;
            reform_info->curr_points[node_id] = *point;
        }
    }
}

int dms_reform_rebuild_xa_res(void *handle, uint32 sess_id, uint8 thread_index, uint8 thread_num)
{
    int ret = g_dms.callback.dms_reform_rebuild_xa_res(handle, thread_index, thread_num);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return dms_reform_rebuild_send_rest(sess_id, thread_index);
}