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
#include "dms_errno.h"
#include "drc_page.h"
#include "dms_reform_judge.h"
#include "dcs_page.h"
#include "dms_reform_health.h"
#include "cm_timer.h"

void dms_reform_display_buf(drc_buf_res_t *buf_res, const char *desc)
{
    LOG_DEBUG_INF("[DMS REFORM PROC][%s]%s, claim_owner: %d, copy_insts: %llu, lock_mode: %d, last_edp: %d, "
        "edp_map: %llu, part_id: %d, in_recovery: %d", cm_display_resid(buf_res->data, buf_res->type),
        desc, buf_res->claimed_owner, buf_res->copy_insts, buf_res->lock_mode, buf_res->last_edp,
        buf_res->edp_map, buf_res->part_id, buf_res->in_recovery);
}

static void dms_reform_next_step(void)
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

    reform_info->current_step = step;
}

static int dms_reform_prepare(void)
{
    LOG_RUN_FUNC_ENTER;
#ifdef OPENGAUSS
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t* share_info = DMS_SHARE_INFO;
    g_dms.callback.reform_start_notify(g_dms.reform_ctx.handle_proc, reform_info->dms_role, share_info->reform_type);
#endif
    dms_scrlock_stop_server();
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
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_reconnect_channel(uint8 inst_id, uint32 index)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    mes_message_head_t head;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        dms_reform_init_channel_check(&head, inst_id, index, (uint16)reform_ctx->sess_proc);
        ret = mfc_send_data(&head);
        if (ret != DMS_SUCCESS) {
            DMS_REFORM_SHORT_SLEEP;
            continue;
        }
        LOG_DEBUG_INF("[DMS_REFORM]channel_check SEND, src_inst: %d, src_channel: %u", inst_id, index);

        ret = dms_reform_channel_check_wait((uint16)reform_ctx->sess_proc);
        if (ret != DMS_SUCCESS) {
            DMS_REFORM_SHORT_SLEEP;
            continue;
        }

        LOG_DEBUG_INF("[DMS_REFORM]channel_check SUCCESS, src_inst: %d, src_channel: %u", inst_id, index);
        break;
    }

    return DMS_SUCCESS;
}

static int dms_reform_reconnect_node(uint8 inst_id)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;

    if (dms_dst_id_is_self(inst_id)) {
        return DMS_SUCCESS;
    }

    for (uint32 i = 0; i < reform_ctx->channel_cnt; i++) {
        ret = dms_reform_reconnect_channel(inst_id, i);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    return DMS_SUCCESS;
}

/*
  mes_connect_batch create mes_channel_entry. but recv_pipe&send_pipe may not connect.
  There two pipes in every channel, such as:
  channel in A: send_pipe -> channel in B: recv_pipe.
  channel in A: recv_pipe <- channel in B: send_pipe.
  Normally, all pipes is active.
  But if B is abort and restart, the send_pipe of channel in A is still active until send message failed.
  So we should send message to check whether send_pipe can work normally.
  If send_pipe is broken, the pipe will be close after send message fail, then mes_channel_entry will reconnect.
  Also, there may be channels between two nodes, we should check all channels.
  Only send message to check channel and receive successfully, can we think the channel work normally
*/
static int dms_reform_reconnect_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        ret = dms_reform_reconnect_node(list_online->inst_id_list[i]);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

#ifdef OPENGAUSS
    reform_info->bitmap_connect = share_info->bitmap_online;
#else
    reform_info->bitmap_connect = share_info->bitmap_in;
#endif
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
    mes_disconnect_batch(list_disconnect->inst_id_list, list_disconnect->inst_id_count);
    bitmap64_minus(&reform_info->bitmap_mes, share_info->bitmap_disconnect);
    cm_spin_unlock(&reform_info->mes_lock);
#endif
    reform_info->bitmap_connect = share_info->bitmap_online;

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

    if (bitmap64_exist(&share_info->bitmap_clean, buf_res->last_edp)) {
        buf_res->last_edp = CM_INVALID_ID8;
        buf_res->lsn = 0;
    }

    bitmap64_minus(&buf_res->copy_insts, share_info->bitmap_clean);
    bitmap64_minus(&buf_res->edp_map, share_info->bitmap_clean);
    drc_release_convert_q(&buf_res->convert_q);
}

static int dms_reform_confirm_owner(drc_buf_res_t *buf_res)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint32 ver   = buf_res->ver;
    uint8 dst_id = buf_res->claimed_owner;

    if (buf_res->lock_mode == DMS_LOCK_SHARE && buf_res->converting.req_info.req_mode == DMS_LOCK_SHARE) {
        init_drc_cvt_item(&buf_res->converting);
        return DMS_SUCCESS;
    }

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_CONFIRM_OWNER);
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_owner SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, &ver);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_confirm_owner WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_owner result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (lock_mode != DMS_LOCK_NULL) {
        buf_res->lock_mode = lock_mode;
    } else {
        buf_res->claimed_owner = CM_INVALID_ID8;
    }

    if (is_edp) {
        drc_add_edp_map(buf_res, buf_res->claimed_owner, lsn);
    }
    init_drc_cvt_item(&buf_res->converting);
    return DMS_SUCCESS;
}

static int dms_reform_confirm_converting(drc_buf_res_t *buf_res)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint32 ver;
    uint8 dst_id = buf_res->converting.req_info.inst_id;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_CONFIRM_CONVERTING);
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_confirm_converting SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, &ver);
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
        buf_res->ver = ver;
    } else {
        buf_res->claimed_owner = CM_INVALID_ID8;
    }
    init_drc_cvt_item(&buf_res->converting);
    return DMS_SUCCESS;
}

#ifndef OPENGAUSS
static int dms_reform_flush_copy_page(drc_buf_res_t *buf_res)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint32 ver = buf_res->ver;
    uint8 dst_id = buf_res->claimed_owner;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_FLUSH_COPY);
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_flush_copy_page SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, &ver);
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

static int dms_reform_clean_buf_res_fault_inst_info(drc_buf_res_t *buf_res)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    dms_reform_display_buf(buf_res, "clean");
    dms_reform_clean_buf_res_fault_inst_info_inner(buf_res);
    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        return DMS_SUCCESS;
    } else if (buf_res->converting.req_info.inst_id == CM_INVALID_ID8) {
        if (bitmap64_exist(&share_info->bitmap_clean, buf_res->claimed_owner)) {
            buf_res->claimed_owner = CM_INVALID_ID8;
        }
        return DMS_SUCCESS;
    }

    bool32 owner_fault = bitmap64_exist(&share_info->bitmap_clean, buf_res->claimed_owner);
    bool32 cvt_fault = bitmap64_exist(&share_info->bitmap_clean, buf_res->converting.req_info.inst_id);
    if (owner_fault && cvt_fault) {
        init_drc_cvt_item(&buf_res->converting);
        buf_res->claimed_owner = CM_INVALID_ID8;
    } else if (!owner_fault && cvt_fault) {
        ret = dms_reform_confirm_owner(buf_res);
    } else if (owner_fault && !cvt_fault) {
        ret = dms_reform_confirm_converting(buf_res);
    }

    return ret;
}

static int dms_reform_clean_buf_res_by_part(bilist_t *part_list)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_clean_buf_res_fault_inst_info(buf_res);
        DMS_RETURN_IF_ERROR(ret);
    }
    return DMS_SUCCESS;
}

static int dms_reform_drc_clean_fault_inst(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list);
        DMS_RETURN_IF_ERROR(ret);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }

    return DMS_SUCCESS;
}

static int dms_reform_drc_clean_full(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_LOCK_TYPE);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE);
        part_id = part_mngr->part_map[part_id].next;
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
    drc_global_res_map_t *page_res = DRC_GLOBAL_RES_MAP(DRC_RES_PAGE_TYPE);
    drc_global_res_map_t *lock_res = DRC_GLOBAL_RES_MAP(DRC_RES_LOCK_TYPE);

    cm_latch_x(&page_res->res_latch, g_dms.reform_ctx.sess_proc, NULL);
    cm_latch_x(&lock_res->res_latch, g_dms.reform_ctx.sess_proc, NULL);

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

static void dms_reform_migrate_collect_local_task(migrate_info_t *local_migrate_info)
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

static int dms_reform_migrate_inner(migrate_task_t *migrate_task)
{
    bilist_t *part_list = NULL;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    int ret = DMS_SUCCESS;

    LOG_RUN_INF("[DMS REFORM]dms_reform_migrate_inner, part_id: %d, inst: %d -> inst: %d",
        migrate_task->part_id, migrate_task->export_inst, migrate_task->import_inst);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_PAGE_TYPE);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    part_list = &ctx->global_buf_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_LOCK_TYPE);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part_list = &ctx->global_lock_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part_list, DRC_RES_LOCK_TYPE);

    return DMS_SUCCESS;
}

static int dms_reform_migrate(void)
{
    migrate_info_t local_migrate_info;
    migrate_task_t *migrate_task = NULL;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    dms_reform_migrate_collect_local_task(&local_migrate_info);
    for (uint8 i = 0; i < local_migrate_info.migrate_task_num; i++) {
        migrate_task = &local_migrate_info.migrate_task[i];
        ret = dms_reform_migrate_inner(migrate_task);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static void drc_rebuild_set_owner(drc_buf_res_t *buf_res, uint8 owner_id, bool8 cover)
{
    if (buf_res->claimed_owner == CM_INVALID_ID8 || buf_res->claimed_owner == owner_id) {
        buf_res->claimed_owner = owner_id;
        return;
    }

    if (cover) {
        bitmap64_set(&buf_res->copy_insts, buf_res->claimed_owner);
        buf_res->claimed_owner = owner_id;
        bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner);
    } else {
        bitmap64_set(&buf_res->copy_insts, owner_id);
    }
}

int dms_reform_rebuild_buf_res_l(char *resid, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty, uint8 inst_id)
{
    if (SECUREC_UNLIKELY(ctrl->lock_mode >= DMS_LOCK_MODE_MAX ||
        ctrl->is_edp > 1 || ctrl->need_flush > 1)) {
        LOG_DEBUG_ERR("[DRC rebuild] invalid request message, is_edp=%u, need_flush=%u",
            (uint32)ctrl->is_edp, (uint32)ctrl->need_flush);
        return ERRNO_DMS_RC_GET_RES_DATA_FAILED;
    }

    LOG_DEBUG_INF("[DRC rebuild][%s]remote_ditry: %d, lock_mode: %d, is_edp: %d, inst_id: %d, lsn: %llu, is_dirty: %d",
        cm_display_pageid(resid), ctrl->is_remote_dirty, ctrl->lock_mode, ctrl->is_edp, inst_id, lsn, is_dirty);

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, CM_TRUE, CM_FALSE);
    int ret = drc_enter_buf_res(resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }
    if (ctrl->lock_mode == DMS_LOCK_EXCLUSIVE) {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->claimed_owner == inst_id,
            "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(resid), buf_res->lock_mode);
        buf_res->claimed_owner = inst_id;
        buf_res->lock_mode = ctrl->lock_mode;
    } else if (ctrl->lock_mode == DMS_LOCK_SHARE) {
        cm_panic_log(buf_res->lock_mode == DMS_LOCK_NULL || buf_res->lock_mode == DMS_LOCK_SHARE,
            "[DRC rebuild][%s]lock_mode(%d) error", cm_display_pageid(resid), buf_res->lock_mode);
        buf_res->lock_mode = ctrl->lock_mode;
        if (ctrl->is_remote_dirty || (is_dirty && !ctrl->is_edp)) { // must be owner
            drc_rebuild_set_owner(buf_res, inst_id, CM_TRUE);
        } else if (is_dirty) { // is dirty and is edp, can be owner
            drc_rebuild_set_owner(buf_res, inst_id, CM_FALSE);
        } else { // is not dirty and is not edp, can not be owner now. should flush
            bitmap64_set(&buf_res->copy_insts, inst_id);
        }
    }

    if (ctrl->is_edp) {
        drc_add_edp_map(buf_res, inst_id, lsn);
    }

    buf_res->ver = ctrl->ver;
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

int dms_reform_rebuild_buf_res_inner(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, uint64 lsn, bool8 is_dirty,
    uint8 master_id)
{
    if (master_id == g_dms.inst_id) {
        return dms_reform_rebuild_buf_res_l(dms_ctx->resid, ctrl, lsn, is_dirty, master_id);
    } else {
        return dms_reform_req_rebuild_buf_res(dms_ctx, ctrl, lsn, is_dirty, master_id);
    }
}

static int dms_reform_rebuild_send_rest(void)
{
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    dms_reform_req_rebuild_t *rebuild_data = NULL;
    int ret = DMS_SUCCESS;

    for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
        rebuild_data = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[i];
        if (rebuild_data == NULL) {
            continue;
        }

        if (rebuild_data->offset != sizeof(dms_reform_req_rebuild_t)) {
            ret = dms_reform_send_data(&rebuild_data->head);
            DMS_RETURN_IF_ERROR(ret);
            rebuild_data->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        }
    }

    return DMS_SUCCESS;
}

static int dms_reform_rebuild_buf_res(void)
{
    int ret;

    ret = g_dms.callback.dms_reform_rebuild_buf_res(g_dms.reform_ctx.handle_proc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return dms_reform_rebuild_send_rest();
}

static void drc_get_lock_remaster_id(dms_drid_t *lock_id, uint8 *master_id)
{
    uint16 part_id;

    part_id = (uint16)drc_resource_id_hash((uint8 *)lock_id, sizeof(dms_drid_t), DRC_MAX_PART_NUM);
    *master_id = DRC_PART_REMASTER_ID(part_id);
}

int dms_reform_rebuild_lock_l(drc_local_lock_res_t *lock_res, uint8 src_inst)
{
    if (SECUREC_UNLIKELY(lock_res->latch_stat.lock_mode >= DMS_LOCK_MODE_MAX)) {
        LOG_DEBUG_ERR("[DRC][lock rebuild] invalid lock_mode: %u", lock_res->latch_stat.lock_mode);
        return ERRNO_DMS_DRC_LOCK_STATUS_FAIL;
    }

    if (lock_res->latch_stat.lock_mode == DMS_LOCK_NULL) {
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DRC][lock rebuild](%s), is_owner(%d), lock_mode: %d",
        cm_display_lockid(&lock_res->resid), lock_res->is_owner, lock_res->latch_stat.lock_mode);

    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_TRUE, CM_TRUE, CM_FALSE);
    int ret = drc_enter_buf_res((char *)&lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }

    buf_res->lock_mode = lock_res->latch_stat.lock_mode;

    if (buf_res->claimed_owner == CM_INVALID_ID8 || lock_res->latch_stat.lock_mode == DMS_LOCK_EXCLUSIVE) {
        buf_res->claimed_owner = src_inst;
    } else {
        bitmap64_set(&buf_res->copy_insts, src_inst);
    }
    
    buf_res->ver = lock_res->ver;
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

static int dms_reform_rebuild_lock_inner(drc_local_lock_res_t *lock_res, uint8 new_master)
{
    if (new_master == g_dms.inst_id) {
        return dms_reform_rebuild_lock_l(lock_res, new_master);
    } else {
        return dms_reform_req_rebuild_lock(lock_res, new_master);
    }
}

bool8 dms_reform_res_need_rebuild(uint8 master_id)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rebuild = &share_info->list_rebuild;

    if (share_info->full_clean) {
        return CM_TRUE;
    }

    if (dms_reform_list_exist(list_rebuild, master_id)) {
        return CM_TRUE;
    } else {
        return CM_FALSE;
    }
}

static int dms_reform_rebuild_lock_by_bucket(drc_res_bucket_t *bucket)
{
    bilist_node_t *node;
    drc_local_lock_res_t *lock_res;
    uint8 master_id;
    int ret = DMS_SUCCESS;

    cm_spin_lock(&bucket->lock, NULL);
    node = cm_bilist_head(&bucket->bucket_list);
    for (uint32 i = 0; i < bucket->bucket_list.count; i++) {
        lock_res = (drc_local_lock_res_t *)DRC_RES_NODE_OF(drc_local_lock_res_t, node, node);
        (void)drc_get_lock_master_id(&lock_res->resid, &master_id);
        if (dms_reform_res_need_rebuild(master_id)) {
            drc_get_lock_remaster_id(&lock_res->resid, &master_id);
            ret = dms_reform_rebuild_lock_inner(lock_res, master_id);
            DMS_BREAK_IF_ERROR(ret);
        }
        node = BINODE_NEXT(node);
    }
    cm_spin_unlock(&bucket->lock);
    return ret;
}

static int dms_reform_rebuild_lock(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    int ret;

    for (uint32 i = 0; i < ctx->local_lock_res.bucket_num; i++) {
        bucket = &ctx->local_lock_res.buckets[i];
        ret = dms_reform_rebuild_lock_by_bucket(bucket);
        DMS_RETURN_IF_ERROR(ret);
    }

    return dms_reform_rebuild_send_rest();
}

static void dms_reform_rebuild_buffer_init(void)
{
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        rebuild_info->rebuild_data[i] = NULL;
    }
}

static void dms_reform_rebuild_buffer_free(void)
{
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    dms_reform_req_rebuild_t *rebuild_data = NULL;

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        rebuild_data = rebuild_info->rebuild_data[i];
        if (rebuild_data != NULL) {
            g_dms.callback.mem_free(g_dms.reform_ctx.handle_proc, rebuild_data);
            rebuild_info->rebuild_data[i] = NULL;
        }
    }
}

static int dms_reform_rebuild(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;

    dms_reform_rebuild_buffer_init();
    ret = dms_reform_rebuild_buf_res();
    dms_reform_rebuild_buffer_free();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_rebuild_buffer_init();
    ret = dms_reform_rebuild_lock();
    dms_reform_rebuild_buffer_free();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_repair_with_copy_insts(drc_buf_res_t *buf_res)
{
    if (bitmap64_exist(&buf_res->copy_insts, (uint8)g_dms.inst_id)) {
        buf_res->claimed_owner = (uint8)g_dms.inst_id;
    } else {
        buf_res->claimed_owner = drc_lookup_owner_id(&buf_res->copy_insts);
    }

    bitmap64_clear(&buf_res->copy_insts, buf_res->claimed_owner);
    if (!dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN) && buf_res->type == DRC_RES_PAGE_TYPE) {
        buf_res->need_flush = CM_TRUE;
    }
    LOG_DEBUG_INF("[DMS REFORM][%s]dms_reform_repair_with_copy_insts, owner: %d, copy_inst: %llu",
        cm_display_resid(buf_res->data, buf_res->type), buf_res->claimed_owner, buf_res->copy_insts);

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_last_edp(drc_buf_res_t *buf_res)
{
    uint64 disk_lsn = 0;
    int ret = DMS_SUCCESS;

    ret = g_dms.callback.disk_lsn(g_dms.reform_ctx.handle_proc, buf_res->data, &disk_lsn);
    DMS_RETURN_IF_ERROR(ret);

    if (disk_lsn >= buf_res->lsn) {
        buf_res->last_edp = 0;
        buf_res->lsn = 0;
        buf_res->edp_map = 0;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_edp_map_inner(drc_buf_res_t *buf_res, uint8 inst_id)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;
    uint32 ver = buf_res->ver;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, inst_id, DMS_REQ_EDP_LSN);
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_repair_with_edp_map_inner SEND error: %d, dst_id: %d", ret, inst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, &ver);
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

static int dms_reform_repair_with_edp_map(drc_buf_res_t *buf_res)
{
    int ret = DMS_SUCCESS;

    buf_res->lsn = 0;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (!bitmap64_exist(&buf_res->edp_map, i)) {
            continue;
        }
        ret = dms_reform_repair_with_edp_map_inner(buf_res, i);
        DMS_RETURN_IF_ERROR(ret);
    }

    return dms_reform_repair_with_last_edp(buf_res);
}

static int dms_reform_repair_by_part_inner(drc_buf_res_t *buf_res)
{
    dms_reform_display_buf(buf_res, "repair");

    if (buf_res->claimed_owner != CM_INVALID_ID8) {
        return DMS_SUCCESS;
    }

    if (buf_res->copy_insts != 0) {
        return dms_reform_repair_with_copy_insts(buf_res);
    }

    if (buf_res->last_edp != CM_INVALID_ID8) {
        return dms_reform_repair_with_last_edp(buf_res);
    }

    if (buf_res->edp_map != 0) {
        return dms_reform_repair_with_edp_map(buf_res);
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_by_part(bilist_t *part_list)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_repair_by_part_inner(buf_res);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

static int dms_reform_repair_inner(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        // lock
        part_list = &ctx->global_lock_res.res_parts[part_id];
        ret = dms_reform_repair_by_part(part_list);
        DMS_RETURN_IF_ERROR(ret);
        // page
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_repair_by_part(part_list);
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

static int dms_reform_flush_copy_by_part_inner(drc_buf_res_t *buf_res)
{
    int ret = DMS_SUCCESS;

    if (!buf_res->need_flush) {
        return ret;
    }

#ifdef OPENGAUSS
    ret = g_dms.callback.flush_copy(g_dms.reform_ctx.handle_proc, buf_res->data);
#else
    if (dms_dst_id_is_self(buf_res->claimed_owner)) {
        ret = g_dms.callback.flush_copy(g_dms.reform_ctx.handle_proc, buf_res->data);
    } else {
        ret = dms_reform_flush_copy_page(buf_res);
    }
#endif

    buf_res->need_flush = CM_FALSE;
    return ret;
}

static int dms_reform_flush_copy_by_part(bilist_t *part_list)
{
    bilist_node_t *node = cm_bilist_head(part_list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_flush_copy_by_part_inner(buf_res);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

static int dms_reform_flush_copy_inner(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    bilist_t *part_list = NULL;
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_flush_copy_by_part(part_list);
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
        DMS_IS_SHARE_REFORMER);
}

static void dms_reform_recovery_set_flag_by_part_inner(drc_buf_res_t *buf_res)
{
    dms_reform_display_buf(buf_res, "recovery_set_flag");
    buf_res->in_recovery = CM_FALSE;
}

static void dms_reform_recovery_set_flag_by_part(bilist_t *part_list)
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

    ret = g_dms.callback.switchover_demote(g_dms.reform_ctx.handle_proc);
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

    ret = g_dms.callback.switchover_promote(g_dms.reform_ctx.handle_proc);
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

static int dms_reform_recovery_flag_clean(void)
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
    }

    int ret = memcpy_s(ctx->deposit_map, DMS_MAX_INSTANCES, remaster_info->deposit_map, DMS_MAX_INSTANCES);
    if (ret != EOK) {
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_undo_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.undo_init(g_dms.reform_ctx.handle_reform, list->inst_id_list[i]) != DMS_SUCCESS) {
            return ERRNO_DMS_CALLBACK_RC_UNDO_INIT;
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_tx_area_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_init(g_dms.reform_ctx.handle_reform, list->inst_id_list[i]) != DMS_SUCCESS) {
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT;
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_tx_area_load(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_load(g_dms.reform_ctx.handle_reform, list->inst_id_list[i]) != DMS_SUCCESS) {
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD;
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_rollback(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_PARTNER || list_rollback->inst_id_count == 0) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    ret = dms_reform_undo_init(list_rollback);
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

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

#ifndef OPENGAUSS
static void dms_reform_set_dms_standby(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

    if (reform_context->primary_standby && DMS_IS_SHARE_PARTNER) {
        g_dms.callback.set_db_standby(g_dms.reform_ctx.handle_proc);
    }
}
#endif

// set sync wait before done
static int dms_reform_success(void)
{
    LOG_RUN_FUNC_ENTER;
#ifndef OPENGAUSS
    dms_reform_set_dms_standby();
#endif
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

static void dms_reform_end(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t share_info;

    // health check should pause before clear share info
    dms_reform_health_set_pause();
    dms_reform_proc_set_pause();

    int ret = memset_s(&share_info, sizeof(share_info_t), 0, sizeof(share_info_t));
    DMS_SECUREC_CHECK(ret);

    reform_ctx->last_reform_info = reform_ctx->reform_info;
    reform_ctx->last_share_info = reform_ctx->share_info;
    reform_ctx->share_info = share_info;
    reform_info->ddl_unable = CM_FALSE;
    reform_info->bcast_unable = CM_FALSE;
    reform_info->reform_done = CM_TRUE;
}

static void dms_reform_set_switchover_result(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        LOG_RUN_INF("[DMS REFORM]dms_reform_set_switchover_result, reform_type: %u, promote_id: %d, current_id: %u",
            share_info->reform_type, share_info->promote_id, g_dms.inst_id);
        if (dms_dst_id_is_self(share_info->promote_id)) {
            g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, reform_info->err_code);
        }
        cm_spin_lock(&switchover_info->lock, NULL);
        switchover_info->switch_req = CM_FALSE;
        switchover_info->inst_id = CM_INVALID_ID8;
        switchover_info->sess_id = CM_INVALID_ID16;
        cm_spin_unlock(&switchover_info->lock);
    }
}

static int dms_reform_done(void)
{
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    LOG_RUN_FUNC_ENTER;
    bool32 save_ctrl = CM_FALSE;
    if (DMS_IS_SHARE_REFORMER) {
        save_ctrl = CM_TRUE;
    }
    ret = g_dms.callback.save_list_stable(g_dms.reform_ctx.handle_proc, share_info->bitmap_online,
        share_info->reformer_id, save_ctrl);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]list_stable fail to save in ctrl");
        return ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED;
    }
    dms_reform_set_switchover_result();
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

    dms_reform_end();
    reform_info->last_fail = CM_FALSE;
    reform_info->first_reform_finish = CM_TRUE;
#ifdef OPENGAUSS
    g_dms.callback.reform_done_notify(g_dms.reform_ctx.handle_proc);
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
    cm_latch_x(&reform_info->bcast_latch, g_dms.reform_ctx.sess_proc, NULL);
    reform_info->bitmap_connect = share_info->bitmap_online;
    reform_info->bcast_unable = CM_FALSE;
    cm_unlatch(&reform_info->bcast_latch, NULL);
    cm_latch_x(&reform_info->ddl_latch, g_dms.reform_ctx.sess_proc, NULL);
    reform_info->ddl_unable = CM_FALSE;
    cm_unlatch(&reform_info->ddl_latch, NULL);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_bcast_unable(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_FUNC_ENTER;
    // Notice: must set ddl unable before set bcast unable
    cm_latch_x(&reform_info->ddl_latch, g_dms.reform_ctx.sess_proc, NULL);
    reform_info->ddl_unable = CM_TRUE;
    cm_unlatch(&reform_info->ddl_latch, NULL);
    cm_latch_x(&reform_info->bcast_latch, g_dms.reform_ctx.sess_proc, NULL);
    reform_info->bcast_unable = CM_TRUE;
    cm_unlatch(&reform_info->bcast_latch, NULL);
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
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_step SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_sync_step_wait();
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
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_sync_next_step(&req, dst_id);
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_sync_fail_r SEND error: %d, dst_id: %d", ret, dst_id);
            break;
        }

        ret = dms_reform_req_sync_next_step_wait();
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_sync_step WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }
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
static void dms_reform_self_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    } else {
        (void)dms_reform_sync_step_send();
    }
    dms_reform_set_last_fail();
    dms_reform_set_switchover_result();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
}

// reform fail cause by notification from reformer
static void dms_reform_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    }
    dms_reform_set_last_fail();
    dms_reform_set_switchover_result();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
}

static int dms_reform_sync_next_step_r(uint8 dst_id)
{
    dms_reform_req_sync_step_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_sync_next_step(&req, dst_id);
        if (reform_info->reform_fail) {
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_sync_next_step_r send error: %d, dst_id: %d", ret, dst_id);
            break;
        }

        ret = dms_reform_req_sync_next_step_wait();
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

static int dms_reform_drc_inaccess(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    if (!dms_reform_type_is(DMS_REFORM_TYPE_FOR_MAINTAIN)) {
        if (!drc_buf_res_set_inaccess(&ctx->global_lock_res)) {
            return DMS_SUCCESS;
        }
    }
    if (!drc_buf_res_set_inaccess(&ctx->global_buf_res)) {
        return DMS_SUCCESS;
    }
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
        if (DMS_IS_SHARE_REFORMER && dms_reform_type_is(DMS_REFORM_TYPE_FOR_OPENGAUSS)) {
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

static void dms_reform_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    switch (reform_info->current_step) {
        case DMS_REFORM_STEP_PREPARE:
            ret = dms_reform_prepare();
            break;

        case DMS_REFORM_STEP_START:
            ret = dms_reform_start();
            break;

        case DMS_REFORM_STEP_DISCONNECT:
            ret = dms_reform_disconnect();
            break;

        case DMS_REFORM_STEP_RECONNECT:
            ret = dms_reform_reconnect();
            break;

        case DMS_REFORM_STEP_DRC_CLEAN:
            ret = dms_reform_drc_clean();
            break;

        case DMS_REFORM_STEP_MIGRATE:
            ret = dms_reform_migrate();
            break;

        case DMS_REFORM_STEP_REBUILD:
            ret = dms_reform_rebuild();
            break;

        case DMS_REFORM_STEP_REMASTER:
            ret = dms_reform_remaster();
            break;

        case DMS_REFORM_STEP_REPAIR:
            ret = dms_reform_repair();
            break;

        case DMS_REFORM_STEP_FLUSH_COPY:
            ret = dms_reform_flush_copy();
            break;

        case DMS_REFORM_STEP_SWITCH_LOCK:
            ret = dms_reform_switch_lock();
            break;

        case DMS_REFORM_STEP_SWITCHOVER_DEMOTE:
            ret = dms_reform_switchover_demote();
            break;

        case DMS_REFORM_STEP_SWITCHOVER_PROMOTE:
            ret = dms_reform_switchover_promote();
            break;

        case DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS:
            ret = dms_reform_switchover_promote_opengauss();
            break;

        case DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS:
            ret = dms_reform_failover_promote_opengauss();
            break;

        case DMS_REFORM_STEP_RECOVERY:
            ret = dms_reform_recovery();
            break;

        case DMS_REFORM_STEP_RECOVERY_OPENGAUSS:
            ret = dms_reform_recovery_opengauss();
            break;

        case DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN:
            ret = dms_reform_recovery_flag_clean();
            break;

        case DMS_REFORM_STEP_TXN_DEPOSIT:
            ret = dms_reform_txn_deposit();
            break;

        case DMS_REFORM_STEP_ROLLBACK:
            ret = dms_reform_rollback();
            break;

        case DMS_REFORM_STEP_SUCCESS:
            ret = dms_reform_success();
            break;

        case DMS_REFORM_STEP_SYNC_WAIT:
            ret = dms_reform_sync_wait();
            break;

        case DMS_REFORM_STEP_PAGE_ACCESS:
            ret = dms_reform_page_access();
            break;

        case DMS_REFORM_STEP_DRC_ACCESS:
            ret = dms_reform_drc_access();
            break;

        case DMS_REFORM_STEP_DRC_INACCESS:
            ret = dms_reform_drc_inaccess();
            break;

        case DMS_REFORM_STEP_STARTUP_OPENGAUSS:
            ret = dms_reform_startup_opengauss();
            break;

        case DMS_REFORM_STEP_DONE:
            ret = dms_reform_done();
            break;

        case DMS_REFORM_STEP_DONE_CHECK:
            ret = dms_reform_done_check();
            break;

        case DMS_REFORM_STEP_SET_PHASE:
            ret = dms_reform_set_phase();
            break;

        case DMS_REFORM_STEP_WAIT_DB:
            ret = dms_reform_wait_db();
            break;

        case DMS_REFORM_STEP_BCAST_ENABLE:
            ret = dms_reform_bcast_enable();
            break;

        case DMS_REFORM_STEP_BCAST_UNABLE:
            ret = dms_reform_bcast_unable();
            break;

        case DMS_REFORM_STEP_UPDATE_SCN:
            ret = dms_reform_update_scn();
            break;

        case DMS_REFORM_STEP_WAIT_CKPT:
            ret = dms_reform_wait_ckpt();
            break;

        case DMS_REFORM_STEP_SELF_FAIL:
            dms_reform_self_fail();
            break;

        case DMS_REFORM_STEP_REFORM_FAIL:
            dms_reform_fail();
            break;

        default:
            LOG_RUN_ERR("dms_reform_inner, error step: %d", reform_info->current_step);
            return;
    }

    if (reform_info->reform_done) {
        return;
    }

    if (reform_info->reform_fail) {
        reform_info->current_step = DMS_REFORM_STEP_REFORM_FAIL;
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }

    if (ret != DMS_SUCCESS) {
        reform_info->current_step = DMS_REFORM_STEP_SELF_FAIL;
        reform_info->err_code = ret;
        return;
    }

    if (dms_reform_check_partner_fail()) {
        reform_info->current_step = DMS_REFORM_STEP_SELF_FAIL;
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }
}

void dms_reform_proc_thread(thread_t *thread)
{
    cm_set_thread_name("reform_proc");
    reform_info_t *reform_info = DMS_REFORM_INFO;
#ifdef OPENGAUSS
    // this thread will invoke startup method in opengauss
    // need_startup flag need set to be true
    g_dms.callback.dms_thread_init(CM_TRUE, (char **)&thread->reg_data);
#endif

    LOG_RUN_INF("[DMS REFORM]dms_reform_proc thread started");
    while (!thread->closed) {
        if (reform_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            reform_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            DMS_REFORM_LONG_SLEEP;
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_proc paused");
            reform_info->thread_status = DMS_THREAD_STATUS_PAUSED;
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_RUNNING) {
            reform_info->proc_time = (uint64)g_timer()->now; // record time for check if dms_reform_proc is active
            dms_reform_inner();
        }
    }
}