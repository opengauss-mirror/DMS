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
 * dms_reform_msg.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_msg.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_msg.h"
#include "dms_reform.h"
#include "dms_reform_proc.h"
#include "dms_reform_judge.h"
#include "drc_res_mgr.h"
#include "dms_error.h"
#include "dms_mfc.h"
#include "dms_stat.h"
#include "dms_msg_protocol.h"
#include "dcs_page.h"
#include "dms_reform_xa.h"
#include "dms_reform_proc_stat.h"

static dms_proto_version_attr g_req_share_info_version_ctrl[DMS_PROTO_VER_NUMS] = {
     [DMS_PROTO_VER_1] = { OFFSET_OF(dms_reform_req_sync_share_info_t, share_info.inst_bitmap), },
     [DMS_PROTO_VER_2] = { sizeof(dms_reform_req_sync_share_info_t) },
};

static int dms_reform_req_common_wait(uint64 ruid)
{
    dms_message_t res;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    DMS_RETURN_IF_ERROR(ret);
    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    if (ack_common->result != DMS_SUCCESS) {
        mfc_release_response(&res);
        return ack_common->result;
    }
    mfc_release_response(&res);
    return DMS_SUCCESS;
}

int dms_reform_send_data(dms_message_head_t *msg_head, uint32 sess_id)
{
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (dms_reform_failed()) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        msg_head->cluster_ver = DMS_GLOBAL_CLUSTER_VER;
        ret = mfc_send_data(msg_head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_send_data SEND error: %d, dst_id: %d", ret, msg_head->dst_inst);
            return ret;
        }

        ret = dms_reform_req_common_wait(msg_head->ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_send_data WAIT timeout, dst_id: %d", msg_head->dst_inst);
            continue;
        } else {
            break;
        }
    }

    return ret;
}

// notify partner reform, sync share info
int dms_reform_init_req_sync_share_info(dms_reform_req_sync_share_info_t *req, uint8 dst_id)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_SYNC_SHARE_INFO, 0, g_dms.inst_id, dst_id, reform_context->sess_judge,
        CM_INVALID_ID16);
    int ret = dms_fill_versioned_msg_head(g_req_share_info_version_ctrl, &req->head, share_info->proto_version);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    req->share_info = *share_info;
    return DMS_SUCCESS;
}

static void dms_reform_ack_sync_share_info(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_sync_share_info(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_req_sync_share_info_t req;
    int ret = dms_recv_versioned_msg(g_req_share_info_version_ctrl, receive_msg, &req, sizeof(req));
    if (ret != DMS_SUCCESS) {
        dms_reform_ack_sync_share_info(process_ctx, receive_msg, DMS_ERROR);
        return;
    }
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (receive_msg->head->src_inst != reform_info->reformer_id) {
        LOG_RUN_WAR(
            "[DMS REFORM]Refusing to proc sync share info because the src %d is not the same as the local reformer %u",
            receive_msg->head->src_inst, reform_info->reformer_id);
        dms_reform_ack_sync_share_info(process_ctx, receive_msg, DMS_ERROR);
        return;
    }
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

    if (SECUREC_UNLIKELY(req.share_info.reform_type >= DMS_REFORM_TYPE_COUNT ||
        req.share_info.reform_step_count > DMS_REFORM_STEP_TOTAL_COUNT ||
        req.share_info.list_stable.inst_id_count > g_dms.inst_cnt ||
        req.share_info.list_online.inst_id_count > g_dms.inst_cnt ||
        req.share_info.list_offline.inst_id_count > g_dms.inst_cnt ||
        req.share_info.list_reconnect.inst_id_count > g_dms.inst_cnt ||
        req.share_info.list_disconnect.inst_id_count > g_dms.inst_cnt)) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_proc_sync_share_info invalid share info message");
        return;
    }

    share_info_t *received_share_info = &req.share_info;
    share_info_t *local_share_info = &reform_context->share_info;
    reform_info_t *local_reform_info = &reform_context->reform_info;
    cm_spin_lock(&reform_context->share_info_lock, NULL);
    if (local_share_info->version_num == received_share_info->version_num &&
        dms_reform_version_same(&local_reform_info->reformer_version, &received_share_info->reformer_version)) {
        LOG_DEBUG_WAR("[DMS REFORM] current round(version num:%llu) of reform is being executed "
                      "or share info sync msg has been expired", local_share_info->version_num);
        dms_reform_ack_sync_share_info(process_ctx, receive_msg, DMS_SUCCESS);
        cm_spin_unlock(&reform_context->share_info_lock);
        return;
    }

    reform_context->share_info = req.share_info;
    cm_spin_unlock(&reform_context->share_info_lock);
    dms_reform_ack_sync_share_info(process_ctx, receive_msg, DMS_SUCCESS);
    dms_reform_judgement_step_log();
    dms_reform_set_start();
}

int dms_reform_req_sync_share_info_wait(uint64 ruid)
{
    int ret = dms_reform_req_common_wait(ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
    return ret;
}

void dms_reform_init_req_sync_step(dms_reform_req_sync_step_t *req)
{
    reform_context_t *ctx = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_SYNC_STEP, 0, g_dms.inst_id, share_info->reformer_id, ctx->sess_proc,
        CM_INVALID_ID16);
    dms_reform_set_judge_time(&req->head);
    req->head.size = (uint16)sizeof(dms_reform_req_sync_step_t);
    req->last_step = reform_info->last_step;
    req->curr_step = reform_info->current_step;
    req->next_step = reform_info->next_step;
#ifndef OPENGAUSS
    req->scn = g_dms.callback.get_global_scn(ctx->handle_proc);
#endif
}

static void dms_reform_ack_req_sync_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = DMS_SUCCESS;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_sync_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_sync_step_t), CM_TRUE);
    dms_reform_req_sync_step_t *req = (dms_reform_req_sync_step_t *)receive_msg->buffer;
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 instance_id = req->head.src_inst;

    if (!dms_reform_check_judge_time(&req->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_MES_INVALID_MSG, "fail to check judge time");
        return;
    }

    if (SECUREC_UNLIKELY(req->last_step >= DMS_REFORM_STEP_COUNT ||
        req->curr_step >= DMS_REFORM_STEP_COUNT ||
        req->next_step >= DMS_REFORM_STEP_COUNT)) {
        LOG_DEBUG_ERR("[DMS REFORM] dms_reform_proc_sync_step, invalid request, "
            "last_step=%u, curr_step=%u, next_step=%u", (uint32)req->last_step,
            (uint32)req->curr_step, (uint32)req->next_step);
        return;
    }

    if (req->curr_step == DMS_REFORM_STEP_SELF_FAIL) {
        reformer_ctrl->instance_fail[instance_id] = CM_TRUE;
    } else {
        reformer_ctrl->instance_step[instance_id] = req->last_step;
    }
    reform_info->max_scn = MAX(reform_info->max_scn, req->scn);

    dms_reform_ack_req_sync_step(process_ctx, receive_msg);
}

int dms_reform_req_sync_step_wait(uint64 ruid)
{
    int ret = dms_reform_req_common_wait(ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
    return ret;
}

void dms_reform_init_req_dms_status(dms_reform_req_partner_status_t *req, uint8 dst_id, uint32 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_DMS_STATUS, 0, g_dms.inst_id, dst_id, sess_id, CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_partner_status_t);
    req->lsn = reform_info->start_time;
    cm_spin_lock(&g_dms.dms_driver_ping_info.lock, NULL);
    req->driver_ping_info = g_dms.dms_driver_ping_info.driver_ping_info;
    cm_spin_unlock(&g_dms.dms_driver_ping_info.lock);
}

void dms_reform_ack_req_dms_status(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_ack_common_t ack_common;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    dms_reform_req_partner_status_t *req = (dms_reform_req_partner_status_t*)receive_msg->head;
    cm_spin_lock(&g_dms.dms_driver_ping_info.lock, NULL);
    g_dms.dms_driver_ping_info.driver_ping_info = req->driver_ping_info;
    cm_spin_unlock(&g_dms.dms_driver_ping_info.lock);

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    if (receive_msg->head->src_inst != reform_info->reformer_id) {
        LOG_RUN_WAR(
            "[DMS REFORM]Refusing to get dms status because the src %d is not the same as the local reformer %u",
            receive_msg->head->src_inst, reform_info->reformer_id);
        ack_common.result = DMS_ERROR;
    } else {
        dms_reform_update_reformer_version(req->lsn, req->head.src_inst);
        ack_common.result = DMS_SUCCESS;
        ack_common.dms_status = (uint8)g_dms.callback.get_dms_status(process_ctx->db_handle);
        ack_common.start_time = reform_info->start_time;
#ifdef OPENGAUSS
        ack_common.db_is_readwrite = 1;
#else
        ack_common.db_is_readwrite = (uint8)g_dms.callback.check_db_readwrite(process_ctx->db_handle);
#endif
    }
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

int dms_reform_req_dms_status_wait(uint8 *online_status, uint64* online_times, uint8 *online_rw_status,
    uint8 dst_id, uint64 ruid)
{
    dms_message_t res;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_MSG_SLEEP_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_req_dms_status_wait error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    if (ack_common->result != DMS_SUCCESS) {
        mfc_release_response(&res);
        return DMS_ERROR;
    }
    online_status[dst_id] = ack_common->dms_status;
    online_times[dst_id] = ack_common->start_time;
    online_rw_status[dst_id] = ack_common->db_is_readwrite;
    mfc_release_response(&res);
    return DMS_SUCCESS;
}

void dms_reform_proc_req_dms_status(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_reform_req_partner_status_t), CM_FALSE);
    dms_reform_ack_req_dms_status(process_ctx, receive_msg);
}


static bool8 dms_lamport_update_cluster_version(uint32 new_gcv, bool8 pushing)
{
    if (new_gcv > DMS_GLOBAL_CLUSTER_VER) {
        LOG_DEBUG_INF("[DMS_REFORM][GCV %s]dms_lamport_update_cluster_version pushed gcv=%u, old_gcv=%u",
            pushing ? "PUSH" : "SYNC", new_gcv, DMS_GLOBAL_CLUSTER_VER);
        g_dms.cluster_ver = new_gcv;
        return CM_TRUE;
    } else {
        if (pushing) {
            LOG_DEBUG_WAR("[DMS_REFORM][GCV PUSH]expect push curr partner gcv=%u; curr_gcv=%u, could be error",
                new_gcv, DMS_GLOBAL_CLUSTER_VER);
        }
    }
    return CM_FALSE;
}

/* reform proc pushes gcv, while judge proc only syncs it */
void dms_reform_init_req_gcv_sync(dms_reform_req_gcv_sync_t *req, uint8 dst_id, bool8 pushing)
{
    reform_context_t *ctx = DMS_REFORM_CONTEXT;
    uint32 src_sid = pushing ? ctx->sess_proc : ctx->sess_judge;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_REFORM_GCV_SYNC, 0, g_dms.inst_id, dst_id, src_sid,
        CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_gcv_sync_t);
    req->pushing = pushing;
}

static void dms_reform_ack_req_gcv_sync(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_ack_gcv_sync_t ack_gcv_sync;
    int ret = DMS_SUCCESS;

    dms_reform_req_gcv_sync_t *req = (dms_reform_req_gcv_sync_t *)receive_msg->buffer;
    bool8 pushing = req->pushing;
    bool8 updated = dms_lamport_update_cluster_version(receive_msg->head->cluster_ver, pushing);

    dms_init_ack_head(receive_msg->head, &ack_gcv_sync.head, MSG_ACK_REFORM_GCV_SYNC, sizeof(dms_reform_ack_gcv_sync_t),
        process_ctx->sess_id);
    ack_gcv_sync.updated = updated;
    ack_gcv_sync.head.cluster_ver = DMS_GLOBAL_CLUSTER_VER;
    ret = mfc_send_data(&ack_gcv_sync.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_gcv_sync(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_gcv_sync_t), CM_TRUE);
    LOG_DEBUG_INF("[DMS REFORM][GCV SYNC]partner curr gcv:%u, received reformer gcv:%u",
        DMS_GLOBAL_CLUSTER_VER, receive_msg->head->cluster_ver);

    /* partner lamport-update gcv during ack here */
    dms_reform_ack_req_gcv_sync(process_ctx, receive_msg);
}

int dms_reform_req_gcv_sync_wait(bool8 *local_updated, bool8 pushing, uint64 ruid)
{
    dms_message_t res;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_gcv_sync_t *ack = (dms_reform_ack_gcv_sync_t *)res.buffer;
    if (pushing && !ack->updated) {
        LOG_DEBUG_WAR("[DMS REFORM][GCV PUSH]reformer:%d-gcv:%u, partner:%d-gcv:%u, could be error",
            res.head->dst_inst, DMS_GLOBAL_CLUSTER_VER,
            res.head->src_inst, res.head->cluster_ver);
    }
    LOG_DEBUG_INF("[DMS REFORM][GCV %s]reformer:%d-gcv:%u, partner:%d-gcv:%u, partner pushed:%s",
        pushing ? "PUSH" : "SYNC", res.head->dst_inst, DMS_GLOBAL_CLUSTER_VER, res.head->src_inst,
        res.head->cluster_ver, ack->updated ? "Y" : "N");

    /* reformer should have the biggest gcv, unless cluster has partially rebooted */
    *local_updated |= dms_lamport_update_cluster_version(res.head->cluster_ver, CM_FALSE);
    mfc_release_response(&res);
    return DMS_SUCCESS;
}

/* check if any partner has reform in progress */
void dms_reform_init_req_prepare(dms_reform_req_prepare_t *req, uint8 dst_id)
{
    reform_context_t *ctx = DMS_REFORM_CONTEXT;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_REFORM_PREPARE, 0, g_dms.inst_id, dst_id, ctx->sess_judge,
        CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_prepare_t);
}

static void dms_reform_ack_req_prepare(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int in_reform)
{
    dms_reform_ack_common_t ack_common = { 0 };
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = in_reform;
    ack_common.last_fail = reform_info->last_fail;
#ifndef OPENGAUSS
    ack_common.has_ddl_2phase = (bool8)g_dms.callback.reform_is_need_ddl_2phase_rcy(process_ctx->db_handle);
#endif
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_prepare(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    if (DMS_IS_REFORMER) {
        LOG_DEBUG_WAR("[DMS REFORM]invalid dms_reform_proc_req_prepare");
        return;
    }

    int in_reform = dms_reform_in_process();
    LOG_DEBUG_INF("[DMS REFORM]dms_reform_proc_req_prepare in reform: %d", in_reform);
    dms_reform_ack_req_prepare(process_ctx, receive_msg, in_reform);

    if (in_reform) {
        reform_info_t* reform_info = DMS_REFORM_INFO;
        reform_info->reform_fail = CM_TRUE;
        LOG_RUN_INF("[DMS REFORM]set reform fail, receive MSG_REQ_REFORM_PREPARE");
        return;
    }

    // switchover will change reformer, initial status array at every instances
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        reformer_ctrl->instance_fail[i] = 0;
        reformer_ctrl->instance_step[i] = 0;
    }
}

int dms_reform_req_prepare_wait(bool8 *last_fail, int *in_reform, bool8 *has_ddl_2phase, uint64 ruid)
{
    dms_message_t res;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    *last_fail = ack_common->last_fail;
    *in_reform = ack_common->result;
    *has_ddl_2phase = ack_common->has_ddl_2phase;
    mfc_release_response(&res);
    return DMS_SUCCESS;
}

void dms_reform_init_req_sync_next_step(dms_reform_req_sync_step_t *req, uint8 dst_id)
{
    reform_context_t *ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t* share_info = DMS_SHARE_INFO;

    DMS_INIT_MESSAGE_HEAD(&(req->head), MSG_REQ_SYNC_NEXT_STEP, 0, g_dms.inst_id, dst_id, ctx->sess_proc,
        CM_INVALID_ID16);
    dms_reform_set_judge_time(&req->head);
    req->head.size = (uint16)sizeof(dms_reform_req_sync_step_t);
    req->curr_step = reform_info->current_step;
    req->next_step = reform_info->next_step;
    req->scn = reform_info->max_scn;
    req->start_time = share_info->start_times[dst_id];
}

void dms_reform_ack_sync_next_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_ack_common_t ack_common = { 0 };
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = DMS_SUCCESS;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_sync_next_step(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_sync_step_t), CM_TRUE);
    dms_reform_req_sync_step_t *req = (dms_reform_req_sync_step_t *)receive_msg->buffer;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (!dms_reform_check_judge_time(&req->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        return;
    }

    if (SECUREC_UNLIKELY(req->next_step >= DMS_REFORM_STEP_COUNT)) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_proc_sync_next_step invalid next_step");
        return;
    }

    if (DMS_IS_REFORMER) {
        LOG_DEBUG_WAR("[DMS REFORM]invalid dms_reform_proc_sync_next_step");
        return;
    }

    if (req->start_time != reform_info->start_time) {
        LOG_DEBUG_WAR("[DMS REFORM]expired dms_reform_proc_sync_next_step");
        return;
    }

    if (req->curr_step == DMS_REFORM_STEP_SELF_FAIL || req->curr_step == DMS_REFORM_STEP_REFORM_FAIL) {
        reform_info->reform_fail = CM_TRUE;
        LOG_RUN_INF("[DMS REFORM]set reform fail by reformer");
        return;
    }

    reform_info->sync_step = req->next_step;
    reform_info->max_scn = MAX(reform_info->max_scn, req->scn);
    dms_reform_ack_sync_next_step(process_ctx, receive_msg);
}

int dms_reform_req_sync_next_step_wait(uint64 ruid)
{
    int ret = dms_reform_req_common_wait(ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
    return ret;
}

static void dms_reform_req_migrate_init(dms_reform_req_migrate_t *req, migrate_task_t *migrate_task, uint8 res_type,
    uint32 sess_id)
{
    DMS_INIT_MESSAGE_HEAD(&req->head, MES_REQ_MGRT_MASTER_DATA, 0, g_dms.inst_id, migrate_task->import_inst, sess_id,
        CM_INVALID_ID16);
    dms_reform_set_judge_time(&req->head);
    req->part_id = migrate_task->part_id;
    req->res_num = 0;
    req->is_part_end = CM_FALSE;
    req->res_type = res_type;
}

static int dms_reform_req_migrate_add_buf_res(drc_head_t *drc, dms_reform_req_migrate_t *req, uint32 *offset,
    uint32 sess_id)
{
    int ret;
    uint32 len = (uint32)sizeof(drc_buf_res_msg_t);
    if ((*offset + len) > DMS_REFORM_MSG_MAX_LENGTH) {
        // send current msg, then reset the msg pack
        req->head.size = (uint16)(*offset);
        ret = dms_reform_send_data(&req->head, sess_id);
        if (ret != CM_SUCCESS) {
            LOG_DEBUG_FUNC_FAIL;
            return ret;
        }
        *offset = (uint32)sizeof(dms_reform_req_migrate_t);
        req->res_num = 0;
    }
    drc_buf_res_msg_t *res_msg = (drc_buf_res_msg_t*)((uint8 *)req + *offset);
    res_msg->claimed_owner = drc->owner;
    res_msg->copy_insts = drc->copy_insts;
    res_msg->mode = drc->lock_mode;
    res_msg->len = drc->len;
    res_msg->converting = drc->converting.req_info;
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        res_msg->last_edp = drc_page->last_edp;
        res_msg->lsn = drc_page->last_edp_lsn;
        res_msg->edp_map = drc_page->edp_map;
    }
    ret = memcpy_s(res_msg->resid, DMS_RESID_SIZE, DRC_DATA(drc), drc->len);
    DMS_SECUREC_CHECK(ret);
    *offset += len;
    req->res_num++;
    return DMS_SUCCESS;
}

int dms_reform_req_migrate_res(migrate_task_t *migrate_task, uint8 type, void *handle, uint32 sess_id)
{
    dms_reform_req_migrate_t *req = NULL;

    req = (dms_reform_req_migrate_t *)g_dms.callback.mem_alloc(handle, DMS_REFORM_MSG_MAX_LENGTH);
    if (req == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_STACK_PUSH);
        return ERRNO_DMS_CALLBACK_STACK_PUSH;
    }
    dms_reform_req_migrate_init(req, migrate_task, type, sess_id);

    int ret = DMS_SUCCESS;
    drc_head_t *drc = NULL;
    drc_global_xa_res_t *xa_res = NULL;
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(type);

    drc_part_list_t *part = &global_res_map->res_parts[migrate_task->part_id];
    bilist_t *res_list = &part->list;
    bilist_node_t *node = cm_bilist_head(res_list);
    uint32 offset = (uint32)sizeof(dms_reform_req_migrate_t);

    if (res_list->count == 0) {
        g_dms.callback.mem_free(handle, req);
        return DMS_SUCCESS;
    }

    for (uint32 i = 0; i < res_list->count; i++) {
        if (type == DRC_RES_GLOBAL_XA_TYPE) {
            xa_res = DRC_RES_NODE_OF(drc_global_xa_res_t, node, part_node);
            ret = dms_reform_req_migrate_xa(xa_res, req, &offset, sess_id);
        } else {
            drc = DRC_RES_NODE_OF(drc_head_t, node, part_node);
            DRC_DISPLAY(drc, "migrate");
            ret = dms_reform_req_migrate_add_buf_res(drc, req, &offset, sess_id);
        }

        if (ret != DMS_SUCCESS) {
            g_dms.callback.mem_free(handle, req);
            LOG_DEBUG_FUNC_FAIL;
            return ret;
        }
        node = BINODE_NEXT(node);
    }

    if (req->res_num == 0) { // page has been sent
        g_dms.callback.mem_free(handle, req);
        return DMS_SUCCESS;
    }

    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_MGRT_MASTER_DATA, MES_REQ_MGRT_MASTER_DATA);
    req->head.size = (uint16)offset;
    ret = dms_reform_send_data(&req->head, sess_id);
    if (ret != CM_SUCCESS) {
        g_dms.callback.mem_free(handle, req);
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    g_dms.callback.mem_free(handle, req);
    return DMS_SUCCESS;
}

static int dms_reform_migrate_add_buf_res(dms_process_context_t *process_ctx, drc_buf_res_msg_t *res_msg, uint8 type)
{
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(res_msg->resid, res_msg->len, type, options, &drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (drc == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH;
    }
    init_drc_cvt_item(&drc->converting);
    drc->type = type;
    drc->len = res_msg->len;
    drc->owner = res_msg->claimed_owner;
    drc->lock_mode = res_msg->mode;
    drc->copy_insts = res_msg->copy_insts;
    drc->converting.req_info = res_msg->converting;
    cm_bilist_init(&drc->convert_q);
    if (type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        drc_page->last_edp = res_msg->last_edp;
        drc_page->last_edp_lsn = res_msg->lsn;
        drc_page->edp_map = res_msg->edp_map;
    }
    drc_leave(drc, options);
    return DMS_SUCCESS;
}

static int dms_reform_proc_req_migrate_res(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_reform_req_migrate_t *req = (dms_reform_req_migrate_t *)receive_msg->buffer;

    LOG_DEBUG_INF("[DRC]get page resource migration data, msg size:%d, part id:%u, res num:%u, part end:%d",
        req->head.size, req->part_id, req->res_num, req->is_part_end);

    if (req->res_num == 0) {
        return DMS_SUCCESS;
    }

    drc_buf_res_msg_t  *res_msg = NULL;
    uint32 offset = (uint32)sizeof(dms_reform_req_migrate_t);
    int ret = DMS_SUCCESS;

    for (uint32 i = 0; i < req->res_num; i++) {
        CM_ASSERT(offset <= req->head.size);
        res_msg = (drc_buf_res_msg_t *)((uint8 *)receive_msg->buffer + offset);
        if (SECUREC_UNLIKELY(res_msg->len > DMS_RESID_SIZE)) {
            DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "res_msg len");
            return ERRNO_DMS_PARAM_INVALID;
        }

        ret = dms_reform_migrate_add_buf_res(process_ctx, res_msg, req->res_type);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_FUNC_FAIL;
            return ret;
        }
        offset += (uint32)sizeof(drc_buf_res_msg_t);
    }

    return DMS_SUCCESS;
}

void dms_reform_ack_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    dms_reform_ack_common_t ack_common = { 0 };
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_migrate_t), CM_TRUE);
    dms_reform_req_migrate_t *req = (dms_reform_req_migrate_t *)receive_msg->buffer;

    if (SECUREC_UNLIKELY(req->part_id > DRC_MAX_PART_NUM)) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_proc_req_migrate invalid migrate request");
        return;
    }

    if (!dms_reform_check_judge_time(&req->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        return;
    }

    if (req->res_type == DRC_RES_GLOBAL_XA_TYPE) {
        dms_reform_proc_req_xa_migrate(process_ctx, receive_msg);
        return;
    }

    uint64 res_len = sizeof(drc_buf_res_msg_t);
    uint64 total_size = (uint64)(sizeof(dms_reform_req_migrate_t) + req->res_num * res_len);
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_TRUE);

    int ret = dms_reform_proc_req_migrate_res(process_ctx, receive_msg);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
    dms_reform_ack_req_migrate(process_ctx, receive_msg, ret);
}

int dms_reform_req_page_rebuild_parallel(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id, uint8 thread_index)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)parallel->data[master_id];
    uint32 append_size = sizeof(dms_ctrl_info_t);
    int ret = DMS_SUCCESS;

    // if NULL, init req_rebuild
    if (req_rebuild == NULL) {
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(parallel->handle,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }
        parallel->data[master_id] = req_rebuild;
        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, cmd, 0, dms_ctx->inst_id, master_id, parallel->sess_id,
            CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }

    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, parallel->sess_id);
        DMS_RETURN_IF_ERROR(ret);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    ret = memcpy_s((uint8 *)req_rebuild + req_rebuild->offset, append_size, ctrl_info, append_size);
    DMS_SECUREC_CHECK(ret);
    req_rebuild->offset += append_size;
    return DMS_SUCCESS;
}

int dms_reform_req_page_rebuild(msg_command_t cmd, dms_context_t *dms_ctx, dms_ctrl_info_t *ctrl_info,
    uint8 master_id)
{
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[master_id];
    uint32 append_size = sizeof(dms_ctrl_info_t);
    int ret = DMS_SUCCESS;

    // if NULL, init req_rebuild
    if (req_rebuild == NULL) {
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }
        rebuild_info->rebuild_data[master_id] = req_rebuild;
        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, cmd, 0, dms_ctx->inst_id, master_id,
            g_dms.reform_ctx.sess_proc, CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }

    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, g_dms.reform_ctx.sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    ret = memcpy_s((uint8 *)req_rebuild + req_rebuild->offset, append_size, ctrl_info, append_size);
    DMS_SECUREC_CHECK(ret);
    req_rebuild->offset += append_size;
    return DMS_SUCCESS;
}

void dms_reform_ack_req_rebuild(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_page_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_rebuild_t), CM_TRUE);
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)receive_msg->buffer;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, req_rebuild->offset, CM_TRUE);

    if (!dms_reform_check_judge_time(&req_rebuild->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_MES_INVALID_MSG, "fail to check judge time");
        return;
    }

    uint8 inst_id = req_rebuild->head.src_inst;
    uint32 offset = (uint32)sizeof(dms_reform_req_rebuild_t);
    uint32 unit_len = sizeof(dms_ctrl_info_t);
    dms_ctrl_info_t *ctrl_info = NULL;
    int ret;

    while (offset + unit_len <= req_rebuild->offset) {
        ctrl_info = (dms_ctrl_info_t *)((uint8 *)req_rebuild + offset);
        offset += unit_len;

        ret = dms_reform_proc_page_rebuild(ctrl_info, inst_id);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DRC][%s]dms_reform_proc_page_rebuild", cm_display_pageid(ctrl_info->pageid));
            break;
        }
    }
    dms_reform_ack_req_rebuild(ctx, receive_msg, ret);
}

int dms_reform_req_rebuild_lock(msg_command_t cmd, void *local_lock, uint32 append_size, uint8 master_id)
{
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[master_id];
    int ret = DMS_SUCCESS;

    // if NULL, init req_rebuild
    if (req_rebuild == NULL) {
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }
        rebuild_info->rebuild_data[master_id] = req_rebuild;
        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, cmd, 0, g_dms.inst_id, master_id, reform_ctx->sess_proc,
            CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }

    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, g_dms.reform_ctx.sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    errno_t err = memcpy_s((uint8 *)req_rebuild + req_rebuild->offset, append_size, local_lock, append_size);
    DMS_SECUREC_CHECK(err);
    req_rebuild->offset += append_size;

    return DMS_SUCCESS;
}

int dms_reform_req_rebuild_lock_parallel(msg_command_t cmd, void *local_lock, uint32 append_size, uint8 master_id,
    uint8 thread_index)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)parallel->data[master_id];
    int ret = DMS_SUCCESS;

    // if NULL, init req_rebuild
    if (req_rebuild == NULL) {
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(parallel->handle,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }
        parallel->data[master_id] = req_rebuild;
        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, cmd, 0, g_dms.inst_id, master_id, parallel->sess_id,
            CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }

    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, parallel->sess_id);
        DMS_RETURN_IF_ERROR(ret);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    errno_t err = memcpy_s((uint8 *)req_rebuild + req_rebuild->offset, append_size, local_lock, append_size);
    DMS_SECUREC_CHECK(err);
    req_rebuild->offset += append_size;

    return DMS_SUCCESS;
}

void dms_reform_proc_req_lock_rebuild_base(dms_process_context_t *ctx, dms_message_t *receive_msg,
    uint32 entry_size, dms_reform_proc_lock_info_rebuild proc)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_rebuild_t), CM_TRUE);
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)receive_msg->buffer;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, req_rebuild->offset, CM_TRUE);

    if (!dms_reform_check_judge_time(&req_rebuild->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_MES_INVALID_MSG, "fail to check judge time");
        return;
    }

    uint8 inst_id = req_rebuild->head.src_inst;
    uint32 offset = (uint32)sizeof(dms_reform_req_rebuild_t);

    uint8 *lock_info;
    int ret;

    while (offset + entry_size <= req_rebuild->offset) {
        lock_info = (uint8 *)req_rebuild + offset;
        offset += entry_size;
        ret = proc(lock_info, inst_id);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DRC]dms_reform_proc_req_rebuild_lock, myid:%u", g_dms.inst_id);
            break;
        }
    }
    dms_reform_ack_req_rebuild(ctx, receive_msg, ret);
}

int dms_reform_proc_local_lock_res_rebuild(void *lock_info, uint8 src_inst)
{
    drc_local_lock_res_t *lock_res = (drc_local_lock_res_t *)lock_info;
    int ret = dms_reform_proc_lock_rebuild(&lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE,
        lock_res->latch_stat.lock_mode, src_inst);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]dms_reform_proc_local_lock_res_rebuild, myid:%u", g_dms.inst_id);
    }
    return ret;
}

void dms_reform_proc_req_lock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    dms_reform_proc_req_lock_rebuild_base(ctx, receive_msg, sizeof(drc_local_lock_res_t),
        dms_reform_proc_local_lock_res_rebuild);
}

int dms_reform_proc_tlock_rebuild(void *lock_info, uint8 src_inst)
{
    dms_tlock_info_t *tlock = (dms_tlock_info_t *)lock_info;
    int ret = dms_reform_proc_lock_rebuild(&tlock->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, tlock->lock_mode,
        src_inst);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]dms_reform_proc_tlock_rebuild, myid:%u", g_dms.inst_id);
    }
    return ret;
}

void dms_reform_proc_req_tlock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    dms_reform_proc_req_lock_rebuild_base(ctx, receive_msg, sizeof(dms_tlock_info_t),
        dms_reform_proc_tlock_rebuild);
}

void dms_reform_proc_req_page(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    /* pass */
}

void dms_reform_init_req_switchover(dms_reform_req_switchover_t *req, uint8 reformer_id, uint16 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&req->head, MSG_REQ_SWITCHOVER, 0, g_dms.inst_id, reformer_id, sess_id, CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_switchover_t);
    req->start_time = reform_info->start_time;
}

static void dms_reform_ack_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ack_common.start_time = reform_info->start_time;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_reform_req_switchover_t), CM_TRUE);
    dms_reform_req_switchover_t *req = (dms_reform_req_switchover_t *)receive_msg->head;

    if (!DMS_IS_REFORMER) {
        dms_reform_ack_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_REFORMER);
        return;
    }

    // if switchover request come from self, return error
    if (dms_dst_id_is_self(req->head.src_inst)) {
        dms_reform_ack_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
        return;
    }

    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        switchover_info->switch_req = CM_TRUE;
        switchover_info->inst_id = req->head.src_inst;
        switchover_info->sess_id = req->head.src_sid;
        switchover_info->start_time = req->start_time;
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_switchover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    if (switchover_info->inst_id == req->head.src_inst &&
        switchover_info->sess_id == req->head.src_sid &&
        switchover_info->start_time == req->start_time) {
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_switchover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    cm_spin_unlock(&switchover_info->lock);
    dms_reform_ack_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
}

int dms_reform_req_switchover_wait(uint64 ruid, uint64 *start_time)
{
    dms_message_t res;
    int result = DMS_SUCCESS;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    result = ack_common->result;
    *start_time = ack_common->start_time;
    mfc_release_response(&res);
    return result;
}

void dms_reform_proc_reform_done_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_message_head_t), CM_TRUE);

    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_ack_common_t ack_common = { 0 };

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);

    if (!reform_info->reform_done) {
        ack_common.result = ERRNO_DMS_REFORM_NOT_FINISHED;
    } else {
        ack_common.result = DMS_SUCCESS;
    }
    int ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

static void dms_reform_init_req_check_reform_done(dms_message_head_t *head, uint8 dst_id)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_CHECK_REFORM_DONE, 0, g_dms.inst_id, dst_id, reform_context->sess_proc,
                          CM_INVALID_ID16);
    head->size = sizeof(dms_message_head_t);
}

static int dms_reform_req_check_reform_done_wait(uint8 dst_id, uint64 ruid)
{
    dms_message_t res;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_req_check_reform_done_wait error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }
    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    ret = ack_common->result;
    mfc_release_response(&res);
    return ret;
}

static int dms_reform_check_reform_done_r(uint8 dst_id)
{
    dms_message_head_t head;
    int ret = DMS_SUCCESS;
    while (CM_TRUE) {
        dms_reform_init_req_check_reform_done(&head, dst_id);

        ret = mfc_send_data(&head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_reform_done SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_check_reform_done_wait(dst_id, head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_check_reform_done WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }
    return ret;
}

int dms_reform_check_reform_done(void)
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
        ret = dms_reform_check_reform_done_r(dst_id);
        if (ret != DMS_SUCCESS) {
            if (ret == ERRNO_DMS_REFORM_NOT_FINISHED) {
                LOG_DEBUG_WAR("[DMS REFORM]dms_reform_check_reform_done WAIT, the dest instance has not finish "
                              "reform, need wait, dst_id: %d", dst_id);
                DMS_REFORM_SHORT_SLEEP;
            } else {
                LOG_DEBUG_WAR("[DMS REFORM]dms_reform_check_reform_done error: %d, dst_id:%d", ret, dst_id);
            }
            return ret;
        }
    }
    LOG_DEBUG_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

void dms_reform_init_map_info_req(dms_message_head_t *head, uint8 dst_id)
{
    reform_context_t *ctx = DMS_REFORM_CONTEXT;

    DMS_INIT_MESSAGE_HEAD(head, MSG_REQ_MAP_INFO, 0, g_dms.inst_id, dst_id, ctx->sess_judge, CM_INVALID_ID16);
    head->size = (uint16)sizeof(dms_message_head_t);
}

int dms_reform_map_info_req_wait(uint64 ruid)
{
    dms_message_t res;
    int ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_map_t *ack_map = (dms_reform_ack_map_t *)res.buffer;
    remaster_info_t remaster_info = ack_map->remaster_info;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    mfc_release_response(&res);

    uint32 size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
    errno_t err = memcpy_s(part_mngr->inst_part_tbl, size, remaster_info.inst_part_tbl, size);
    DMS_SECUREC_CHECK(err);

    size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
    err = memcpy_s(part_mngr->part_map, size, remaster_info.part_map, size);
    DMS_SECUREC_CHECK(err);

    err = memcpy_s(ctx->deposit_map, DMS_MAX_INSTANCES, remaster_info.deposit_map, DMS_MAX_INSTANCES);
    DMS_SECUREC_CHECK(err);

    return DMS_SUCCESS;
}

void dms_reform_proc_map_info_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_message_head_t), CM_TRUE);

    errno_t err;
    dms_reform_ack_map_t ack_map;
    err = memset_s(&ack_map, sizeof(dms_reform_ack_map_t), 0, sizeof(dms_reform_ack_map_t));
    DMS_SECUREC_CHECK(err);
    remaster_info_t *remaster_info = &ack_map.remaster_info;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    dms_init_ack_head(receive_msg->head, &ack_map.head, MSG_ACK_MAP_INFO, sizeof(dms_reform_ack_map_t),
        process_ctx->sess_id);

    uint32 size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
    err = memcpy_s(remaster_info->inst_part_tbl, size, part_mngr->inst_part_tbl, size);
    DMS_SECUREC_CHECK(err);

    size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
    err = memcpy_s(remaster_info->part_map, size, part_mngr->part_map, size);
    DMS_SECUREC_CHECK(err);

    err = memcpy_s(remaster_info->deposit_map, DMS_MAX_INSTANCES, ctx->deposit_map, DMS_MAX_INSTANCES);
    DMS_SECUREC_CHECK(err);

    int ret = mfc_send_data(&ack_map.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

int dms_reform_req_opengauss_ondemand_redo_buffer(dms_context_t *dms_ctx, void *block_key, unsigned int key_len,
    int *redo_status)
{
    dms_reform_req_opengauss_ondemand_redo_t redo_req;
    dms_xmap_ctx_t *xmap_ctx = &dms_ctx->xmap_ctx;
    dms_message_t message = { 0 };

    DMS_INIT_MESSAGE_HEAD(&redo_req.head, MSG_REQ_OPENGAUSS_ONDEMAND_REDO, 0, dms_ctx->inst_id,
        xmap_ctx->dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    redo_req.head.size = (uint16)(key_len + sizeof(dms_reform_req_opengauss_ondemand_redo_t));
    redo_req.len = (uint16)key_len;

    // openGauss has not adapted stats yet
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_ONDEMAND_REDO, CM_TRUE);
    int32 ret = mfc_send_data3(&redo_req.head, sizeof(dms_reform_req_opengauss_ondemand_redo_t), block_key);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);
        LOG_DEBUG_ERR("[On-demand][request openGauss on-demand redo failed] src_inst %u src_sid %u dst_inst %u",
            dms_ctx->inst_id, dms_ctx->sess_id, xmap_ctx->dest_id);
        return ret;
    }

    ret = mfc_get_response(redo_req.head.ruid, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        dms_end_stat(dms_ctx->sess_id);

        LOG_DEBUG_ERR("[On-demand] receive message to instance(%u) failed, cmd(%u) ruid(%llu) errcode(%d)",
            xmap_ctx->dest_id, (uint32)MSG_REQ_OPENGAUSS_ONDEMAND_REDO, redo_req.head.ruid, ret);
        return ret;
    }

    dms_end_stat(dms_ctx->sess_id);

    CM_CHK_RESPONSE_SIZE(&message, (uint32)(sizeof(dms_message_head_t) + sizeof(int32)), CM_FALSE);
    *redo_status = *(int *)(message.buffer + sizeof(dms_message_head_t));

    mfc_release_response(&message);
    return DMS_SUCCESS;
}

void dms_reform_proc_opengauss_ondemand_redo_buffer(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    dms_message_head_t *req_head = receive_msg->head;
    dms_message_head_t ack_head;
    int32 redo_status;
    void *block_key;

    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_opengauss_ondemand_redo_t),
        CM_TRUE);
    dms_reform_req_opengauss_ondemand_redo_t *req = (dms_reform_req_opengauss_ondemand_redo_t *)(receive_msg->buffer);
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)(sizeof(dms_reform_req_opengauss_ondemand_redo_t) + req->len),
        CM_TRUE);

    block_key = (void *)(receive_msg->buffer + sizeof(dms_reform_req_opengauss_ondemand_redo_t));
    g_dms.callback.opengauss_ondemand_redo_buffer(block_key, &redo_status);

    dms_init_ack_head(req_head, &ack_head, MSG_ACK_OPENGAUSS_ONDEMAND_REDO, sizeof(int32) + sizeof(dms_message_head_t),
        process_ctx->sess_id);

    if (mfc_send_data3(&ack_head, sizeof(dms_message_head_t), &redo_status) != CM_SUCCESS) {
        LOG_DEBUG_ERR(
            "[On-demand] send openGauss on-demand redo status ack message failed, src_inst = %u, dst_inst = %u",
            (uint32)ack_head.src_inst, (uint32)ack_head.dst_inst);
    }
}

// only for message used in reform, because share_info will be cleaned in dms_reform_end
void dms_reform_set_judge_time(dms_message_head_t *req_head)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    req_head->judge_time = share_info->judge_time;
}

// only for message used in reform, because share_info will be cleaned in dms_reform_end
bool32 dms_reform_check_judge_time(dms_message_head_t *req_head)
{
    if (req_head->msg_proto_ver >= DMS_PROTO_VER_2) {
        share_info_t *share_info = DMS_SHARE_INFO;
        return req_head->judge_time == share_info->judge_time;
    } else {
        return CM_TRUE;
    }
}

#define DMS_REFORM_REQ_GROUP_INIT_OFFSET(req_group)                         \
    do {                                                                    \
        (req_group)->offset = (uint32)sizeof(dms_reform_req_group_t);       \
    } while (0)

#define DMS_REFORM_REQ_GROUP_IS_INIT_OFFSET(req_group)                      \
    ((req_group)->offset == (uint32)sizeof(dms_reform_req_group_t))

static dms_reform_req_group_t *dms_reform_req_group_get_buffer(msg_command_t cmd, uint8 dst_id, uint8 thread_index,
    uint32 *sess_id)
{
    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        reform_context_t *ctx = DMS_REFORM_CONTEXT;
        dms_reform_req_group_t *buffer = (dms_reform_req_group_t *)rebuild_info->rebuild_data[dst_id];
        *sess_id = ctx->sess_proc;
        if (buffer == NULL) {
            buffer = (dms_reform_req_group_t *)g_dms.callback.mem_alloc(ctx->handle_proc, DMS_REFORM_MSG_MAX_LENGTH);
            rebuild_info->rebuild_data[dst_id] = buffer;
            DMS_INIT_MESSAGE_HEAD(&buffer->head, cmd, 0, g_dms.inst_id, dst_id, *sess_id, CM_INVALID_ID16);
            dms_reform_set_judge_time(&buffer->head);
            DMS_REFORM_REQ_GROUP_INIT_OFFSET(buffer);
            buffer->head.size = DMS_REFORM_MSG_MAX_LENGTH;
        }
        return buffer;
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
        dms_reform_req_group_t *buffer = (dms_reform_req_group_t *)parallel->data[dst_id];
        *sess_id = parallel->sess_id;
        if (buffer == NULL) {
            buffer = (dms_reform_req_group_t *)g_dms.callback.mem_alloc(parallel->handle, DMS_REFORM_MSG_MAX_LENGTH);
            parallel->data[dst_id] = buffer;
            DMS_INIT_MESSAGE_HEAD(&buffer->head, cmd, 0, g_dms.inst_id, dst_id, *sess_id, CM_INVALID_ID16);
            dms_reform_set_judge_time(&buffer->head);
            DMS_REFORM_REQ_GROUP_INIT_OFFSET(buffer);
            buffer->head.size = DMS_REFORM_MSG_MAX_LENGTH;
        }
        return buffer;
    }
}

int dms_reform_req_group(msg_command_t cmd, uint8 dst_id, uint8 thread_index, void *data, uint32 data_len)
{
    int ret = DMS_SUCCESS;
    uint32 sess_id = 0;
    dms_reform_req_group_t *buffer = dms_reform_req_group_get_buffer(cmd, dst_id, thread_index, &sess_id);
    if (buffer == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    if (buffer->offset + data_len > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&buffer->head, sess_id);
        DMS_RETURN_IF_ERROR(ret);
        DMS_REFORM_REQ_GROUP_INIT_OFFSET(buffer);
    }

    ret = memcpy_s((uint8 *)buffer + buffer->offset, DMS_REFORM_MSG_MAX_LENGTH - buffer->offset, data, data_len);
    DMS_SECUREC_CHECK(ret);
    buffer->offset += data_len;

    return DMS_SUCCESS;
}

int dms_reform_req_group_send_rest(uint8 thread_index)
{
    dms_reform_req_group_t *buffer = NULL;
    int ret = DMS_SUCCESS;

    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        reform_context_t *ctx = DMS_REFORM_CONTEXT;
        for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
            buffer = (dms_reform_req_group_t *)rebuild_info->rebuild_data[i];
            if (buffer == NULL) {
                continue;
            }

            if (!DMS_REFORM_REQ_GROUP_IS_INIT_OFFSET(buffer)) {
                ret = dms_reform_send_data(&buffer->head, ctx->sess_proc);
                DMS_RETURN_IF_ERROR(ret);
                DMS_REFORM_REQ_GROUP_INIT_OFFSET(buffer);
            }
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
        for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
            buffer = (dms_reform_req_group_t *)parallel->data[i];
            if (buffer == NULL) {
                continue;
            }

            if (!DMS_REFORM_REQ_GROUP_IS_INIT_OFFSET(buffer)) {
                ret = dms_reform_send_data(&buffer->head, parallel->sess_id);
                DMS_RETURN_IF_ERROR(ret);
                DMS_REFORM_REQ_GROUP_INIT_OFFSET(buffer);
            }
        }
    }

    return DMS_SUCCESS;
}

void dms_reform_req_group_init(uint8 thread_index)
{
    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            rebuild_info->rebuild_data[i] = NULL;
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            parallel->data[i] = NULL;
        }
    }
}

void dms_reform_req_group_free(uint8 thread_index)
{
    if (thread_index == CM_INVALID_ID8) {
        rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
        reform_context_t *ctx = DMS_REFORM_CONTEXT;
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            if (rebuild_info->rebuild_data[i] != NULL) {
                g_dms.callback.mem_free(ctx->handle_proc, rebuild_info->rebuild_data[i]);
                rebuild_info->rebuild_data[i] = NULL;
            }
        }
    } else {
        parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
        parallel_thread_t *parallel = &parallel_info->parallel[thread_index];
        for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
            if (parallel->data[i] != NULL) {
                g_dms.callback.mem_free(parallel->handle, parallel->data[i]);
                parallel->data[i] = NULL;
            }
        }
    }
}

void dms_reform_init_req_az_switchover_demote(dms_reform_req_az_switchover_t *req, uint8 reformer_id, uint16 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&req->head, MSG_REQ_AZ_SWITCHOVER_DEMOTE, 0, g_dms.inst_id, reformer_id,
        sess_id, CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_az_switchover_t);
    req->start_time = reform_info->start_time;
}

static void dms_reform_ack_az_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ack_common.start_time = reform_info->start_time;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_az_switchover(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_reform_req_az_switchover_t), CM_TRUE);
    dms_reform_req_az_switchover_t *req = (dms_reform_req_az_switchover_t *)receive_msg->head;

    if (!DMS_IS_REFORMER) {
        dms_reform_ack_az_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_REFORMER);
        return;
    }

    // if switchover request come from self, return error
    if (dms_dst_id_is_self(req->head.src_inst)) {
        dms_reform_ack_az_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
        return;
    }

    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        switchover_info->switch_req = CM_TRUE;
        switchover_info->inst_id = req->head.src_inst;
        switchover_info->sess_id = req->head.src_sid;
        switchover_info->start_time = req->start_time;
        switchover_info->switch_type = AZ_SWITCHOVER;
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_az_switchover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    if (switchover_info->inst_id == req->head.src_inst &&
        switchover_info->sess_id == req->head.src_sid &&
        switchover_info->start_time == req->start_time) {
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_az_switchover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    cm_spin_unlock(&switchover_info->lock);
    dms_reform_ack_az_switchover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
}

int dms_reform_req_az_switchover_wait(uint64 ruid, uint64 *start_time)
{
    dms_message_t res;
    int result = DMS_SUCCESS;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    result = ack_common->result;
    *start_time = ack_common->start_time;
    mfc_release_response(&res);
    return result;
}

void dms_reform_init_req_az_failover(dms_reform_req_az_failover_t *req, uint8 reformer_id, uint16 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&req->head, MSG_REQ_AZ_FAILOVER, 0, g_dms.inst_id, reformer_id, sess_id, CM_INVALID_ID16);
    req->head.size = (uint16)sizeof(dms_reform_req_az_failover_t);
    req->start_time = reform_info->start_time;
}

static void dms_reform_ack_az_failover(dms_process_context_t *process_ctx, dms_message_t *receive_msg, int result)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_ack_common_t ack_common;
    int ret = DMS_SUCCESS;

    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = result;
    ack_common.start_time = reform_info->start_time;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }
}

void dms_reform_proc_req_az_failover(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, sizeof(dms_reform_req_az_failover_t), CM_TRUE);
    dms_reform_req_az_failover_t *req = (dms_reform_req_az_failover_t *)receive_msg->head;

    if (!DMS_IS_REFORMER) {
        dms_reform_ack_az_failover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_REFORMER);
        return;
    }

    // if switchover request come from self, return error
    if (dms_dst_id_is_self(req->head.src_inst)) {
        dms_reform_ack_az_failover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
        return;
    }

    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        switchover_info->switch_req = CM_TRUE;
        switchover_info->inst_id = req->head.src_inst;
        switchover_info->sess_id = req->head.src_sid;
        switchover_info->start_time = req->start_time;
        switchover_info->switch_type = AZ_FAILOVER;
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_az_failover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    if (switchover_info->inst_id == req->head.src_inst &&
        switchover_info->sess_id == req->head.src_sid &&
        switchover_info->start_time == req->start_time) {
        cm_spin_unlock(&switchover_info->lock);
        dms_reform_ack_az_failover(process_ctx, receive_msg, DMS_SUCCESS);
        return;
    }

    cm_spin_unlock(&switchover_info->lock);
    dms_reform_ack_az_failover(process_ctx, receive_msg, ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED);
    return;
}

int dms_reform_req_az_failover_wait(uint64 ruid, uint64 *start_time)
{
    dms_message_t res;
    int result = DMS_SUCCESS;
    int ret = DMS_SUCCESS;

    ret = mfc_get_response(ruid, &res, DMS_WAIT_MAX_TIME);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_ack_common_t *ack_common = (dms_reform_ack_common_t *)res.buffer;
    result = ack_common->result;
    *start_time = ack_common->start_time;
    mfc_release_response(&res);
    return result;
}

static int dms_reform_proc_repair_inner(dms_process_context_t *process_ctx, repair_item_t *item)
{
    int ret = DMS_SUCCESS;
    switch (item->action) {
        case DMS_REQ_FLUSH_COPY:
            ret = g_dms.callback.flush_copy(process_ctx->db_handle, item->page_id);
            break;

        default:
            CM_ASSERT(CM_FALSE);
            break;
    }
    return ret;
}

void dms_reform_proc_repair(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_group_t), CM_TRUE);
    dms_reform_req_group_t *buffer = (dms_reform_req_group_t *)receive_msg->buffer;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, buffer->offset, CM_TRUE);

    if (!dms_reform_check_judge_time(&buffer->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        cm_send_error_msg(receive_msg->head, ERRNO_DMS_MES_INVALID_MSG, "fail to check judge time");
        return;
    }

    uint32 offset = (uint32)sizeof(dms_reform_req_group_t);
    repair_item_t *item = NULL;
    int ret = DMS_SUCCESS;
    while (offset + sizeof(repair_item_t) <= buffer->offset) {
        item = (repair_item_t *)((uint8 *)buffer + offset);
        offset += (uint32)sizeof(repair_item_t);
        ret = dms_reform_proc_repair_inner(process_ctx, item);
        DMS_BREAK_IF_ERROR(ret);
    }

    dms_reform_ack_common_t ack_common;
    dms_init_ack_head(receive_msg->head, &ack_common.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_common.result = ret;
    ret = mfc_send_data(&ack_common.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_proc_repair_new ack fail, error: %d", ret);
    }
}