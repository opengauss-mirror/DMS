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
 * dcs_dc.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_dc.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_dc.h"
#include "dcs_msg.h"
#include "dms_msg_command.h"
#include "dms_msg_protocol.h"
#include "dms_error.h"
#include "dms_api.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define DCS_BROADCAST_OUTPUT_MSG_LEN ((int)128)

void dcs_proc_broadcast_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_message_head_t), CM_TRUE);
    uint32 output_msg_len = 0;
    char output_msg[DCS_BROADCAST_OUTPUT_MSG_LEN] = {0};
    dms_message_head_t *head = (dms_message_head_t *)(receive_msg->buffer);
    LOG_DEBUG_INF("Receive broadcast, cmd: %d", head->cmd);
    char *data = receive_msg->buffer + sizeof(dms_message_head_t);
    uint32 len = (uint32)(head->size - sizeof(dms_message_head_t));
    dms_broadcast_context_t broad_ctx = {.data = data, .len = len, .output_msg = output_msg,
        .output_msg_len = &output_msg_len};
    int32 ret = g_dms.callback.process_broadcast(process_ctx->db_handle, &broad_ctx);
    if (output_msg_len != 0) {
        char ack_buf[DCS_BROADCAST_OUTPUT_MSG_LEN + sizeof(dms_message_head_t)];
        cm_ack_result_msg2(process_ctx, receive_msg, MSG_ACK_BROADCAST_WITH_MSG, output_msg, output_msg_len, ack_buf);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BROADCAST, ret);
    }
    LOG_DEBUG_INF("Succeed to send ack to inst %u", receive_msg->head->src_inst);
}

static int dcs_handle_broadcast_msg(dms_context_t *dms_ctx, mes_msg_list_t *recv_msg)
{
    uint32 i;
    uint32 len;
    char *data;
    int ret;
    dms_message_head_t *head;

    for (i = 0; i < recv_msg->count; i++) {
        head = (dms_message_head_t *)recv_msg->messages[i].buffer;
        data = recv_msg->messages[i].buffer + sizeof(dms_message_head_t);
        len = (uint32)(head->size - sizeof(dms_message_head_t));
        dms_broadcast_context_t broad_ctx = {.data = data, .len = len};
        ret = g_dms.callback.process_broadcast_ack(dms_ctx->db_handle, &broad_ctx);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }
    return DMS_SUCCESS;
}

static int dcs_recv_and_handle_broadcast_msg(dms_context_t *dms_ctx, uint32 timeout, uint64 ruid,
    uint64 expect_inst)
{
    int ret;
    mes_msg_list_t recv_msg = { 0 };

    ret = mfc_get_broadcast_res_with_msg(ruid, timeout, expect_inst, &recv_msg);
    if (ret == DMS_SUCCESS) {
        ret = dcs_handle_broadcast_msg(dms_ctx, &recv_msg);
        mfc_release_broadcast_response(&recv_msg);
    }
    return ret;
}

static int dms_broadcast_msg_internal(dms_context_t *dms_ctx, char *data, uint32 len, uint32 timeout, bool8 handle_msg,
    msg_command_t cmd, dms_broadcast_scope_e scope)
{
    uint64 succ_inst = 0;
    dms_message_head_t head;
    int ret = DMS_SUCCESS;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    cm_panic_log(scope < DMS_BROADCAST_TYPE_COUNT, "Invalid scope: %d, when dms broadcast msg internal", scope);

    DMS_INIT_MESSAGE_HEAD(&head, cmd, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);
    head.size = (uint16)(sizeof(dms_message_head_t) + len);

    uint64 all_inst = (scope == DMS_BROADCAST_ONLINE_LIST) ? reform_info->bitmap_connect : reform_info->bitmap_in;
#ifdef OPENGAUSS
    all_inst = g_dms.enable_reform ? all_inst : g_dms.inst_map;
#endif
    all_inst = all_inst & (~((uint64)0x1 << (dms_ctx->inst_id))); // exclude self
    mfc_broadcast2(all_inst, &head, (const void *)data, &succ_inst);
    LOG_DEBUG_INF("Send broadcast cmd: %d, all inst: %llu, expect succ inst: %llu", cmd, all_inst, succ_inst);
    if (!handle_msg) {
        ret = mfc_get_broadcast_res_with_succ_insts(head.ruid, timeout, all_inst, &succ_inst);
    } else {
        mes_msg_list_t recv_msg = { 0 };
        int32 ret = mfc_get_broadcast_res_with_msg(head.ruid, timeout, succ_inst, &recv_msg);
        if (ret == DMS_SUCCESS) {
            LOG_DEBUG_INF("Succeed to receive broadcast ack of all nodes");
            ret = dcs_handle_broadcast_msg(dms_ctx, &recv_msg);
            mfc_release_broadcast_response(&recv_msg);
        }
    }
    if (ret != DMS_SUCCESS) {
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED);
    }
    return ret;
}

int dms_broadcast_msg_with_cmd(dms_context_t *dms_ctx, char *data, unsigned int len, unsigned char handle_recv_msg,
    unsigned int timeout, msg_command_t cmd, dms_broadcast_scope_e scope)
{
    int ret = DMS_SUCCESS;

    if (timeout != CM_INFINITE_TIMEOUT) {
        ret = dms_broadcast_msg_internal(dms_ctx, data, len, timeout, handle_recv_msg, cmd, scope);
        return ret;
    }

    while (CM_TRUE) {
        if (dms_broadcast_msg_internal(dms_ctx, data, len, DMS_WAIT_MAX_TIME, handle_recv_msg, cmd, scope) == DMS_SUCCESS) {
            return DMS_SUCCESS;
        }
#ifndef OPENGAUSS
        if (g_dms.callback.check_session_invalid(dms_ctx->sess_id)) {
            LOG_RUN_INF("[DCS] session %u is killed or canneled during the broadcast process.", dms_ctx->sess_id);
            return DMS_ERROR;
        }
#endif
        cm_sleep(DMS_MSG_RETRY_TIME);
    }
}

int dms_broadcast_msg_with_scope(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, dms_broadcast_scope_e scope)
{
    dms_reset_error();
    return dms_broadcast_msg_with_cmd(dms_ctx, data, len, handle_recv_msg, timeout, MSG_REQ_BROADCAST, scope);
}

int dms_broadcast_msg(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout)
{
    dms_reset_error();
    return dms_broadcast_msg_with_cmd(dms_ctx, data, len, handle_recv_msg, timeout, MSG_REQ_BROADCAST,
        DMS_BROADCAST_ONLINE_LIST);
}

void dcs_proc_boc(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifdef OPENGAUSS
    cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BOC, DMS_ERROR);
#else
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dcs_boc_req_t), CM_TRUE);
    dcs_boc_req_t *boc_req = (dcs_boc_req_t *)(receive_msg->buffer);
    if (boc_req->inst_id >= DMS_MAX_INSTANCES) {
        LOG_DEBUG_ERR("[DCS]%s instance id %u is invalid", __FUNCTION__, boc_req->inst_id);
        return;
    }
    g_dms.callback.update_global_scn(process_ctx->db_handle, boc_req->commit_scn);
    (void)cm_atomic_set((atomic_t *)&(g_dms.min_scn[boc_req->inst_id]), (int64)boc_req->min_scn);
    cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BOC, DMS_SUCCESS);
#endif
    return;
}

int dms_send_bcast(dms_context_t *dms_ctx, void *data, unsigned int len, unsigned long long *success_inst,
    unsigned long long *ruid)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_message_head_t head;

    DMS_INIT_MESSAGE_HEAD(&head, MSG_REQ_BROADCAST, 0, dms_ctx->inst_id, 0,  dms_ctx->sess_id, CM_INVALID_ID16);
    head.size = (uint16)(sizeof(dms_message_head_t) + len);
    uint64 all_inst = reform_info->bitmap_connect;
#ifdef OPENGAUSS
    all_inst = g_dms.enable_reform ? all_inst : g_dms.inst_map;
#endif
    all_inst = all_inst & (~((uint64)0x1 << (dms_ctx->inst_id)));
    mfc_broadcast2(all_inst, &head, (const void *)data, success_inst);
    *ruid = head.ruid;
    if (*success_inst == all_inst) {
        return DMS_SUCCESS;
    }
    DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED, all_inst, *success_inst);
    return DMS_ERROR;
}

int dms_wait_bcast(unsigned long long ruid, unsigned int inst_id, unsigned int timeout, unsigned long long *success_inst)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint64 all_inst = reform_info->bitmap_connect;
#ifdef OPENGAUSS
    all_inst = g_dms.enable_reform ? all_inst : g_dms.inst_map;
#endif
    all_inst = all_inst & (~((uint64)0x1 << inst_id));
    int ret = mfc_get_broadcast_res_with_succ_insts(ruid, timeout, all_inst, success_inst);
    if (ret != DMS_SUCCESS) {
        DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret);
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED, all_inst, *success_inst);
        return DMS_ERROR;
    }
    return ret;
}

int dms_send_boc(dms_context_t *dms_ctx, unsigned long long commit_scn, unsigned long long min_scn,
    unsigned long long *success_inst, unsigned long long *ruid)
{
    dms_reset_error();
    dcs_boc_req_t boc_req;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    DMS_INIT_MESSAGE_HEAD(&boc_req.head, MSG_REQ_BOC, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);
    boc_req.head.size = (uint16)sizeof(dcs_boc_req_t);
    boc_req.commit_scn = commit_scn;
    boc_req.min_scn = min_scn;
    boc_req.inst_id = dms_ctx->inst_id;

    uint64 all_inst = reform_info->bitmap_connect;
#ifdef OPENGAUSS
    if (!g_dms.enable_reform) {
        all_inst = g_dms.inst_map;
    }
#endif
    uint64 inval_insts = all_inst & (~((uint64)0x1 << (dms_ctx->inst_id)));
    mfc_broadcast(inval_insts, (void *)&boc_req, success_inst);
    *ruid = boc_req.head.ruid;
    if (*success_inst != inval_insts) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BROADCAST_FAILED, inval_insts, *success_inst);
        return ERRNO_DMS_DCS_BROADCAST_FAILED;
    }
    return DMS_SUCCESS;
}

int dms_wait_boc(uint64 ruid, unsigned int timeout, unsigned long long success_inst)
{
    dms_reset_error();
    return mfc_get_broadcast_res(ruid, timeout, success_inst);
}

int dms_broadcast_opengauss_ddllock(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, unsigned char lock_req_type)
{
    dms_reset_error();
    uint64 succ_inst = 0;
    dms_message_head_t head;
    uint16 size = (uint16)(sizeof(dms_message_head_t) + len);
    reform_info_t *reform_info = DMS_REFORM_INFO;
    DMS_INIT_MESSAGE_HEAD(&head, MSG_REQ_OPENGAUSS_DDLLOCK, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);

    head.size = size;

    uint64 all_inst = reform_info->bitmap_connect;
    if (!g_dms.enable_reform) {
        all_inst = g_dms.inst_map;
    }   

    uint64 invld_insts = 0;
    switch ((dms_opengauss_lock_req_type_t)lock_req_type) {
        case SHARED_INVAL_MSG:
        case DROP_BUF_MSG:
        case LOCK_NORMAL_MODE: {
            /* normal case, send to all normal nodes exclude self and in recovery */
            share_info_t *share_info = DMS_SHARE_INFO;
            invld_insts = (all_inst & (~(share_info->bitmap_recovery))) & (~((uint64)0x1 << (dms_ctx->inst_id)));
            break;
        }
        case LOCK_RELEASE_SELF: {
            /* only send to self for release the lock of my own */
            invld_insts = (uint64)0x1 << (dms_ctx->inst_id);
            break;
        }
        case LOCK_REACQUIRE: {
            /* only send to the nodes which new joined or recoveryed or rebooted */
            share_info_t *share_info = DMS_SHARE_INFO;
            invld_insts = share_info->bitmap_recovery;
            break;
        }
        default:
            LOG_DEBUG_ERR("[DMS][dms_broadcast_opengauss_ddllock]unknow lock req type");
            break;
    }

    mfc_broadcast2(invld_insts, &head, (const void *)data, &succ_inst);

    if (!handle_recv_msg && timeout > 0) {
        return mfc_get_broadcast_res(head.ruid, timeout, succ_inst);
    } else {
        return dcs_recv_and_handle_broadcast_msg(dms_ctx, timeout, head.ruid, succ_inst);
    }
}

int dms_broadcast_ddl_sync_msg(dms_context_t *dms_ctx, char *data, unsigned int len, unsigned char handle_recv_msg,
    unsigned int timeout, dms_broadcast_scope_e scope)
{
    dms_reset_error();
    return dms_broadcast_msg_with_cmd(dms_ctx, data, len, handle_recv_msg, timeout, MSG_REQ_DDL_SYNC, scope);
}

#ifdef __cplusplus
}
#endif
