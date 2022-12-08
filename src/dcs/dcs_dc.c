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
#include "dms_msg.h"
#include "dms_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DCS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)
#define DCS_BROADCAST_OUTPUT_MSG_LEN ((int)128)

void dcs_proc_broadcast_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    cm_latch_s(&reform_info->bcast_latch, process_ctx->sess_id, CM_FALSE, NULL);
    if (reform_info->bcast_unable) {
        cm_unlatch(&reform_info->bcast_latch, NULL);
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BROADCAST, ERRNO_DMS_REFORM_IN_PROCESS);
        return;
    }

    uint32 output_msg_len = 0;
    char output_msg[DCS_BROADCAST_OUTPUT_MSG_LEN] = {0};
    mes_message_head_t *head = (mes_message_head_t *)(receive_msg->buffer);

    char *data = receive_msg->buffer + sizeof(mes_message_head_t);
    uint32 len = (uint32)(head->size - sizeof(mes_message_head_t));
    int32 ret = g_dms.callback.process_broadcast(process_ctx->db_handle, data, len, output_msg, &output_msg_len);
    cm_unlatch(&reform_info->bcast_latch, NULL);
    if (output_msg_len != 0) {
        char ack_buf[DCS_BROADCAST_OUTPUT_MSG_LEN + sizeof(mes_message_head_t)];
        cm_ack_result_msg2(process_ctx, receive_msg, MSG_ACK_BROADCAST_WITH_MSG, output_msg, output_msg_len, ack_buf);
    } else {
        cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BROADCAST, ret);
    }
}

static int dcs_handle_broadcast_msg(dms_context_t *dms_ctx, uint64 succ_inst, char *recv_msg[CM_MAX_INSTANCES])
{
    uint32 i;
    uint32 len;
    char *data;
    int ret;
    mes_message_head_t *head;

    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        if (DCS_IS_INST_SEND(succ_inst, i) && recv_msg[i] != NULL) {
            head = (mes_message_head_t *)recv_msg[i];
            data = recv_msg[i] + sizeof(mes_message_head_t);
            len = (uint32)(head->size - sizeof(mes_message_head_t));
            ret = g_dms.callback.process_broadcast_ack(dms_ctx->db_handle, data, len);
            if (ret != DMS_SUCCESS) {
                return ret;
            }
        }
    }
    return DMS_SUCCESS;
}

static void dcs_release_broadcast_msg(dms_context_t *dms_ctx, uint64 succ_inst, char *recv_msg[CM_MAX_INSTANCES])
{
    uint32 i;
    mes_message_t msg;
    for (i = 0; i < CM_MAX_INSTANCES; i++) {
        if (DCS_IS_INST_SEND(succ_inst, i) && recv_msg[i] != NULL) {
            msg.buffer = recv_msg[i];
            msg.head = (mes_message_head_t *)recv_msg[i];
            mfc_release_message_buf(&msg);
        }
    }
}

static int dcs_handle_recv_broadcast_msg(dms_context_t *dms_ctx, uint64 succ_inst, uint32 timeout)
{
    int ret;
    char *recv_msg[CM_MAX_INSTANCES] = {0};

    ret = mfc_wait_acks_and_recv_msg(dms_ctx->sess_id, timeout, succ_inst, recv_msg);
    if (ret == DMS_SUCCESS) {
        ret = dcs_handle_broadcast_msg(dms_ctx, succ_inst, recv_msg);
    }

    dcs_release_broadcast_msg(dms_ctx, succ_inst, recv_msg);
    return ret;
}

static int dms_broadcast_msg_internal(dms_context_t *dms_ctx, char *data, uint32 len, uint32 timeout, bool8 handle_msg)
{
    uint64 succ_inst = 0;
    mes_message_head_t head;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    MES_INIT_MESSAGE_HEAD(&head, MSG_REQ_BROADCAST, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);
    head.size = (uint16)(sizeof(mes_message_head_t) + len);
    head.rsn = mfc_get_rsn(dms_ctx->sess_id);

    uint64 all_inst = reform_info->bitmap_connect;
#ifdef OPENGAUSS
    all_inst = g_dms.enable_reform ? all_inst : g_dms.inst_map;
#endif
    all_inst = all_inst & (~((uint64)0x1 << (dms_ctx->inst_id))); // exclude self
    mfc_broadcast2(dms_ctx->sess_id, all_inst, &head, (const void *)data, &succ_inst);
    if (!handle_msg) {
        (void)mfc_wait_acks2(dms_ctx->sess_id, timeout, &succ_inst);
        return all_inst == succ_inst ? DMS_SUCCESS : ERRNO_DMS_DCS_BROADCAST_FAILED;
    }

    char *recv_msg[CM_MAX_INSTANCES] = { 0 };
    int32 ret = mfc_wait_acks_and_recv_msg(dms_ctx->sess_id, timeout, succ_inst, recv_msg);
    if (ret != DMS_SUCCESS || all_inst != succ_inst) {
        if (ret == DMS_SUCCESS) {
            dcs_release_broadcast_msg(dms_ctx, succ_inst, recv_msg);
        }
        return ERRNO_DMS_DCS_BROADCAST_FAILED;
    }
    ret = dcs_handle_broadcast_msg(dms_ctx, succ_inst, recv_msg);
    dcs_release_broadcast_msg(dms_ctx, succ_inst, recv_msg);
    return ret;
}

int dms_broadcast_msg(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    cm_latch_s(&reform_info->bcast_latch, dms_ctx->sess_id, CM_FALSE, NULL);
    if (reform_info->bcast_unable) {
        cm_unlatch(&reform_info->bcast_latch, NULL);
        LOG_DEBUG_ERR("[DMS REFORM] broadcast is unable");
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    if (timeout != CM_INFINITE_TIMEOUT) {
        ret = dms_broadcast_msg_internal(dms_ctx, data, len, timeout, handle_recv_msg);
        cm_unlatch(&reform_info->bcast_latch, NULL);
        return ret;
    }

    while (CM_TRUE) {
        if (dms_broadcast_msg_internal(dms_ctx, data, len, DMS_WAIT_MAX_TIME, handle_recv_msg) == DMS_SUCCESS) {
            cm_unlatch(&reform_info->bcast_latch, NULL);
            return DMS_SUCCESS;
        }
        cm_unlatch(&reform_info->bcast_latch, NULL);
        cm_sleep(DMS_MSG_RETRY_TIME);
        cm_latch_s(&reform_info->bcast_latch, dms_ctx->sess_id, CM_FALSE, NULL);
        if (reform_info->bcast_unable) {
            cm_unlatch(&reform_info->bcast_latch, NULL);
            LOG_DEBUG_ERR("[DMS REFORM] broadcast is unable");
            return ERRNO_DMS_REFORM_IN_PROCESS;
        }
    }
}

void dcs_proc_boc(dms_process_context_t *process_ctx, mes_message_t *receive_msg)
{
#ifdef OPENGAUSS
    cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BOC, DMS_ERROR);
#else
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dcs_boc_req_t), CM_TRUE, CM_TRUE);
    dcs_boc_req_t *boc_req = (dcs_boc_req_t *)(receive_msg->buffer);
    g_dms.callback.update_global_scn(process_ctx->db_handle, boc_req->commit_scn);
    (void)cm_atomic_set((atomic_t *)&(g_dms.min_scn[boc_req->inst_id]), (int64)boc_req->min_scn);
    cm_ack_result_msg(process_ctx, receive_msg, MSG_ACK_BOC, DMS_SUCCESS);
#endif
    return;
}

int dms_send_boc(dms_context_t *dms_ctx, unsigned long long commit_scn, unsigned long long min_scn,
    unsigned long long *success_inst)
{
    dcs_boc_req_t boc_req;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    MES_INIT_MESSAGE_HEAD(&boc_req.head, MSG_REQ_BOC, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);
    boc_req.head.size = (uint16)sizeof(dcs_boc_req_t);
    boc_req.head.rsn = mfc_get_rsn(dms_ctx->sess_id);
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
    mfc_broadcast(dms_ctx->sess_id, inval_insts, (const void *)&boc_req, success_inst);
    if (*success_inst != inval_insts) {
        DMS_THROW_ERROR(ERRNO_DMS_DCS_BOC_FAILED, inval_insts, *success_inst);
        return ERRNO_DMS_DCS_BOC_FAILED;
    }
    return DMS_SUCCESS;
}

int dms_wait_boc(unsigned int sid, unsigned int timeout, unsigned long long success_inst)
{
    return mfc_wait_acks(sid, timeout, success_inst);
}

int dms_broadcast_opengauss_ddllock(dms_context_t *dms_ctx, char *data, unsigned int len,
    unsigned char handle_recv_msg, unsigned int timeout, unsigned char lock_req_type)
{
    int32 ret = DMS_SUCCESS;
    uint64 succ_inst = 0;
    mes_message_head_t head;
    uint16 size = (uint16)(sizeof(mes_message_head_t) + len);
    reform_info_t *reform_info = DMS_REFORM_INFO;
    MES_INIT_MESSAGE_HEAD(&head, MSG_REQ_OPENGAUSS_DDLLOCK, 0, dms_ctx->inst_id, 0, dms_ctx->sess_id, CM_INVALID_ID16);

    head.size = size;
    head.rsn = mfc_get_rsn(dms_ctx->sess_id);

    uint64 all_inst = reform_info->bitmap_connect;
    if (!g_dms.enable_reform) {
        all_inst = g_dms.inst_map;
    }

    uint64 invld_insts = 0;
    switch ((dms_opengauss_lock_req_type_t)lock_req_type) {
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

    mfc_broadcast2(dms_ctx->sess_id, invld_insts, &head, (const void *)data, &succ_inst);

    if (!handle_recv_msg && timeout > 0) {
        ret = mfc_wait_acks(dms_ctx->sess_id, timeout, succ_inst);
    } else {
        ret = dcs_handle_recv_broadcast_msg(dms_ctx, succ_inst, timeout);
    }

    return ret;
}

#ifdef __cplusplus
}
#endif
