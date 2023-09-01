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
 * dms_mfc.c
 *
 *
 * IDENTIFICATION
 *    src/common/dms_mfc.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_mfc.h"
#include "dms_process.h"
#include "dms_error.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_MFC_SEND_WAIT_TIME 10 // ms
#define MFC_NODE_IS_IN_BITMAP(bitmap, node_id) (((bitmap) >> (node_id)) & 0x1)

static bool8 mfc_try_get_ticket(uint8 dst_inst)
{
    mfc_ticket_t *ticket = &g_dms.mfc.remain_tickets[dst_inst];
    uint32 time = 0;
    for (;;) {
        if (time >= g_dms.mfc.max_wait_ticket_time) {
            return CM_FALSE;
        }

        time += DMS_MFC_SEND_WAIT_TIME;
        if (!cm_spin_try_lock(&ticket->lock)) {
            cm_sleep(DMS_MFC_SEND_WAIT_TIME);
            continue;
        }

        if (ticket->count > 0) {
            ticket->count--;
            cm_spin_unlock(&ticket->lock);
            return CM_TRUE;
        }
        cm_spin_unlock(&ticket->lock);
        cm_sleep(DMS_MFC_SEND_WAIT_TIME);
    }
}

static inline bool32 mfc_msg_is_req(mes_message_head_t *head)
{
    return g_dms.processors[head->cmd].is_enqueue;
}

static inline int32 mfc_send_data_req(mes_message_head_t *msg)
{
    if (!mfc_try_get_ticket(msg->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = mes_send_data(msg);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[msg->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data_ack(mes_message_head_t *msg)
{
    msg->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[msg->dst_inst]);
    int ret = mes_send_data(msg);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[msg->dst_inst], msg->tickets);
    }
    return ret;
}

int32 mfc_send_data_internal(mes_message_head_t *msg)
{
    if (DMS_MFC_OFF) {
        return mes_send_data(msg);
    }

    if (mfc_msg_is_req(msg)) {
        return mfc_send_data_req(msg);
    } else {
        return mfc_send_data_ack(msg);
    }
}

int32 mfc_send_data(dms_message_head_t *msg)
{
    return mfc_send_data_internal(&msg->mes_head);
}

static inline int32 mfc_send_data3_req(mes_message_head_t *head, uint32 head_size, const void *body)
{
    if (!mfc_try_get_ticket(head->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = mes_send_data3(head, head_size, body);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data3_ack(mes_message_head_t *head, uint32 head_size, const void *body)
{
    head->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[head->dst_inst]);
    int ret = mes_send_data3(head, head_size, body);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[head->dst_inst], head->tickets);
    }
    return ret;
}

int32 mfc_send_data3_internal(mes_message_head_t *head, uint32 head_size, const void *body)
{
    if (DMS_MFC_OFF) {
        return mes_send_data3(head, head_size, body);
    }

    if (mfc_msg_is_req(head)) {
        return mfc_send_data3_req(head, head_size, body);
    } else {
        return mfc_send_data3_ack(head, head_size, body);
    }
}

int32 mfc_send_data3(dms_message_head_t *head, uint32 head_size, const void *body)
{
    return mfc_send_data3_internal(&head->mes_head, head_size, body);
}

static inline int32 mfc_send_data4_req(mes_message_head_t *head, uint32 head_size,
    const void *body1, uint32 len1, const void *body2, uint32 len2)
{
    if (!mfc_try_get_ticket(head->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = mes_send_data4(head, head_size, body1, len1, body2, len2);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data4_ack(mes_message_head_t *head, uint32 head_size,
    const void *body1, uint32 len1, const void *body2, uint32 len2)
{
    head->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[head->dst_inst]);
    int ret = mes_send_data4(head, head_size, body1, len1, body2, len2);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[head->dst_inst], head->tickets);
    }
    return ret;
}

int32 mfc_send_data4_internal(mes_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    if (DMS_MFC_OFF) {
        return mes_send_data4(head, head_size, body1, len1, body2, len2);
    }

    if (mfc_msg_is_req(head)) {
        return mfc_send_data4_req(head, head_size, body1, len1, body2, len2);
    } else {
        return mfc_send_data4_ack(head, head_size, body1, len1, body2, len2);
    }
}

int32 mfc_send_data4(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    return mfc_send_data4_internal(&head->mes_head, head_size, body1, len1, body2, len2);
}

int32 dms_handle_recv_ack_internal(dms_message_head_t *head)
{
    dms_set_node_proto_version((head)->mes_head.src_inst, (head)->sw_proto_ver);
    if ((head)->dms_cmd == MSG_ACK_VERSION_NOT_MATCH) {
        LOG_RUN_INF("[DMS] receive ack version not match, ack info: src_inst:%u, src_sid:%u, dst_inst:%u, "
            "dst_sid:%u, msg_proto_ver:%u, my sw_proto_ver:%u",
            (uint32)(head)->mes_head.src_inst, (uint32)(head)->mes_head.src_sid,
            (uint32)(head)->mes_head.dst_inst, (uint32)(head)->mes_head.dst_sid,
            (head)->msg_proto_ver, SW_PROTO_VER);
        mfc_release_message_buf((mes_message_t *)head);
        return ERRNO_DMS_MSG_VERSION_NOT_MATCH;
    }
    return DMS_SUCCESS;
}

int32 dms_handle_recv_ack_error(mes_message_t *msg)
{
    dms_message_head_t *ack_dms_head = get_dms_head(msg);
    if (ack_dms_head->dms_cmd == MSG_ACK_ERROR) {
        cm_print_error_msg(msg->buffer);
        msg_error_t *error_msg = (msg_error_t *)msg->buffer;
        DMS_THROW_ERROR(error_msg->code);
        mfc_release_message_buf(msg);
        return error_msg->code;
    }
    return DMS_SUCCESS;
}

int32 mfc_allocbuf_and_recv_data(uint16 sid, mes_message_t *msg, uint32 timeout)
{
    int ret = mes_allocbuf_and_recv_data(sid, msg, timeout);
    if (DMS_MFC_OFF) {
        DMS_RETURN_IF_ERROR(ret);
        dms_message_head_t *dms_head = get_dms_head(msg);
        ret = dms_handle_recv_ack_internal(dms_head);
        DMS_RETURN_IF_ERROR(ret);
        return dms_handle_recv_ack_error(msg);
    }

    DMS_RETURN_IF_ERROR(ret);
    dms_message_head_t *dms_head = get_dms_head(msg);
    ret = dms_handle_recv_ack_internal(dms_head);
    mfc_add_tickets(&g_dms.mfc.remain_tickets[msg->head->src_inst], msg->head->tickets);
    ret = dms_handle_recv_ack_internal(dms_head);
    DMS_RETURN_IF_ERROR(ret);
    return dms_handle_recv_ack_error(msg);
}

static void mfc_wait_acks_add_tickets(uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    for (uint32 i = 0; i < CM_MAX_INSTANCES; i++) {
        if (MES_IS_INST_SEND(success_inst, i) && recv_msg[i] != NULL) {
            mes_message_head_t *head = (mes_message_head_t *)recv_msg[i];
            mfc_add_tickets(&g_dms.mfc.remain_tickets[head->src_inst], head->tickets);
        }
    }
}

static void mfc_wait_acks_add_tickets_and_release_msg(uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    mes_message_t msg;
    for (uint32 i = 0; i < CM_MAX_INSTANCES; i++) {
        if (MES_IS_INST_SEND(success_inst, i) && recv_msg[i] != NULL) {
            msg.head = (mes_message_head_t *)recv_msg[i];
            msg.buffer = recv_msg[i];
            mfc_add_tickets(&g_dms.mfc.remain_tickets[msg.head->src_inst], msg.head->tickets);
            mfc_release_message_buf(&msg);
        }
    }
}

static void mfc_wait_acks_add_tickets_and_release_msg2(uint64 *success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    mes_message_t msg;
    for (uint8 i = 0; i < CM_MAX_INSTANCES; i++) {
        if (MES_IS_INST_SEND(*success_inst, i) && recv_msg[i] != NULL) {
            msg.head = (mes_message_head_t *)recv_msg[i];
            msg.buffer = recv_msg[i];
            mfc_add_tickets(&g_dms.mfc.remain_tickets[msg.head->src_inst], msg.head->tickets);
            int32 ret = *(int32 *)(msg.buffer + sizeof(mes_message_head_t));
            if (ret != CM_SUCCESS) {
                bitmap64_clear(success_inst, i);
            }
            mfc_release_message_buf(&msg);
        }
    }
}

int32 mfc_broadcast_and_recv_msg_with_judge(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout,
    uint64 *success_insts)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_broadcast3(sid, inst_bits, msg_data, success_insts, mfc_send_data_internal);
    char *recv_msg[CM_MAX_INSTANCES] = { 0 };
    uint64 success_recv_insts = 0;
    int32 ret = mfc_wait_acks_and_recv_msg_with_judge(sid, timeout, *success_insts, recv_msg, &success_recv_insts);
    if (ret != CM_SUCCESS || (*success_insts) != success_recv_insts) {
        if (ret == CM_SUCCESS) {
            dms_release_recv_acks_after_broadcast(*success_insts, recv_msg);
        }
        LOG_RUN_ERR("[mes]mfc_broadcast_and_recv_msg_with_judge failed.");
        return ret;
    }
    dms_release_recv_acks_after_broadcast(*success_insts, recv_msg);
    mes_consume_with_time(((mes_message_head_t *)msg_data)->cmd, MES_TIME_TEST_MULTICAST_AND_WAIT, start_stat_time);
    return CM_SUCCESS;
}

int32 mfc_wait_acks(uint32 sid, uint32 timeout, uint64 success_inst)
{
    if (DMS_MFC_OFF) {
        return mes_wait_acks(sid, timeout);
    }

    char *recv_msg[CM_MAX_INSTANCES] = { 0 };
    int32 ret = mes_wait_acks_and_recv_msg2(sid, timeout, success_inst, recv_msg, mfc_wait_acks_add_tickets);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    mfc_wait_acks_add_tickets_and_release_msg(success_inst, recv_msg);
    return DMS_SUCCESS;
}

int32 mfc_wait_acks2(uint32 sid, uint32 timeout, uint64 *succ_insts)
{
    if (DMS_MFC_OFF) {
        return mes_wait_acks2(sid, timeout, succ_insts);
    }

    char *recv_msg[CM_MAX_INSTANCES] = { 0 };
    int32 ret = mes_wait_acks_and_recv_msg2(sid, timeout, *succ_insts, recv_msg, mfc_wait_acks_add_tickets);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    mfc_wait_acks_add_tickets_and_release_msg2(succ_insts, recv_msg);
    return DMS_SUCCESS;
}

int32 dms_handle_recv_acks_after_broadcast(uint64 send_insts, char *recv_msg[MES_MAX_INSTANCES],
    uint64 *success_recv_insts)
{
    int32 ret = CM_SUCCESS;
    if (success_recv_insts != NULL) {
        *success_recv_insts = 0;
    }

    for (int i = 0; i < MES_MAX_INSTANCES; i++) {
        if (MFC_NODE_IS_IN_BITMAP(send_insts, i) == 0) {
            continue;
        }
        dms_message_head_t *head = (dms_message_head_t*)recv_msg[i];
        cm_panic_log(head != NULL, "caller think all send_insts:%llu send success and ack recvived, but inst:%d ack "
            "is NULL. please check", send_insts, i);
        ret = dms_handle_recv_ack_internal(head);
        if (success_recv_insts != NULL) {
            dms_common_ack_t *ack_msg = (dms_common_ack_t*)recv_msg[i];
            if (head->dms_cmd != MSG_ACK_VERSION_NOT_MATCH && ack_msg->ret == DMS_SUCCESS) {
                *success_recv_insts |= ((uint64)0x1 << i);
            }
        }
    }

    if (ret == MSG_ACK_VERSION_NOT_MATCH) {
        dms_release_recv_acks_after_broadcast(send_insts, recv_msg);
    }
    return ret;
}

int32 mfc_wait_acks_and_recv_msg(uint32 sid, uint32 timeout, uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    if (DMS_MFC_OFF) {
        int32 ret = mes_wait_acks_and_recv_msg(sid, timeout, success_inst, recv_msg);
        DMS_RETURN_IF_ERROR(ret);
        ret = dms_handle_recv_acks_after_broadcast(success_inst, recv_msg, NULL);
        return ret;
    }

    int32 ret = mes_wait_acks_and_recv_msg2(sid, timeout, success_inst, recv_msg, mfc_wait_acks_add_tickets);
    DMS_RETURN_IF_ERROR(ret);
    ret = dms_handle_recv_acks_after_broadcast(success_inst, recv_msg, NULL);
    mfc_wait_acks_add_tickets(success_inst, recv_msg);
    return ret;
}

int32 mfc_wait_acks_and_recv_msg_with_judge(uint32 sid, uint32 timeout, uint64 send_insts,
    char *recv_msg[MES_MAX_INSTANCES], uint64 *success_recv_insts)
{
    if (DMS_MFC_OFF) {
        int32 ret = mes_wait_acks_and_recv_msg(sid, timeout, send_insts, recv_msg);
        DMS_RETURN_IF_ERROR(ret);
        ret = dms_handle_recv_acks_after_broadcast(send_insts, recv_msg, success_recv_insts);
        return ret;
    }

    int32 ret = mes_wait_acks_and_recv_msg2(sid, timeout, send_insts, recv_msg, mfc_wait_acks_add_tickets);
    DMS_RETURN_IF_ERROR(ret);
    ret = dms_handle_recv_acks_after_broadcast(send_insts, recv_msg, success_recv_insts);
    mfc_wait_acks_add_tickets(send_insts, recv_msg);
    return ret;
}

void dms_release_recv_acks_after_broadcast(uint64 recv_insts, char *recv_msg[MES_MAX_INSTANCES])
{
    mes_message_t msg;
    for (uint8 i = 0; i < MES_MAX_INSTANCES; i++) {
        if (MFC_NODE_IS_IN_BITMAP(recv_insts, i) && recv_msg[i] != NULL) {
            msg.buffer = recv_msg[i];
            msg.head = (mes_message_head_t*)recv_msg[i];
            mfc_release_message_buf(&msg);
        }
    }
}

void mfc_init_ack_head(mes_message_head_t *req_head, dms_message_head_t *ack_head, unsigned int cmd,
    unsigned short size, unsigned int src_sid)
{
    mes_init_ack_head(req_head, &ack_head->mes_head, cmd, size, src_sid);
    uint32 send_version = dms_get_send_proto_version_by_cmd(cmd, req_head->src_inst);
    dms_init_message_dms_head(ack_head, cmd, send_version);
}

#ifdef __cplusplus
}
#endif
