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

int32 mfc_send_data(mes_message_head_t *msg)
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

static inline int32 mfc_send_data2_req(const mes_message_head_t *head, const void *body)
{
    if (!mfc_try_get_ticket(head->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = mes_send_data2(head, body);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data2_ack(mes_message_head_t *head, const void *body)
{
    head->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[head->dst_inst]);
    int ret = mes_send_data2(head, body);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[head->dst_inst], head->tickets);
    }
    return ret;
}

int32 mfc_send_data2(mes_message_head_t *head, const void *body)
{
    if (DMS_MFC_OFF) {
        return mes_send_data2(head, body);
    }

    if (mfc_msg_is_req(head)) {
        return mfc_send_data2_req(head, body);
    } else {
        return mfc_send_data2_ack(head, body);
    }
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

int32 mfc_send_data3(mes_message_head_t *head, uint32 head_size, const void *body)
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

int32 mfc_send_data4(mes_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
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

int32 mfc_allocbuf_and_recv_data(uint16 sid, mes_message_t *msg, uint32 timeout)
{
    int ret = mes_allocbuf_and_recv_data(sid, msg, timeout);
    if (DMS_MFC_OFF || ret != CM_SUCCESS) {
        return ret;
    }

    mfc_add_tickets(&g_dms.mfc.remain_tickets[msg->head->src_inst], msg->head->tickets);
    return DMS_SUCCESS;
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

int32 mfc_broadcast_and_wait(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout,
    uint64 *success_inst)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_broadcast3(sid, inst_bits, msg_data, success_inst, mfc_send_data);
    int ret = mfc_wait_acks(sid, timeout, *success_inst);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]mes_wait_acks failed.");
        return ret;
    }

    mes_consume_with_time(((mes_message_head_t *)msg_data)->cmd, MES_TIME_TEST_MULTICAST_AND_WAIT, start_stat_time);
    return CM_SUCCESS;
}

int32 mfc_broadcast_and_wait2(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout,
    uint64 *succ_insts)
{
    uint64 start_stat_time = 0;
    mes_get_consume_time_start(&start_stat_time);
    mes_broadcast3(sid, inst_bits, msg_data, succ_insts, mfc_send_data);
    int ret = mfc_wait_acks2(sid, timeout, succ_insts);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[mes]mes_wait_acks failed.");
        return ret;
    }

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

int32 mfc_wait_acks_and_recv_msg(uint32 sid, uint32 timeout, uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES])
{
    if (DMS_MFC_OFF) {
        return mes_wait_acks_and_recv_msg(sid, timeout, success_inst, recv_msg);
    }

    int32 ret = mes_wait_acks_and_recv_msg2(sid, timeout, success_inst, recv_msg, mfc_wait_acks_add_tickets);
    if (ret != CM_SUCCESS) {
        return ret;
    }

    mfc_wait_acks_add_tickets(success_inst, recv_msg);
    return DMS_SUCCESS;
}

#ifdef __cplusplus
}
#endif
