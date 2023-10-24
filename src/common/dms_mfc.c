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
#include "mes_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_MFC_SEND_WAIT_TIME (10) /* ms */
#define MFC_CONNECT_TIMEOUT (2000) /* us */
#define DMS_ONE 1
#define DMS_TWO 2
#define DMS_THREE 3

static inline uint32 dms_count_bits(uint64 bits)
{
    uint32 c = 0;
    while (bits) {
        bits &= (bits - 1);
        c++;
    }
    return c;
}

static inline void dms_inst_bits_to_list(uint64 bits, uint32 *list)
{
    uint32 idx = 0;
    for (uint32 node_id = 0; node_id < DMS_MAX_INSTANCES; node_id++) {
        if (bits & 1) {
            list[idx] = node_id;
            idx++;
        }
        bits >>= 1;
    }
}

/* is request in MFC sense, meaning will consume a ticket */
static inline bool32 mfc_msg_is_req(dms_message_head_t *head)
{
    return head->cmd < MSG_REQ_END;
}

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

/*
 * currently groupd id is equivalent to MES priority number
 * further flagbits are added after priority and serial bits
 */
static unsigned int inline mfc_get_mes_flag(dms_message_head_t *msg)
{
    unsigned int flag = dms_msg_group_id(msg->cmd);
    CM_ASSERT(flag <= MES_FLAG_SERIAL);
    return flag;
}


int32 mfc_forward_request(dms_message_head_t *msg)
{
    return mes_forward_request_x(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid,
        DMS_ONE, (char *)msg, msg->size);
}

static inline int32 mfc_send_data_req(dms_message_head_t *msg, bool8 is_sync)
{
    if (!mfc_try_get_ticket(msg->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = DMS_SUCCESS;
    if (is_sync) {
        ret = mes_send_request(msg->dst_inst, mfc_get_mes_flag(msg), &msg->ruid, (char *)msg, msg->size);
    } else {
        ret = mes_send_data(msg->dst_inst, mfc_get_mes_flag(msg), (char *)msg, msg->size);
    }

    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[msg->dst_inst], 1);
    }
    return ret;
}

static inline int32 mfc_send_data_ack(dms_message_head_t *msg, bool8 is_sync)
{
    msg->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[msg->dst_inst]);

    int ret = DMS_SUCCESS;
    if (is_sync) {
        ret = mes_send_response(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid, (char *)msg, msg->size);
    } else {
        ret = mes_send_data(msg->dst_inst, mfc_get_mes_flag(msg), (char *)msg, msg->size);
    }
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[msg->dst_inst], msg->tickets);
    }
    return ret;
}

int32 mfc_send_data_async(dms_message_head_t *msg)
{
    if (DMS_MFC_OFF) {
        return mes_send_data(msg->dst_inst, mfc_get_mes_flag(msg), (char *)msg, msg->size);
    }

    if (mfc_msg_is_req(msg)) {
        return mfc_send_data_req(msg, CM_FALSE);
    } else {
        return mfc_send_data_ack(msg, CM_FALSE);
    }
}

/* 1-BODY SYNC MESSAGE */
int32 mfc_send_data(dms_message_head_t *msg)
{
    if (DMS_MFC_OFF) {
        if (mfc_msg_is_req(msg)) {
            return mes_send_request(msg->dst_inst, mfc_get_mes_flag(msg), &msg->ruid, (char *)msg, msg->size);
        } else {
            return mes_send_response(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid, (char *)msg, msg->size);
        }
    }

    if (mfc_msg_is_req(msg)) {
        return mfc_send_data_req(msg, CM_TRUE);
    } else {
        return mfc_send_data_ack(msg, CM_TRUE);
    }
}

int32 mfc_send_response(dms_message_head_t *msg)
{
    return mes_send_response(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid, (char *)msg, msg->size);
}

static inline int32 mfc_send_data3_req(dms_message_head_t *head, uint32 head_size, const void *body)
{
    if (!mfc_try_get_ticket(head->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = DMS_SUCCESS;
    ret = mes_send_request_x(head->dst_inst, head->flags, &head->ruid,
        DMS_TWO, head, head_size, body, head->size - head_size);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data3_ack(dms_message_head_t *head, uint32 head_size, const void *body)
{
    head->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[head->dst_inst]);

    int ret = DMS_SUCCESS;
    ret = mes_send_response_x(head->dst_inst, head->flags, head->ruid,
        DMS_TWO, head, head_size, body, head->size - head_size);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[head->dst_inst], head->tickets);
    }
    return ret;
}

/* 2-BODY SYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data3(dms_message_head_t *head, uint32 head_size, const void *body)
{
    if (DMS_MFC_OFF) {
        if (mfc_msg_is_req(head)) {
            return mes_send_request_x(head->dst_inst, head->flags, &head->ruid,
                DMS_TWO, head, head_size, body, head->size - head_size);
        } else {
            MFC_RETURN_IF_BAD_RUID(head->ruid);
            return mes_send_response_x(head->dst_inst, head->flags, head->ruid,
                DMS_TWO, head, head_size, body, head->size - head_size);
        }
    }

    if (mfc_msg_is_req(head)) {
        return mfc_send_data3_req(head, head_size, body);
    } else {
        return mfc_send_data3_ack(head, head_size, body);
    }
}

static inline int32 mfc_send_data4_req(dms_message_head_t *head, uint32 head_size,
    const void *body1, uint32 len1, const void *body2, uint32 len2)
{
    if (!mfc_try_get_ticket(head->dst_inst)) {
        DMS_THROW_ERROR(ERRNO_DMS_MFC_NO_TICKETS);
        return ERRNO_DMS_MFC_NO_TICKETS;
    }

    int ret = DMS_SUCCESS;
    ret = mes_send_request_x(head->dst_inst, head->flags, &head->ruid,
            DMS_THREE, head, head_size, body1, len1, body2, len2);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->dst_inst], 1);
    }

    return ret;
}

static inline int32 mfc_send_data4_ack(dms_message_head_t *head, uint32 head_size,
    const void *body1, uint32 len1, const void *body2, uint32 len2)
{
    int ret = DMS_SUCCESS;
    head->tickets = mfc_clean_tickets(&g_dms.mfc.recv_tickets[head->dst_inst]);
    ret = mes_send_response_x(head->dst_inst, head->flags, head->ruid,
        DMS_THREE, head, head_size, body1, len1, body2, len2);
    if (ret != CM_SUCCESS) {
        mfc_add_tickets(&g_dms.mfc.recv_tickets[head->dst_inst], head->tickets);
    }
    return ret;
}

/* 3-BODY SYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data4(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    if (DMS_MFC_OFF) {
        if (mfc_msg_is_req(head)) {
            return mes_send_request_x(head->dst_inst, head->flags, &head->ruid,
                DMS_THREE, head, head_size, body1, len1, body2, len2);
        } else {
            MFC_RETURN_IF_BAD_RUID(head->ruid);
            return mes_send_response_x(head->dst_inst, head->flags, head->ruid,
                DMS_THREE, head, head_size, body1, len1, body2, len2);
        }
    }

    if (mfc_msg_is_req(head)) {
        return mfc_send_data4_req(head, head_size, body1, len1, body2, len2);
    } else {
        return mfc_send_data4_ack(head, head_size, body1, len1, body2, len2);
    }
}

/* 3-BODY ASYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data4_async(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    if (DMS_MFC_OFF) {
        return mes_send_data_x(head->dst_inst, head->flags,
            DMS_THREE, head, head_size, body1, len1, body2, len2);
    }
    /* Need to adapt if MFC to be enabled */
    return DMS_SUCCESS;
}

static inline int32 dms_handle_recv_ack_internal(dms_message_t *dms_msg)
{
    dms_message_head_t *head = dms_msg->head;
    dms_set_node_proto_version((head)->src_inst, (head)->sw_proto_ver);
    if ((head)->cmd == MSG_ACK_PROTOCOL_VERSION_NOT_MATCH) {
        dms_protocol_result_ack_t recv_msg = *(dms_protocol_result_ack_t*)dms_msg->buffer;
        LOG_RUN_INF("[DMS] receive ack version not match, ack info: src_inst:%u, src_sid:%u, dst_inst:%u, "
            "dst_sid:%u, msg_proto_ver:%u, result:%u, my sw_proto_ver:%u",
            (uint32)(head)->src_inst, (uint32)(head)->src_sid,
            (uint32)(head)->dst_inst, (uint32)(head)->dst_sid,
            (head)->msg_proto_ver, recv_msg.result, DMS_SW_PROTO_VER);
        if (recv_msg.result == DMS_PROTOCOL_VERSION_NOT_SUPPORT) {
            return ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT;
        }
        return ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH;
    }

    return DMS_SUCCESS;
}

/* previously mfc_allocbuf_and_recv_data */
int32 mfc_get_response(uint64 ruid, dms_message_t *response, int32 timeout_ms)
{
    if (response == NULL && timeout_ms == 0) {
        return mes_get_response(ruid, NULL, 0);
    }
    mes_msg_t msg = { 0 };
    int ret = mes_get_response(ruid, &msg, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    response->buffer = msg.buffer;
    response->head = (dms_message_head_t *)msg.buffer;
    ret = dms_handle_recv_ack_internal(response);
    if (DMS_MFC_OFF) {
        if (dms_check_if_protocol_compatibility_error(ret)) {
            mfc_release_mes_msg(&msg);
        }
        return ret;
    }

    CM_ASSERT(response->head->cmd >= MSG_ACK_BEGIN);
    mfc_add_tickets(&g_dms.mfc.remain_tickets[response->head->src_inst], response->head->tickets);
    if (dms_check_if_protocol_compatibility_error(ret)) {
        mfc_release_mes_msg(&msg);
    }
    return ret;
}

/* were mfc to be used, further adaptation is needed */
static void mfc_wait_acks_add_tickets(mes_msg_list_t *recv_msg)
{
    for (uint32 i = 0; i < recv_msg->count; i++) {
        dms_message_head_t *head = (dms_message_head_t *)recv_msg->messages[i].buffer;
        mfc_add_tickets(&g_dms.mfc.remain_tickets[head->src_inst], head->tickets);
    }
}

static void mfc_add_tickets_and_release_msg(mes_msg_list_t *recv_msg)
{
    dms_message_t msg;
    for (uint8 i = 0; i < recv_msg->count; i++) {
        msg.head = (dms_message_head_t *)recv_msg->messages[i].buffer;
        msg.buffer = recv_msg->messages[i].buffer;
        mfc_add_tickets(&g_dms.mfc.remain_tickets[msg.head->src_inst], msg.head->tickets);
        dms_release_recv_message(&msg);
    }
}

void mfc_broadcast(uint64 inst_bits, void *msg_data, uint64 *success_inst)
{
    *success_inst = inst_bits; /* cannot tell success insts until get response */
    if (inst_bits == 0) {
        return;
    }

    uint32 count = dms_count_bits(inst_bits);
    dms_message_head_t *head = (dms_message_head_t *)msg_data;
    uint32 inst_list[DMS_MAX_INSTANCES] = { 0 };
    dms_inst_bits_to_list(inst_bits, inst_list);
    (void)mes_broadcast_request_sp(inst_list, count, head->flags, &head->ruid, msg_data, head->size);
}

/* 2-BODY SYNC BROADCAST */
void mfc_broadcast2(uint64 inst_bits, dms_message_head_t *head, const void *body, uint64 *success_inst)
{
    *success_inst = inst_bits; /* cannot tell success insts until get response */
    if (inst_bits == 0) {
        *success_inst = 0;
        return;
    }

    uint32 count = dms_count_bits(inst_bits);
    uint32 inst_list[DMS_MAX_INSTANCES] = { 0 };
    dms_inst_bits_to_list(inst_bits, inst_list);
    (void)mes_broadcast_request_spx(inst_list, count, head->flags, &head->ruid,
        DMS_TWO, head, sizeof(dms_message_head_t), body, head->size - sizeof(dms_message_head_t));
}

static int32 mfc_check_broadcast_res(mes_msg_list_t *msg_list, bool32 check_ret,
    uint64 expect_insts, uint64 *recv_success_insts)
{
    int32 ret = CM_SUCCESS;
    *recv_success_insts = 0;
    int32 high_priority_ret = DMS_SUCCESS;

    for (uint32 i = 0; i < msg_list->count; i++) {
        dms_message_t dms_msg;
        dms_cast_mes_msg(&msg_list->messages[i], &dms_msg);
        dms_message_head_t *head = dms_msg.head;
        cm_panic_log(head != NULL, "inst:%d ack is NULL. please check", i);
        ret = dms_handle_recv_ack_internal(&dms_msg);
        if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT) {
            high_priority_ret = ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT;
        } else if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH
            && high_priority_ret != ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT) {
            high_priority_ret = ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH;
        }

        dms_common_ack_t *ack_msg = (dms_common_ack_t*)msg_list->messages[i].buffer;
        if (head->cmd != MSG_ACK_PROTOCOL_VERSION_NOT_MATCH && (!check_ret || ack_msg->ret == DMS_SUCCESS)) {
            *recv_success_insts |= ((uint64)0x1 << msg_list->messages[i].src_inst);
        }
    }

    DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(high_priority_ret);
    if (high_priority_ret == DMS_SUCCESS && expect_insts != *recv_success_insts) {
        high_priority_ret = ERRNO_DMS_DCS_BROADCAST_FAILED;
    }
    if (high_priority_ret == DMS_SUCCESS) {
        LOG_DEBUG_INF("Succeed to recv bcast ack from all nodes");
    }
    return high_priority_ret;
}

/*
 * previously mfc_wait_acks. return status only
 * mes buf is released before return
 */
int32 mfc_get_broadcast_res(uint64 ruid, uint32 timeout_ms, uint64 expect_insts)
{
    if (ruid == 0) {
        return DMS_SUCCESS;
    }
    mes_msg_list_t responses = { 0 };
    int ret = DMS_SUCCESS;
    uint64 recv_succ_insts = 0;
    if (DMS_MFC_OFF) {
        ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
        DMS_RETURN_IF_ERROR(ret);
        ret = mfc_check_broadcast_res(&responses, CM_FALSE, expect_insts, &recv_succ_insts);
        mfc_release_mes_msglist(&responses);
        return ret;
    }

    /* were mfc to be used, further adaptation is needed */
    ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
    if (ret != CM_SUCCESS) {
        mfc_wait_acks_add_tickets(&responses);
        return ret;
    }
    ret = mfc_check_broadcast_res(&responses, CM_FALSE, expect_insts, &recv_succ_insts);

    mfc_add_tickets_and_release_msg(&responses);
    return ret;
}

/*
 * previously mfc_wait_acks2. returns ret and succ_insts
 * mes buf is released before return
 */
int32 mfc_get_broadcast_res_with_succ_insts(uint64 ruid, uint32 timeout_ms, uint64 expect_insts, uint64 *succ_insts)
{
    if (ruid == 0) {
        *succ_insts = 0;
        return DMS_SUCCESS;
    }
    int ret = DMS_SUCCESS;
    mes_msg_list_t responses = { 0 };
    if (DMS_MFC_OFF) {
        ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
        DMS_RETURN_IF_ERROR(ret);
        ret = mfc_check_broadcast_res(&responses, CM_TRUE, expect_insts, succ_insts);
        mfc_release_mes_msglist(&responses);
        return ret;
    }

    ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(&responses, CM_TRUE, expect_insts, succ_insts);
    mfc_add_tickets_and_release_msg(&responses);
    return ret;
}

/*
 * previously mfc_wait_acks_and_recv_msg. returns ret and msglist
 * make sure mes buf is released by caller!
 */
int32 mfc_get_broadcast_res_with_msg(uint64 ruid, uint32 timeout_ms, uint64 expect_insts, mes_msg_list_t *msg_list)
{
    if (ruid == 0) {
        return DMS_SUCCESS;
    }
    int ret = DMS_SUCCESS;
    uint64 recv_succ_insts = 0;
    if (DMS_MFC_OFF) {
        ret = mes_broadcast_get_response(ruid, msg_list, timeout_ms);
        DMS_RETURN_IF_ERROR(ret);
        ret = mfc_check_broadcast_res(msg_list, CM_FALSE, expect_insts, &recv_succ_insts);
        if (ret != DMS_SUCCESS) {
            mfc_release_mes_msglist(msg_list);
        }
        return ret;
    }

    ret = mes_broadcast_get_response(ruid, msg_list, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(msg_list, CM_FALSE, expect_insts, &recv_succ_insts);
    mfc_wait_acks_add_tickets(msg_list);
    if (ret != DMS_SUCCESS) {
        mfc_release_mes_msglist(msg_list);
    }
    return ret;
}

/* previously mes_connect_batch; add instance and wait for connection */
int mfc_add_instance_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt, bool8 is_sync)
{
    int ret = DMS_SUCCESS;
    unsigned char inst_id;

    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (g_dms.inst_id == inst_id) {
            continue;
        }
        ret = mes_add_instance(inst_id, 0, 0);
        if (ret != CM_SUCCESS && ret != ERR_MES_IS_CONNECTED) {
            LOG_RUN_ERR("failed to add instance %d", inst_id);
            return ret;
        }
    }
    if (is_sync) {
        ret = mfc_check_connection_batch(inst_id_list, inst_id_cnt);
    }
    return ret;
}

int mfc_check_connection_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    uint8 inst_id;
    uint32 wait_time = 0;
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (g_dms.inst_id == inst_id) {
            continue;
        }
        while (!mes_connection_ready(inst_id)) {
            const uint8 once_wait_time = 10;
            cm_sleep(once_wait_time);
            wait_time += once_wait_time;
            if (wait_time > MFC_CONNECT_TIMEOUT) {
                LOG_RUN_INF("connect to instance %hhu time out.", inst_id);
                return DMS_ERROR;
            }
        }
    }
    return DMS_SUCCESS;
}

int mfc_del_instance_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt)
{
    int ret = DMS_SUCCESS;
    unsigned char inst_id;
    for (uint8 i = 0; i < inst_id_cnt; i++) {
        inst_id = inst_id_list[i];
        if (g_dms.inst_id == inst_id) {
            continue;
        }
        ret = mes_del_instance(inst_id);
        if (ret != CM_SUCCESS) {
            LOG_RUN_ERR("failed to del instance %d", inst_id);
            return ret;
        }
    }
    return ret;
}

#ifdef __cplusplus
}
#endif
