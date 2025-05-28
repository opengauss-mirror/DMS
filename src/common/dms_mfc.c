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

#include "dms_process.h"
#include "dms_error.h"
#include "dms_stat.h"
#include "dms_msg_protocol.h"
#include "mes_interface.h"
#include "fault_injection.h"

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

/*
 * currently groupd id is equivalent to MES priority number
 * further flagbits are added after priority and serial bits
 */
static inline unsigned int mfc_get_mes_flag(dms_message_head_t *msg)
{
    unsigned int flag = dms_get_mes_prio_by_cmd(msg);
    CM_ASSERT(flag <= MES_FLAG_SERIAL);
    return flag;
}


int32 mfc_forward_request(dms_message_head_t *msg)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = mes_forward_request_x(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid,
        DMS_ONE, (char *)msg, msg->size);
    dms_consume_with_time(msg->cmd, start_stat_time, ret);
    return ret;
}

int32 mfc_send_data_async(dms_message_head_t *msg)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = mes_send_data(msg->dst_inst, mfc_get_mes_flag(msg), (char *)msg, msg->size);
    dms_consume_with_time(msg->cmd, start_stat_time, ret);
    return ret;
}

/* 1-BODY SYNC MESSAGE */
int32 mfc_send_data(dms_message_head_t *msg)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = DMS_SUCCESS;
    if (mfc_msg_is_req(msg)) {
        ret = mes_send_request(msg->dst_inst, mfc_get_mes_flag(msg), &msg->ruid, (char *)msg, msg->size);
    } else {
        ret = mes_send_response(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid, (char *)msg, msg->size);
    }

    dms_consume_with_time(msg->cmd, start_stat_time, ret);
    return ret;
}

/* explicitly send response, need adaptation if mfc to be enabled */
int32 mfc_send_response(dms_message_head_t *msg)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = mes_send_response(msg->dst_inst, mfc_get_mes_flag(msg), msg->ruid, (char *)msg, msg->size);
    dms_consume_with_time(msg->cmd, start_stat_time, ret);
    return ret;
}

/* 2-BODY SYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data3(dms_message_head_t *head, uint32 head_size, const void *body)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = DMS_SUCCESS;
    if (mfc_msg_is_req(head)) {
        ret = mes_send_request_x(head->dst_inst, mfc_get_mes_flag(head), &head->ruid,
            DMS_TWO, head, head_size, body, head->size - head_size);
    } else {
        MFC_RETURN_IF_BAD_RUID(head->ruid);
        ret = mes_send_response_x(head->dst_inst, mfc_get_mes_flag(head), head->ruid,
            DMS_TWO, head, head_size, body, head->size - head_size);
    }

    dms_consume_with_time(head->cmd, start_stat_time, ret);
    return ret;
}

/* 3-BODY SYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data4(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();

    int ret = DMS_SUCCESS;
    if (mfc_msg_is_req(head)) {
        ret = mes_send_request_x(head->dst_inst, mfc_get_mes_flag(head), &head->ruid,
            DMS_THREE, head, head_size, body1, len1, body2, len2);
    } else {
        MFC_RETURN_IF_BAD_RUID(head->ruid);
        ret = mes_send_response_x(head->dst_inst, mfc_get_mes_flag(head), head->ruid,
            DMS_THREE, head, head_size, body1, len1, body2, len2);
    }

    dms_consume_with_time(head->cmd, start_stat_time, ret);
    return ret;
}

int32 mfc_send_data2_async(dms_message_head_t *head, uint32 head_size, const void *body, uint32 len)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();
    int ret = mes_send_data_x(head->dst_inst, mfc_get_mes_flag(head), DMS_TWO, head, head_size, body, len);
    dms_consume_with_time(head->cmd, start_stat_time, ret);
    return ret;
}

/* 3-BODY ASYNC MESSAGE, with 1st body as user-customized head. */
int32 mfc_send_data3_async(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return (DMS_SUCCESS));
    uint64 start_stat_time = dms_cm_get_time_usec();
    int ret = mes_send_data_x(head->dst_inst, mfc_get_mes_flag(head),
        DMS_THREE, head, head_size, body1, len1, body2, len2);
    dms_consume_with_time(head->cmd, start_stat_time, ret);
    return ret;
}

static inline int32 dms_handle_recv_ack_internal(dms_message_t *dms_msg)
{
    dms_message_head_t *head = dms_msg->head;
    dms_set_node_proto_version((head)->src_inst, (head)->sw_proto_ver);
    if ((head)->cmd == MSG_ACK_PROTOCOL_VERSION_NOT_MATCH) {
        dms_protocol_result_ack_t recv_msg = *(dms_protocol_result_ack_t*)dms_msg->buffer;
        LOG_RUN_WAR("[DMS] receive ack version not match, ack info: src_inst:%u, src_sid:%u, dst_inst:%u, "
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
    uint64 start_stat_time = dms_cm_get_time_usec();

    mes_msg_t msg = { 0 };
    int ret = mes_get_response(ruid, &msg, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    response->buffer = msg.buffer;
    response->head = (dms_message_head_t *)msg.buffer;
    ret = dms_handle_recv_ack_internal(response);
    dms_consume_with_time(response->head->cmd, start_stat_time, ret);

    if (dms_check_if_protocol_compatibility_error(ret)) {
        mes_release_msg(&msg);
    }
    return ret;
}

void mfc_broadcast(uint64 inst_bits, void *msg_data, uint64 *success_inst)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return);
    *success_inst = inst_bits; /* cannot tell success insts until get response */
    if (inst_bits == 0) {
        return;
    }
    uint64 start_stat_time = dms_cm_get_time_usec();

    uint32 count = dms_count_bits(inst_bits);
    uint32 inst_list[DMS_MAX_INSTANCES] = { 0 };
    dms_inst_bits_to_list(inst_bits, inst_list);

    dms_message_head_t *head = (dms_message_head_t *)msg_data;
    int ret = mes_broadcast_request_sp(inst_list, count, mfc_get_mes_flag(head), &head->ruid, msg_data, head->size);
    dms_consume_with_time(head->cmd, start_stat_time, ret);
}

/* 2-BODY SYNC BROADCAST */
void mfc_broadcast2(uint64 inst_bits, dms_message_head_t *head, const void *body, uint64 *success_inst)
{
    DDES_FAULT_INJECTION_ACTION_TRIGGER(return);
    *success_inst = inst_bits; /* cannot tell success insts until get response */
    if (inst_bits == 0) {
        return;
    }
    uint64 start_stat_time = dms_cm_get_time_usec();

    uint32 count = dms_count_bits(inst_bits);
    uint32 inst_list[DMS_MAX_INSTANCES] = { 0 };
    dms_inst_bits_to_list(inst_bits, inst_list);

    int ret = mes_broadcast_request_spx(inst_list, count, mfc_get_mes_flag(head), &head->ruid,
        DMS_TWO, head, sizeof(dms_message_head_t), body, head->size - sizeof(dms_message_head_t));
    dms_consume_with_time(head->cmd, start_stat_time, ret);
}

static int32 mfc_check_broadcast_res(mes_msg_list_t *msg_list, bool32 check_ret,
    uint64 expect_insts, uint64 *recv_succ_insts)
{
    int32 ret = CM_SUCCESS;
    *recv_succ_insts = 0;
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
        if (head->cmd != MSG_ACK_PROTOCOL_VERSION_NOT_MATCH) {
            if (!check_ret || ack_msg->ret == DMS_SUCCESS) {
                *recv_succ_insts |= ((uint64)0x1 << msg_list->messages[i].src_inst);
            } else {
                LOG_RUN_ERR("[mfc_check_bcast_res]node:%hhu acks errno:%d",
                    ack_msg->head.src_inst, ack_msg->ret);
            }
        }
    }

    DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(high_priority_ret);
    if (high_priority_ret == DMS_SUCCESS && expect_insts != *recv_succ_insts) {
        high_priority_ret = ERRNO_DMS_DCS_BROADCAST_FAILED;
    }
    if (high_priority_ret == DMS_SUCCESS) {
        LOG_DEBUG_INF("Succeed to receive broadcast ack of all nodes");
    }
    return high_priority_ret;
}

/*
 * previously mfc_wait_acks. return status only
 * mes buffer is released before return
 */
int32 mfc_get_broadcast_res(uint64 ruid, uint32 timeout_ms, uint64 expect_insts)
{
    if (ruid == 0) {
        return DMS_SUCCESS;
    }

    mes_msg_list_t responses;
    responses.count = 0;
    uint64 recv_succ_insts = 0;

    int ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(&responses, CM_FALSE, expect_insts, &recv_succ_insts);
    mfc_release_broadcast_response(&responses);
    return ret;
}

/*
 * previously mfc_wait_acks2. returns ret and succ_insts
 * mes buffer is released before return
 */
int32 mfc_get_broadcast_res_with_succ_insts(uint64 ruid, uint32 timeout_ms, uint64 expect_insts, uint64 *succ_insts)
{
    if (ruid == 0) {
        *succ_insts = 0;
        return DMS_SUCCESS;
    }
    mes_msg_list_t responses;
    responses.count = 0;

    int ret = mes_broadcast_get_response(ruid, &responses, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(&responses, CM_TRUE, expect_insts, succ_insts);
    mfc_release_broadcast_response(&responses);
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
    uint64 recv_succ_insts = 0;
    int ret = mes_broadcast_get_response(ruid, msg_list, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(msg_list, CM_FALSE, expect_insts, &recv_succ_insts);
    if (ret != DMS_SUCCESS) {
        mfc_release_broadcast_response(msg_list);
    }
    return ret;
}

int32 mfc_get_broadcast_res_with_msg_and_succ_insts(uint64 ruid, uint32 timeout_ms, uint64 expect_insts,
    uint64 *succ_insts, mes_msg_list_t *msg_list)
{
    if (ruid == 0) {
        *succ_insts = 0;
        return DMS_SUCCESS;
    }
    int ret = mes_broadcast_get_response(ruid, msg_list, timeout_ms);
    DMS_RETURN_IF_ERROR(ret);
    ret = mfc_check_broadcast_res(msg_list, CM_TRUE, expect_insts, succ_insts);
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

        ret = mes_connect_instance(inst_id);
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
        ret = mes_disconnect_instance(inst_id);
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
