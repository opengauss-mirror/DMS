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
 * dms_mfc.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_mfc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_MFC_H__
#define __DMS_MFC_H__

#include "mes.h"
#include "cm_spinlock.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_mfc_ticket {
    uint16 count;
    spinlock_t lock;
} mfc_ticket_t;

typedef struct st_mfc {
    uint16 profile_tickets;
    uint16 max_wait_ticket_time; // ms
    mfc_ticket_t remain_tickets[CM_MAX_INSTANCES];
    mfc_ticket_t recv_tickets[CM_MAX_INSTANCES];
} mfc_t;

#define DMS_MSG_HEAD_UNUSED_SIZE 64
typedef struct st_dms_message_head {
    mes_message_head_t mes_head;
    unsigned int msg_proto_ver;
    unsigned int sw_proto_ver;
    unsigned int dms_cmd;
    uint8 unused[DMS_MSG_HEAD_UNUSED_SIZE];
} dms_message_head_t;

static inline void mfc_add_tickets(mfc_ticket_t *ticket, uint16 count)
{
    cm_spin_lock(&ticket->lock, NULL);
    ticket->count += count;
    cm_spin_unlock(&ticket->lock);
}

static inline uint16 mfc_clean_tickets(mfc_ticket_t *ticket)
{
    uint16 count;
    cm_spin_lock(&ticket->lock, NULL);
    count = ticket->count;
    ticket->count = 0;
    cm_spin_unlock(&ticket->lock);
    return count;
}

#define mfc_init mes_init
#define mfc_uninit mes_uninit
#define mfc_set_msg_enqueue mes_set_msg_enqueue
#define mfc_register_proc_func mes_register_proc_func
#define mfc_notify_msg_recv mes_notify_msg_recv
#define mfc_notify_broadcast_msg_recv_and_release mes_notify_broadcast_msg_recv_and_release
#define mfc_notify_broadcast_msg_recv_and_cahce mes_notify_broadcast_msg_recv_and_cahce
#define mfc_notify_broadcast_msg_recv_with_errcode mes_notify_broadcast_msg_recv_with_errcode
#define mfc_set_command_task_group mes_set_command_task_group
#define mfc_connect mes_connect
#define mfc_disconnect mes_disconnect
#define mfc_connect_batch mes_connect_batch
#define mfc_disconnect_batch mes_disconnect_batch
#define mfc_connection_ready mes_connection_ready
int32 mfc_send_data(dms_message_head_t *msg);
int32 mfc_send_data2(dms_message_head_t *head, const void *body);
int32 mfc_send_data3(dms_message_head_t *head, uint32 head_size, const void *body);
int32 mfc_send_data4(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2);
int32 mfc_send_data_internal(mes_message_head_t *msg);
int32 mfc_send_data2_internal(mes_message_head_t *head, const void *body);
int32 mfc_send_data3_internal(mes_message_head_t *head, uint32 head_size, const void *body);
int32 mfc_send_data4_internal(mes_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2);
int32 mfc_allocbuf_and_recv_data(uint16 sid, mes_message_t *msg, uint32 timeout);
#define mfc_release_message_buf mes_release_message_buf
static inline void mfc_broadcast(uint32 sid, uint64 inst_bits, const void *msg_data, uint64 *success_inst)
{
    mes_broadcast3(sid, inst_bits, msg_data, success_inst, mfc_send_data_internal);
}
static inline void mfc_broadcast2(uint32 sid, uint64 inst_bits, dms_message_head_t *head, const void *body,
    uint64 *success_inst)
{
    mes_broadcast4(sid, inst_bits, &(head->mes_head), body, success_inst, mfc_send_data2_internal);
}
static inline void mfc_broadcast3(uint32 sid, uint64 inst_bits, dms_message_head_t *head, uint32 head_size,
    const void *body, uint64 *success_inst)
{
    mes_broadcast5(sid, inst_bits, &(head->mes_head), head_size, body, success_inst, mfc_send_data3_internal);
}
int32 mfc_broadcast_and_wait(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout, uint64 *success_inst);
int32 mfc_broadcast_and_wait2(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout, uint64 *succ_insts);
int32 mfc_broadcast_and_recv_msg_with_judge(uint32 sid, uint64 inst_bits, const void *msg_data, uint32 timeout,
    uint64 *send_insts);
#define mfc_get_current_rsn mes_get_current_rsn
void mfc_init_ack_head(mes_message_head_t *req_head, dms_message_head_t *ack_head, unsigned int cmd,
    unsigned short size, unsigned int src_sid);
int32 mfc_wait_acks(uint32 sid, uint32 timeout, uint64 success_inst);
int32 mfc_wait_acks2(uint32 sid, uint32 timeout, uint64 *succ_insts);
int32 mfc_wait_acks_and_recv_msg(uint32 sid, uint32 timeout, uint64 success_inst, char *recv_msg[MES_MAX_INSTANCES]);
int32 mfc_wait_acks_and_recv_msg_with_judge(uint32 sid, uint32 timeout, uint64 send_insts,
    char *recv_msg[MES_MAX_INSTANCES], uint64 *success_recv_insts);
void dms_release_recv_acks_after_broadcast(uint64 recv_insts, char *recv_msg[MES_MAX_INSTANCES]);
#define mfc_get_rsn mes_get_rsn
#define mfc_get_stat_send_count mes_get_stat_send_count
#define mfc_get_stat_recv_count mes_get_stat_recv_count
#define mfc_get_stat_occupy_buf mes_get_stat_occupy_buf
#define mfc_get_elapsed_switch mes_get_elapsed_switch
#define mfc_set_elapsed_switch mes_set_elapsed_switch
#define mfc_get_elapsed_time mes_get_elapsed_time
#define mfc_get_elapsed_count mes_get_elapsed_count
#define mfc_register_decrypt_pwd mes_register_decrypt_pwd
#define mfc_get_max_watting_rooms mes_get_max_watting_rooms

#define DMS_HANDLE_RECV_ACK(head, ret)                                               \
    do {                                                                             \
        dms_set_node_proto_version((head)->mes_head.src_inst, (head)->sw_proto_ver); \
        if ((head)->dms_cmd == MSG_ACK_VERSION_NOT_MATCH) {                          \
            LOG_RUN_INF("[DMS] receive ack version not match, ack info: src_inst:%u, src_sid:%u, dst_inst:%u, " \
                "dst_sid:%u, msg_proto_ver:%u, my sw_proto_ver:%u",                  \
                (uint32)(head)->mes_head.src_inst, (uint32)(head)->mes_head.src_sid, \
                (uint32)(head)->mes_head.dst_inst, (uint32)(head)->mes_head.dst_sid, \
                (head)->msg_proto_ver, SW_PROTO_VER);                                \
            (*ret) = ERRNO_DMS_MSG_VERSION_NOT_MATCH;                                \
        }                                                                            \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __DMS_MFC_H__ */
