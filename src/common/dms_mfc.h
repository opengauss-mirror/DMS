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

#include "mes_interface.h"
#include "cm_spinlock.h"
#include "dms_api.h"

#ifdef __cplusplus
extern "C" {
#endif

/* common code to adapt new MES */

#define DMS_MSG_HEAD_SIZE       sizeof(dms_message_head_t)
#define DMS_ASYNC_OR_INVLD_RUID (0)

#define DMS_MSG_HEAD_UNUSED_SIZE 24
#define DMS_MAX_WORK_THREAD_CNT  128

#define MFC_RETURN_IF_BAD_RUID(ruid)                \
    do {                                            \
        if (ruid == 0) {                            \
            LOG_DEBUG_ERR("[mfc] illegal ruid:0");  \
            return CM_ERROR;                        \
        }                                           \
    } while (0)

typedef struct st_dms_message_head {
    unsigned int msg_proto_ver;
    unsigned int sw_proto_ver;
    unsigned int cmd;
    unsigned int  flags;
    unsigned long long ruid;
    unsigned char src_inst;
    unsigned char dst_inst;
    unsigned short size;
    unsigned int cluster_ver;
    unsigned short src_sid;
    unsigned short dst_sid;
    unsigned short tickets;
    unsigned short unused;
    union {
        struct {
            long long judge_time; // for message used in reform, check if it is the same round of reform
        };
        struct {
            unsigned long long seq;
        };
        unsigned char reserved[DMS_MSG_HEAD_UNUSED_SIZE]; /* 64 bytes total */
    };
} dms_message_head_t;

typedef struct st_dms_message_t {
    dms_message_head_t *head;
    char *buffer;
} dms_message_t;

#define mfc_init mes_init
#define mfc_uninit mes_uninit
#define mfc_register_proc_func mes_register_proc_func

/* MES connection */
#define mfc_connection_ready mes_connection_ready
#define mfc_connect mes_connect_instance
int mfc_add_instance_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt, bool8 is_sync);
int mfc_check_connection_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);
int mfc_del_instance_batch(const unsigned char *inst_id_list, unsigned char inst_id_cnt);

/* MES p2p message passing */
int32 mfc_send_data(dms_message_head_t *msg);
int32 mfc_send_data_async(dms_message_head_t *msg);
int32 mfc_send_data3(dms_message_head_t *head, uint32 head_size, const void *body);
int32 mfc_send_data4(dms_message_head_t *head, uint32 head_size,
    const void *body1, uint32 len1, const void *body2, uint32 len2);
int32 mfc_send_data2_async(dms_message_head_t *head, uint32 head_size, const void *body, uint32 len);
int32 mfc_send_data3_async(dms_message_head_t *head, uint32 head_size, const void *body1, uint32 len1,
    const void *body2, uint32 len2);
int32 mfc_get_response(uint64 ruid, dms_message_t *response, int32 timeout_ms);
int32 mfc_forward_request(dms_message_head_t *msg);
int32 mfc_send_response(dms_message_head_t *msg);

/* MES broadcast */
void mfc_broadcast(uint64 inst_bits, void *msg_data, uint64 *success_inst);
void mfc_broadcast2(uint64 inst_bits, dms_message_head_t *head, const void *body, uint64 *success_inst);
int32 mfc_get_broadcast_res(uint64 ruid, uint32 timeout_ms, uint64 expect_insts);
int32 mfc_get_broadcast_res_with_succ_insts(uint64 ruid, uint32 timeout_ms, uint64 expect_insts, uint64 *succ_insts);
int32 mfc_get_broadcast_res_with_msg(uint64 ruid, uint32 timeout_ms, uint64 expect_insts, mes_msg_list_t *msg_list);
int32 mfc_get_broadcast_res_with_msg_and_succ_insts(uint64 ruid, uint32 timeout_ms, uint64 expect_insts,
    uint64 *succ_insts, mes_msg_list_t *msg_list);


static inline void mfc_release_broadcast_response(mes_msg_list_t *response)
{
    mes_release_msg_list(response);
}

static inline void mfc_release_response(dms_message_t *msg)
{
    if (msg == NULL || msg->buffer == NULL) {
        return;
    }
    mes_msg_t mes_msg = { 0 };
    mes_msg.buffer = msg->buffer;
    mes_release_msg(&mes_msg);
    msg->buffer = NULL;
}

#define mfc_set_elapsed_switch mes_set_elapsed_switch
#define mfc_register_decrypt_pwd mes_register_decrypt_pwd

#ifdef __cplusplus
}
#endif

#endif /* __DMS_MFC_H__ */
