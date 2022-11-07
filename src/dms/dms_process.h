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
 * dms_process.h
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_process.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_PROCESS_H__
#define __DMS_PROCESS_H__

#include "dms.h"
#include "dms_mfc.h"
#include "cm_types.h"
#include "dms_msg.h"
#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dms_message_proc_t)(dms_process_context_t *ctx, mes_message_t *message);
typedef struct st_dms_processor {
    dms_message_proc_t proc;
    bool32 is_enqueue;
    bool32 is_enable_before_reform;
    bool32 is_sync_msg;
    char name[CM_MAX_NAME_LEN];
} dms_processor_t;

typedef struct st_dms_cntlr {
    uint64     rsn;
    spinlock_t lock;
}dms_cntlr_t;

typedef struct st_dms_instance {
    uint32 inst_id;
    uint32 inst_cnt; // all instance count in cluster
    volatile uint64 inst_map;
    uint32 page_size;
    uint32 proc_ctx_cnt;
    dms_process_context_t *proc_ctx;
    dms_processor_t processors[CM_MAX_MES_MSG_CMD];
    dms_callback_t callback;
    reform_context_t reform_ctx;
    mfc_t mfc;
    uint64 min_scn[DMS_MAX_INSTANCES];
    uint8 enable_reform;
    cm_res_mgr_t cm_res_mgr;
    dms_cntlr_t *cntlr[DMS_MAX_INSTANCES];
} dms_instance_t;

#define DMS_MFC_OFF (g_dms.mfc.profile_tickets == 0)

#define DMS_BUFFER_POOL_NUM (3)
#define DMS_MSG_BUFFER_QUEUE_NUM (8)
#define DMS_FIRST_BUFFER_LENGTH (64)
#define DMS_SECOND_BUFFER_LENGTH (128)
#define DMS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 64)
#define DMS_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define DMS_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define DMS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DMS_FIRST_BUFFER_RATIO (1.0f / 4)
#define DMS_SECOND_BUFFER_RATIO (1.0f / 4)
#define DMS_THIRDLY_BUFFER_RATIO (1.0f / 2)

extern dms_instance_t g_dms;

static inline void dms_proc_msg_ack(dms_process_context_t *process_ctx, mes_message_t *msg)
{
    mfc_notify_msg_recv(msg);
}

static inline void dms_proc_broadcast_ack(dms_process_context_t *process_ctx, mes_message_t *msg)
{
    if (DMS_MFC_OFF) {
        mfc_notify_broadcast_msg_recv_and_release(msg);
    } else {
        mfc_notify_broadcast_msg_recv_and_cahce(msg);
    }
}

static inline void dms_proc_broadcast_ack2(dms_process_context_t *process_ctx, mes_message_t *msg)
{
    mfc_notify_broadcast_msg_recv_and_cahce(msg);
}

static inline void dms_proc_broadcast_ack3(dms_process_context_t *process_ctx, mes_message_t *msg)
{
    mfc_notify_broadcast_msg_recv_with_errcode(msg);
}

static inline const char *dms_get_mescmd_msg(uint8 cmd)
{
    return (cmd < MSG_CMD_CEIL) ? g_dms.processors[cmd].name : "INVALID";
}
#ifdef __cplusplus
}
#endif

#endif /* __DMS_PROCESS_H__ */
