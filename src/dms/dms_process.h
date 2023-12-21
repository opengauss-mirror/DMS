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
#include "dms_msg_command.h"
#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*dms_message_proc_t)(dms_process_context_t *ctx, dms_message_t *message);
typedef struct st_dms_processor {
    dms_message_proc_t proc;
    bool32 is_enqueue;
    bool32 is_enable_before_reform;
    char name[CM_MAX_NAME_LEN];
} dms_processor_t;

typedef struct st_ock_scrlock_context {
    unsigned char enable;
}dms_ock_scrlock_context_t;

typedef struct st_dms_instance {
    uint32 inst_id;
    uint32 inst_cnt; // all instance count in cluster
    volatile uint64 inst_map;
    uint32 page_size;
    uint32 proc_ctx_cnt;
    dms_ock_scrlock_context_t scrlock_ctx;
    dms_process_context_t *proc_ctx;
    dms_processor_t processors[CM_MAX_MES_MSG_CMD];
    dms_callback_t callback;
    reform_context_t reform_ctx;
    mfc_t mfc;
    uint64 min_scn[DMS_MAX_INSTANCES];
    uint8 enable_reform;
    uint8 gdb_in_progress;
    bool8 dms_init_finish;
    uint8 unused;
    cm_res_mgr_t cm_res_mgr;
    uint32 cluster_ver;
    void* mes_ptr;
    uint32 max_wait_time;
    atomic32_t cluster_proto_vers[DMS_MAX_INSTANCES];
} dms_instance_t;

#define DMS_MFC_OFF (g_dms.mfc.profile_tickets == 0)

#define DMS_PRIORITY_COMPRESS_LEVEL 0
#define DMS_BUFFER_POOL_NUM (3)
#define DMS_MSG_BUFFER_QUEUE_NUM (8)
#define DMS_FIRST_BUFFER_LENGTH (128)
#define DMS_SECOND_BUFFER_LENGTH (256)
#define DMS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define DMS_CKPT_NOTIFY_TASK_RATIO (1.0f / 4)
#define DMS_CLEAN_EDP_TASK_RATIO (1.0f / 4)
#define DMS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DMS_RECV_WORK_THREAD_RATIO (1.0f / 4)
#define DMS_FIRST_BUFFER_RATIO (1.0f / 4)
#define DMS_SECOND_BUFFER_RATIO (1.0f / 4)
#define DMS_THIRDLY_BUFFER_RATIO (1.0f / 2)
#define DMS_GLOBAL_CLUSTER_VER  (g_dms.cluster_ver)
#define DMS_WORK_THREAD_PRIO_0      2
#define DMS_WORK_THREAD_PRIO_1      1
#define DMS_WORK_THREAD_PRIO_2      1
#define DMS_CURR_PRIORITY_COUNT     4

#define DMS_RECV_THREAD_PRIO_0 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_0 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_1 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_1 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_2 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_2 * DMS_RECV_WORK_THREAD_RATIO))

#define DMS_CM_MAX_SESSIONS 16320
#define DMS_CS_TYPE_TCP (1)
#define DMS_CS_TYPE_RDMA (7)

extern dms_instance_t g_dms;

static inline void dms_proc_msg_ack(dms_process_context_t *process_ctx, dms_message_t *msg)
{
    /* pass */
}

static inline void dms_proc_broadcast_ack(dms_process_context_t *process_ctx, dms_message_t *msg)
{
    /* pass */
}

static inline void dms_proc_broadcast_ack2(dms_process_context_t *process_ctx, dms_message_t *msg)
{
    /* pass */
}

static inline void dms_proc_broadcast_ack3(dms_process_context_t *process_ctx, dms_message_t *msg)
{
    /* pass */
}

static inline const char *dms_get_mescmd_msg(uint32 cmd)
{
    return (cmd < MSG_CMD_CEIL) ? g_dms.processors[cmd].name : "INVALID";
}

unsigned int dms_get_mes_prio_by_cmd(uint32 cmd);
void dms_cast_mes_msg(mes_msg_t *mes_msg, dms_message_t *dms_msg);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_PROCESS_H__ */
