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
#include "fault_injection.h"

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

#define DMS_CM_MAX_SESSIONS 16320
#define DMS_CS_TYPE_TCP (1)
#define DMS_CS_TYPE_RDMA (7)

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
    uint64 min_scn[DMS_MAX_INSTANCES];
    uint8 gdb_in_progress;
    bool8 dms_init_finish;
    uint8 unused[2];
    cm_res_mgr_t cm_res_mgr;
    uint32 cluster_ver;
    void* mes_ptr;
    uint32 max_wait_time;
    atomic32_t cluster_proto_vers[DMS_MAX_INSTANCES];
    uint32 max_alive_time_for_abnormal_status;
    ddes_fi_context_t fi_ctx;
    dms_msg_stats_t msg_stats[DMS_CM_MAX_SESSIONS];
    dms_driver_ping_info_t dms_driver_ping_info;
    memory_context_t *drc_mem_context;
} dms_instance_t;

typedef enum en_dms_msg_buffer_number {
    DMS_MSG_BUFFER_NO_0 = 0,
    DMS_MSG_BUFFER_NO_1,
    DMS_MSG_BUFFER_NO_2,
    DMS_MSG_BUFFER_NO_CEIL
} dms_msg_buffer_number_e;

#define DMS_PRIORITY_COMPRESS_LEVEL 0
#define DMS_MSG_BUFFER_QUEUE_NUM (8)
#define DMS_MSG_BUFFER_QUEUE_NUM_PRIO_6 (16)
#define DMS_FIRST_BUFFER_LENGTH (256)
#define DMS_SECOND_BUFFER_LENGTH (512)
#define DMS_THIRD_BUFFER_LENGTH (SIZE_K(32) + 256)
#define DMS_FIRST_BUFFER_RATIO (0.25)
#define DMS_SECOND_BUFFER_RATIO (0.25)
#define DMS_THIRDLY_BUFFER_RATIO (0.5)

#define DMS_CKPT_NOTIFY_TASK_RATIO (1.0f / 32)
#define DMS_CLEAN_EDP_TASK_RATIO (1.0f / 32)
#define DMS_DERIVED_TASK_RATIO (1.0f / 8)
#define DMS_TXN_INFO_TASK_RATIO (1.0f / 16)
#define DMS_RECV_WORK_THREAD_RATIO (1.0f / 4)

#define DMS_WORK_THREAD_COUNT       (dms_profile->enable_mes_task_threadpool == CM_TRUE ? \
    dms_profile->mes_task_worker_max_cnt : dms_profile->work_thread_cnt)
#define DMS_CURR_PRIORITY_COUNT     7
#define DMS_WORK_THREAD_PRIO_0      2
#define DMS_WORK_THREAD_PRIO_1      1
#define DMS_WORK_THREAD_PRIO_2      1
#define DMS_WORK_THREAD_PRIO_3      MAX(1, (uint32)(DMS_WORK_THREAD_COUNT * DMS_CKPT_NOTIFY_TASK_RATIO))
#define DMS_WORK_THREAD_PRIO_4      MAX(1, (uint32)(DMS_WORK_THREAD_COUNT * DMS_CLEAN_EDP_TASK_RATIO))
#define DMS_WORK_THREAD_PRIO_5      MAX(1, (uint32)(DMS_WORK_THREAD_COUNT * DMS_DERIVED_TASK_RATIO))

#define DMS_RECV_THREAD_PRIO_0 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_0 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_1 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_1 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_2 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_2 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_3 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_3 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_4 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_4 * DMS_RECV_WORK_THREAD_RATIO))
#define DMS_RECV_THREAD_PRIO_5 MAX(1, (uint32)(DMS_WORK_THREAD_PRIO_5 * DMS_RECV_WORK_THREAD_RATIO))

#define DMS_WORK_THREAD_PRIO_0_MIN_CNT 1
#define DMS_WORK_THREAD_PRIO_1_MIN_CNT 1
#define DMS_WORK_THREAD_PRIO_2_MIN_CNT 1

#ifdef OPENGAUSS
#define DMS_WORK_THREAD_PRIO_3_MIN_CNT 0
#define DMS_WORK_THREAD_PRIO_4_MIN_CNT 0
#else
#define DMS_WORK_THREAD_PRIO_3_MIN_CNT 1
#define DMS_WORK_THREAD_PRIO_4_MIN_CNT 1
#endif

#define DMS_WORK_THREAD_PRIO_5_MIN_CNT 1
#define DMS_WORK_THREAD_MAJOR_MIN_CNT 1
#define DMS_WORK_THREAD_MIN_CNT (DMS_WORK_THREAD_PRIO_0_MIN_CNT + DMS_WORK_THREAD_PRIO_1_MIN_CNT + \
    DMS_WORK_THREAD_PRIO_2_MIN_CNT + DMS_WORK_THREAD_PRIO_3_MIN_CNT + DMS_WORK_THREAD_PRIO_4_MIN_CNT + \
    DMS_WORK_THREAD_PRIO_5_MIN_CNT + DMS_WORK_THREAD_MAJOR_MIN_CNT)

#define DMS_WORK_THREAD_PRIO_0_RATIO (2.0f / 32)
#define DMS_WORK_THREAD_PRIO_1_RATIO (1.0f / 32)
#define DMS_WORK_THREAD_PRIO_2_RATIO (1.0f / 32)
#define DMS_WORK_THREAD_PRIO_3_RATIO DMS_CKPT_NOTIFY_TASK_RATIO
#define DMS_WORK_THREAD_PRIO_4_RATIO DMS_CLEAN_EDP_TASK_RATIO
#define DMS_WORK_THREAD_PRIO_5_RATIO DMS_DERIVED_TASK_RATIO

#define DMS_PRIO_0_MSG_NUM_CEILING 2
#define DMS_PRIO_0_MSG_NUM_FLOOR 0
#define DMS_PRIO_2_MSG_NUM_CEILING 2
#define DMS_PRIO_2_MSG_NUM_FLOOR 0
#define DMS_DEFAULT_MSG_NUM_CEILING 5
#define DMS_DEFAULT_MSG_NUM_FLOOR 0
#define DEFAULT_TIME_FOR_ABNORMAL_STATUS 10

#define DMS_GLOBAL_CLUSTER_VER  (g_dms.cluster_ver)

#define DMS_LOG_BACKUP_FILE_COUNT   (10)
#define DMS_MAX_LOG_FILE_SIZE       ((uint64)SIZE_M(1024) * 1)
#define DMS_MAX_DYN_TRC_WARN_BUF    "DMS_MAX_DYN_TRACE_SIZE reached:"
#define DMS_MAX_DYN_TRC_WARN_SZ     31
#define DMS_MALLOC_ALIGN_OFFSET     16

extern dms_instance_t g_dms;

typedef enum en_dms_malloc_fun_type {
    MALLOC_TYPE_OS = 0,
    MALLOC_TYPE_REGIST = 1,
    MALLOC_TYPE_CONTEXT = 2,
    MALLOC_TYPE_CEIL
} dms_malloc_fun_type_t;

typedef struct st_dms_buffer_header {
    dms_malloc_fun_type_t type;
    char padding[DMS_MALLOC_ALIGN_OFFSET - sizeof(dms_malloc_fun_type_t)];
} dms_buffer_header_t;

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
void *dms_malloc(memory_context_t *context, size_t size);
void dms_free(void *ptr);
void dms_dynamic_trace_cache_inner(dms_log_level_t log_level, char *buf_text, uint32 buf_size, bool8 is_head);

#define DMS_FREE_PROT_PTR(pointer) \
    do {                           \
        if ((pointer) != NULL) {   \
            dms_free(pointer);     \
            (pointer) = NULL;      \
        }                          \
    } while (0)

static inline void dms_get_one_thread(thread_set_t *thread_set, thread_t *thread,
    char *thread_name_format, char *thread_name)
{
    if (thread_set->thread_count >= MAX_DMS_THREAD_NUM) {
        return;
    }
    errno_t err = sprintf_s(thread_set->threads[thread_set->thread_count].thread_name,
        DMS_MAX_NAME_LEN, thread_name_format, thread_name);
    DMS_SECUREC_CHECK_SS(err);
    thread_set->threads[thread_set->thread_count].thread_info = (void *)thread;
    thread_set->thread_count++;
}

void dms_global_res_reinit(drc_global_res_map_t *global_res);
int dms_dyn_trc_init_logger_handle();

#ifdef __cplusplus
}
#endif

#endif /* __DMS_PROCESS_H__ */
