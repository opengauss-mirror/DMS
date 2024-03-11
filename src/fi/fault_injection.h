/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * fault_injection.h
 * the ways to perform fault injection:
 * compile DEBUG, which registers all FI triggers at set_dms_fi
 *
 * -------------------------------------------------------------------------
 */
#ifndef FAULT_INJECTION_H
#define FAULT_INJECTION_H

#include "cm_file.h"
#include "cm_config.h"
#include "dms_api.h"
#include "dms_msg.h"
#include "dms_msg_command.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_fi_context {
    dms_fi_config_t ss_fi_packet_loss;
    dms_fi_config_t ss_fi_net_latency;
    dms_fi_config_t ss_fi_cpu_latency;
    dms_fi_config_t ss_fi_process_fault;
    dms_fi_config_t ss_fi_custom_fault;
} dms_fi_context_t;

typedef enum en_dms_fi_point_name {
    DMS_FI_ENTRY_BEGIN = 0,
    DMS_FI_REQ_ASK_MASTER_FOR_PAGE = DMS_FI_ENTRY_BEGIN,
    DMS_FI_REQ_ASK_OWNER_FOR_PAGE = 1,
    DMS_FI_REQ_INVALIDATE_SHARE_COPY = 2,
    DMS_FI_CLAIM_OWNER = 3,
    DMS_FI_REQ_CR_PAGE = 4,
    DMS_FI_REQ_ASK_MASTER_FOR_CR_PAGE = 5,
    DMS_FI_REQ_ASK_OWNER_FOR_CR_PAGE = 6,
    DMS_FI_REQ_CHECK_VISIBLE = 7,
    DMS_FI_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID = 8,
    DMS_FI_REQ_BROADCAST = 9,
    DMS_FI_REQ_TXN_INFO = 10,
    DMS_FI_REQ_TXN_SNAPSHOT = 11,
    DMS_FI_REQ_WAIT_TXN = 12,
    DMS_FI_REQ_AWAKE_TXN = 13,
    DMS_FI_REQ_MASTER_CKPT_EDP = 14,
    DMS_FI_REQ_OWNER_CKPT_EDP = 15,
    DMS_FI_REQ_MASTER_CLEAN_EDP = 16,
    DMS_FI_REQ_OWNER_CLEAN_EDP = 17,
    DMS_FI_REQ_MGRT_MASTER_DATA = 18,
    DMS_FI_REQ_RELEASE_OWNER = 19,
    DMS_FI_REQ_BOC = 20,
    DMS_FI_REQ_CONFIRM_CVT = 21,
    DMS_FI_REQ_DDL_SYNC = 22,
    DMS_FI_REQ_INVALID_OWNER = 23,
    DMS_FI_REQ_ASK_RES_OWNER_ID = 24,
    DMS_FI_REQ_PROTOCOL_MAINTAIN_VERSION = 25,
    DMS_FI_REQ_CREATE_GLOBAL_XA_RES = 26,
    DMS_FI_REQ_DELETE_GLOBAL_XA_RES = 27,
    DMS_FI_REQ_ASK_XA_OWNER_ID = 28,
    DMS_FI_REQ_END_XA = 29,
    DMS_FI_REQ_ASK_XA_IN_USE = 30,
    DMS_FI_REQ_MERGE_XA_OWNERS = 31,
    DMS_FI_REQ_XA_REBUILD = 32,
    DMS_FI_REQ_XA_OWNERS = 33,
    DMS_FI_REQ_RECYCLE = 34,

    DMS_FI_ACK_CHECK_VISIBLE = 35,
    DMS_FI_ACK_PAGE_OWNER_ID = 36,
    DMS_FI_ACK_BROADCAST = 37,
    DMS_FI_ACK_BROADCAST_WITH_MSG = 38,
    DMS_FI_ACK_PAGE_READY = 39,
    DMS_FI_ACK_GRANT_OWNER = 40,
    DMS_FI_ACK_ALREADY_OWNER = 41,
    DMS_FI_ACK_CR_PAGE = 42,
    DMS_FI_ACK_TXN_WAIT = 43,
    DMS_FI_ACK_LOCK = 44,
    DMS_FI_ACK_TXN_INFO = 45,
    DMS_FI_ACK_TXN_SNAPSHOT = 46,
    DMS_FI_ACK_WAIT_TXN = 47,
    DMS_FI_ACK_AWAKE_TXN = 48,
    DMS_FI_ACK_MASTER_CKPT_EDP = 49,
    DMS_FI_ACK_OWNER_CKPT_EDP = 50,
    DMS_FI_ACK_MASTER_CLEAN_EDP = 51,
    DMS_FI_ACK_OWNER_CLEAN_EDP = 52,
    DMS_FI_ACK_ERROR = 53,
    DMS_FI_ACK_RELEASE_PAGE_OWNER = 54,
    DMS_FI_ACK_INVLDT_SHARE_COPY = 55,
    DMS_FI_ACK_BOC = 56,
    DMS_FI_ACK_EDP_LOCAL = 57,
    DMS_FI_ACK_EDP_READY = 58,
    DMS_FI_ACK_INVLD_OWNER = 59,
    DMS_FI_ACK_ASK_RES_OWNER_ID = 60,
    DMS_FI_ACK_CREATE_GLOBAL_XA_RES = 61,
    DMS_FI_ACK_DELETE_GLOBAL_XA_RES = 62,
    DMS_FI_ACK_ASK_XA_OWNER_ID = 63,
    DMS_FI_ACK_END_XA = 64,
    DMS_FI_ACK_XA_IN_USE = 65,
    DMS_FI_ENTRY_END
} dms_fi_point_name_e;

#if defined _DEBUG

#define DMS_FI_PROB_NEVER       0
#define DMS_FI_PROB_ALWAYS      100
#define FI_NORMAL_FLAG          0
#define FI_PACKET_LOSS_FLAG     1
#define FI_NET_LATENCY_FLAG     2
#define FI_CPU_LATENCY_FLAG     4
#define FI_PROCESS_FAULT_FLAG   8
#define FI_CUSTOM_FAULT_FLAG    0x10
#define FI_TYPE_NUM_MAX         5

typedef struct st_fi_type_map {
    int fi_type;
    int fi_flag;
    dms_fi_config_t *config;
} dms_fi_type_mapping_t;


extern dms_fi_type_mapping_t g_fi_type_map[];

dms_fi_entry *dms_fi_get_entry(unsigned int fi_entry);
int dms_fi_get_tls_trigger();
void dms_fi_set_tls_trigger(int val);
int dms_fi_get_tls_trigger_custom();
void dms_fi_set_tls_trigger_custom(int val);
void fault_injection_call(unsigned int point, ...);

#define FAULT_INJECTION_ACTIVATE(point, flag)         \
    do {                                               \
        dms_fi_entry *entry = dms_fi_get_entry(point); \
        if (entry != NULL) {                           \
            entry->faultFlags |= flag;                 \
            entry->pointId = point;                    \
        }                                              \
    } while (0)


#define FAULT_INJECTION_INACTIVE(point, flag)       \
    do {                                               \
        dms_fi_entry *entry = dms_fi_get_entry(point); \
        if (entry != NULL) {                           \
            entry->faultFlags &= (~flag);              \
        }                                              \
    } while (0)

#define FAULT_INJECTION_ACTION_TRIGGER(action)         \
    do {                                               \
        if (dms_fi_get_tls_trigger() == CM_TRUE) {     \
            dms_fi_set_tls_trigger(CM_FALSE);          \
            LOG_DEBUG_INF("[DMS_FI] fi action happens at %s", __FUNCTION__);  \
            action;                                    \
        }                                              \
    } while (0)

#define FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(action)      \
    do {                                                   \
        if (dms_fi_get_tls_trigger_custom() == CM_TRUE) {  \
            dms_fi_set_tls_trigger_custom(CM_FALSE);       \
            LOG_DEBUG_INF("[DMS_FI] fi cust action happens at %s", __FUNCTION__);  \
            action;                                        \
        }                                                  \
    } while (0)

#define DMS_FAULT_INJECTION_CALL(point, ...)                \
    do {                                                \
        dms_fi_entry *entry = dms_fi_get_entry(point);  \
        if (entry != NULL && entry->faultFlags) {       \
            fault_injection_call(point, ##__VA_ARGS__); \
        }                                               \
    } while (0)

#else


#define FAULT_INJECTION_ACTIVATE(point, flag)
#define FAULT_INJECTION_INACTIVE(point, flag)
#define FAULT_INJECTION_ACTION_TRIGGER(action)
#define FAULT_INJECTION_ACTION_TRIGGER_CUSTOM(action)
#define DMS_FAULT_INJECTION_CALL(point, ...)

#endif

#ifdef __cplusplus
}
#endif

#endif // FAULT_INJECTION_H