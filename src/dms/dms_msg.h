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
 * dms_msg.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_msg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_MSG_H__
#define __DMS_MSG_H__

#include "mes_type.h"
#include "mes.h"
#include "cm_log.h"
#include "dms_mfc.h"
#include "dms_api.h"
#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_WAIT_MAX_TIME       (10000) // ms
#define DMS_MSG_RETRY_TIME      (100) // ms
#define DMS_MSG_SLEEP_TIME      (1000) // ms
#define DMS_CVT_EXPIRE_TIME     (2 * DMS_WAIT_MAX_TIME) // ms
#define DMS_BROADCAST_ALL_INST  (0xFFFFFFFFFFFFFFFF)
#define DMS_MSG_CONFIRM_TIMES   (10)

#define DMS_GLOBAL_CLUSTER_VER  (g_dms.cluster_ver)

typedef enum en_msg_command {
    MSG_REQ_BEGIN = 0,
    MSG_REQ_ASK_MASTER_FOR_PAGE = MSG_REQ_BEGIN,
    MSG_REQ_ASK_OWNER_FOR_PAGE = 1,
    MSG_REQ_INVALIDATE_SHARE_COPY = 2,
    MSG_REQ_CLAIM_OWNER = 3,
    MSG_REQ_CR_PAGE = 4,
    MSG_REQ_ASK_MASTER_FOR_CR_PAGE = 5,
    MSG_REQ_ASK_OWNER_FOR_CR_PAGE = 6,
    MSG_REQ_CHECK_VISIBLE = 7,
    MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID = 8,
    MSG_REQ_BROADCAST = 9,
    MSG_REQ_TXN_INFO = 10,
    MSG_REQ_TXN_SNAPSHOT = 11,
    MSG_REQ_WAIT_TXN = 12,
    MSG_REQ_AWAKE_TXN = 13,
    MSG_REQ_MASTER_CKPT_EDP = 14,
    MSG_REQ_OWNER_CKPT_EDP = 15,
    MSG_REQ_MASTER_CLEAN_EDP = 16,
    MSG_REQ_OWNER_CLEAN_EDP = 17,
    MES_REQ_MGRT_MASTER_DATA = 18,
    MSG_REQ_RELEASE_OWNER = 19,
    MSG_REQ_BOC = 20,
    MSG_REQ_SMON_DLOCK_INFO = 21,
    MSG_REQ_SMON_DEADLOCK_SQL = 22,
    MSG_REQ_SMON_DEADLOCK_ITL = 23,
    MSG_REQ_SMON_DEADLOCK_CHECK_STATUS = 24,
    MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_TID = 25,
    MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_RM = 26,
    MSG_REQ_PAGE_REBUILD = 27,
    MSG_REQ_LOCK_REBUILD = 28,
    MSG_REQ_OPENGAUSS_TXN_STATUS = 29,
    MSG_REQ_OPENGAUSS_TXN_SNAPSHOT = 30,
    MSG_REQ_OPENGAUSS_TXN_UPDATE_XID = 31,
    MSG_REQ_OPENGAUSS_XID_CSN = 32,
    MSG_REQ_ASK_EDP_REMOTE = 33,
    MSG_REQ_SYNC_STEP = 34,
    MSG_REQ_SYNC_SHARE_INFO = 35,
    MSG_REQ_DMS_STATUS = 36,
    MSG_REQ_REFORM_PREPARE = 37,
    MSG_REQ_SYNC_NEXT_STEP = 38,
    MSG_REQ_PAGE = 39,
    MSG_REQ_SWITCHOVER = 40,
    MSG_REQ_CANCEL_REQUEST_RES = 41,
    MSG_REQ_OPENGAUSS_DDLLOCK = 42,
    MSG_REQ_CONFIRM_CVT = 43,
    MSG_REQ_CHECK_REFORM_DONE = 44,
    MSG_REQ_MAP_INFO = 45,
    MSG_REQ_DDL_SYNC = 46,
    MSG_REQ_REFORM_GCV_SYNC = 47,
    MSG_REQ_PAGE_VALIDATE = 48,
    MSG_REQ_INVALID_OWNER = 49,
    MSG_REQ_ASK_RES_OWNER_ID = 50,
    MSG_REQ_END,

    MSG_ACK_BEGIN = 128,
    MSG_ACK_CHECK_VISIBLE = MSG_ACK_BEGIN,
    MSG_ACK_PAGE_OWNER_ID = 129,
    MSG_ACK_BROADCAST = 130,
    MSG_ACK_BROADCAST_WITH_MSG = 131,
    MSG_ACK_PAGE_READY = 132,
    MSG_ACK_GRANT_OWNER = 133,
    MSG_ACK_ALREADY_OWNER = 134,
    MSG_ACK_CR_PAGE = 135,
    MSG_ACK_TXN_WAIT = 136,
    MSG_ACK_LOCK = 137,
    MSG_ACK_TXN_INFO = 138,
    MSG_ACK_TXN_SNAPSHOT = 139,
    MSG_ACK_WAIT_TXN = 140,
    MSG_ACK_AWAKE_TXN = 141,
    MSG_ACK_MASTER_CKPT_EDP = 142,
    MSG_ACK_OWNER_CKPT_EDP = 143,
    MSG_ACK_MASTER_CLEAN_EDP = 144,
    MSG_ACK_OWNER_CLEAN_EDP = 145,
    MSG_ACK_ERROR = 146,
    MSG_ACK_RELEASE_PAGE_OWNER = 147,
    MSG_ACK_INVLDT_SHARE_COPY = 148,
    MSG_ACK_BOC = 149,
    MSG_ACK_SMON_DLOCK_INFO = 150,
    MSG_ACK_SMON_DEADLOCK_SQL = 151,
    MSG_ACK_SMON_DEADLOCK_ITL = 152,
    MSG_ACK_SMON_DEADLOCK_CHECK_STATUS = 153,
    MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_MSG = 154,
    MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_RM = 155,
    MSG_ACK_OPENGAUSS_TXN_STATUS = 156,
    MSG_ACK_OPENGAUSS_TXN_SNAPSHOT = 157,
    MES_ACK_RELEASE_OWNER_BATCH = 158,
    MSG_ACK_OPENGAUSS_TXN_UPDATE_XID = 159,
    MSG_ACK_OPENGAUSS_XID_CSN = 160,
    MSG_ACK_OPENGAUSS_LOCK_BUFFER = 161,
    MSG_ACK_EDP_LOCAL = 162,
    MSG_ACK_EDP_READY = 163,
    MSG_ACK_REFORM_COMMON = 164,
    MSG_ACK_CONFIRM_CVT = 165,
    MSG_ACK_MAP_INFO = 166,
    MSG_ACK_REFORM_GCV_SYNC = 167,
    MSG_ACK_INVLD_OWNER = 168,
    MSG_ACK_ASK_RES_OWNER_ID = 169,
    MSG_ACK_END,
    MSG_CMD_CEIL = MSG_ACK_END
} msg_command_t;

typedef struct st_dms_process_context {
    void *db_handle;
    uint32 sess_id; // current session id
    uint8 inst_id;  // current instance id
} dms_process_context_t;

typedef struct st_msg_error {
    mes_message_head_t head;
    int32 code;
} msg_error_t;

typedef struct st_dms_ask_res_req {
    mes_message_head_t head;
    dms_lock_mode_t req_mode;
    dms_lock_mode_t curr_mode;
    dms_session_e sess_type;
    uint16 len;
    bool8 is_try;
    uint8 res_type;
    uint8 unused[4];
    date_t req_time;
    char resid[DMS_RESID_SIZE];
} dms_ask_res_req_t;

// msg for notifying instance load page from disk
typedef struct st_dms_ask_res_ack_load {
    mes_message_head_t head;
    uint64 master_lsn;
    uint64 scn;
    bool8 master_grant;
} dms_ask_res_ack_ld_t;

typedef struct st_dms_ask_res_ack {
    mes_message_head_t head;
    uint64 lsn;
    uint64 scn;
    uint64 edp_map;
#ifdef OPENGAUSS
    uint8 seg_fileno;
    uint32 seg_blockno;
#endif
} dms_ask_res_ack_t;

typedef struct st_dms_claim_owner_req {
    mes_message_head_t head;
    dms_lock_mode_t req_mode;
    dms_session_e sess_type;
    bool8  has_edp;  // previous owner has earlier dirty page
    uint8  res_type;
    uint16 len;
    uint64 lsn;
    char resid[DMS_RESID_SIZE];
} dms_claim_owner_req_t;

typedef struct st_dms_invld_req {
    mes_message_head_t head;
    uint8  is_try;
    uint8  res_type;
    uint16 len;
    bool32 invld_owner;
    dms_session_e sess_type;
    char   resid[DMS_RESID_SIZE];
} dms_invld_req_t;

typedef struct st_dms_invld_ack {
    mes_message_head_t head;
    int32 err_code;
} dms_invld_ack_t;

typedef struct st_dms_ask_res_owner_id_req {
    mes_message_head_t head;
    dms_session_e sess_type;
    uint16 len;
    uint8 res_type;
    uint8 unused;
    uint64 lsn;
    char resid[DMS_RESID_SIZE];
} dms_ask_res_owner_id_req_t;

typedef struct st_dms_ask_res_owner_id_ack {
    mes_message_head_t head;
    uint8 owner_id;
    uint8 unused[3];
} dms_ask_res_owner_id_ack_t;

typedef struct st_dms_res_req_info {
    uint8 req_id;
    uint8 owner_id;
    uint8 res_type;
    bool8 is_try;
    uint8 unused[2];
    uint16 req_sid;
    dms_session_e sess_type;
    uint64 req_rsn;
    uint32 len;
    dms_lock_mode_t req_mode;
    dms_lock_mode_t curr_mode;
    char resid[DMS_RESID_SIZE];
} dms_res_req_info_t;

typedef struct st_dms_cancel_request_res {
    mes_message_head_t head;
    dms_session_e sess_type;
    uint16 len;
    uint8  res_type;
    uint8  unused;
    char resid[DMS_RESID_SIZE];
}dms_cancel_request_res_t;

typedef struct st_dms_confirm_cvt_req {
    mes_message_head_t head;
    uint8 res_type;
    uint8 cvt_mode;
    char resid[DMS_RESID_SIZE];
}dms_confirm_cvt_req_t;

typedef enum en_confirm_result {
    CONFIRM_NONE   = 0,
    CONFIRM_READY  = 1,
    CONFIRM_CANCEL = 2
}confirm_result_t;

typedef struct st_dms_confirm_cvt_ack {
    mes_message_head_t head;
    uint32 result;
    uint64 lsn;
    uint64 edp_map;
    uint8 lock_mode;
}dms_confirm_cvt_ack_t;

typedef struct st_dms_query_owner_req  {
    mes_message_head_t head;
    char resid[DMS_RESID_SIZE];
} dms_query_owner_req_t;

typedef struct st_dms_query_owner_ack  {
    mes_message_head_t head;
    uint8 owner_id;
} dms_query_owner_ack_t;

static inline void cm_print_error_msg(const void *msg_data)
{
    msg_error_t *error_msg = (msg_error_t *)msg_data;
    char *message = (char *)error_msg + sizeof(msg_error_t);
    LOG_DEBUG_ERR("errno code: %d, errno info: %s", error_msg->code, message);
}

void cm_send_error_msg(mes_message_head_t *head, int32 err_code, char *err_info);
void cm_ack_result_msg(dms_process_context_t *process_ctx, mes_message_t *receive_msg, uint8 cmd, int32 ret);
void cm_ack_result_msg2(dms_process_context_t *process_ctx, mes_message_t *receive_msg, uint8 cmd, char *msg,
    uint32 len, char *ack_buf);

#define CM_CHK_RECV_MSG_SIZE(msg, len, free_msg, has_ack)                \
    do {                                                                 \
        if ((msg)->head->size < (len)) {                                 \
            LOG_DEBUG_ERR("recv invalid msg, cmd:%u size:%u len:%u",     \
                (uint32)(msg)->head->cmd, (uint32)(msg)->head->size, (uint32)(len)); \
            if (has_ack) {                                               \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg"); \
            }                                                            \
            if (free_msg) {                                              \
                mfc_release_message_buf((msg));                          \
            }                                                            \
            return ERRNO_DMS_MES_INVALID_MSG;                            \
        }                                                                \
    } while (0)

#define CM_CHK_RECV_MSG_SIZE_NO_ERR(msg, len, free_msg, has_ack)         \
    do {                                                                 \
        if ((msg)->head->size < (len)) {                                 \
            LOG_DEBUG_ERR("recv invalid msg, cmd:%u size:%u len:%u",     \
                (uint32)(msg)->head->cmd, (uint32)(msg)->head->size, (uint32)(len)); \
            if (has_ack) {                                               \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg"); \
            }                                                            \
            if (free_msg) {                                              \
                mfc_release_message_buf((msg));                          \
            }                                                            \
            return;                                                      \
        }                                                                \
    } while (0)

#define DMS_INIT_MESSAGE_HEAD(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid)  \
    do {                                                                                           \
        MES_INIT_MESSAGE_HEAD(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid); \
        (head)->cluster_ver = (uint32)(DMS_GLOBAL_CLUSTER_VER);                                    \
    } while (0)

static inline void dms_set_req_info(drc_request_info_t *req_info, uint8 req_id, uint16 sess_id, uint64 rsn,
    dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode, uint8 is_try, dms_session_e sess_type, date_t req_time)
{
    req_info->rsn = rsn;
    req_info->inst_id = req_id;
    req_info->sess_id = sess_id;
    req_info->is_try = is_try;
    req_info->curr_mode = curr_mode;
    req_info->req_mode = req_mode;
    req_info->sess_type = sess_type;
    req_info->req_time = req_time;
}

void dms_send_error_ack(uint8 src_inst, uint32 src_sid, uint8 dst_inst, uint32 dst_sid, uint64 dst_rsn, int32 ret);
void dms_claim_ownership(dms_context_t *dms_ctx, uint8 master_id,
    dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn);
int32 dms_request_res_internal(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode);
void dms_proc_ask_master_for_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg);
void dms_proc_ask_owner_for_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg);
void dms_proc_invld_req(dms_process_context_t *proc_ctx, mes_message_t *receive_msg);
void dms_proc_claim_ownership_req(dms_process_context_t *process_ctx, mes_message_t *receive_msg);
void dms_cancel_request_res(dms_context_t *dms_ctx);
void dms_proc_cancel_request_res(dms_process_context_t *proc_ctx, mes_message_t *receive_msg);
void dms_smon_entry(thread_t *thread);
void dms_proc_confirm_cvt_req(dms_process_context_t *proc_ctx, mes_message_t *receive_msg);
int32 dms_notify_invld_share_copy(uint32 inst_id, uint32 sess_id, char* resid, uint16 len,
    uint8 type, uint64 invld_insts, dms_session_e sess_type, uint64* succ_insts);
int32 dms_notify_invld_owner(dms_process_context_t* ctx, char* resid, uint16 len,
    uint8 type, dms_session_e sess_type, uint8 owner_id);
int32 dms_ask_res_owner_id_r(dms_context_t *dms_ctx, uint8 master_id, uint8 *owner_id);
void dms_proc_ask_res_owner_id(dms_process_context_t *dms_ctx, mes_message_t *receive_msg);
#ifdef __cplusplus
}
#endif

#endif /* __DMS_MSG_H__ */
