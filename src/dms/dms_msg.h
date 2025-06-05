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

#include "mes_interface.h"
#include "cm_log.h"
#include "dms_mfc.h"
#include "dms_api.h"
#include "drc.h"
#include "dms_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_WAIT_MAX_TIME       g_dms.max_wait_time
#define DMS_MSG_RETRY_TIME      (100) // ms
#define DMS_MSG_SLEEP_TIME      (1000) // ms
#define DMS_CVT_EXPIRE_TIME     (2 * DMS_WAIT_MAX_TIME) // ms
#define DMS_BROADCAST_ALL_INST  (0xFFFFFFFFFFFFFFFF)
#define DMS_MSG_CONFIRM_TIMES   (10)

#define DMS_EVENT_MONITOR_TIMEOUT  (20 * MICROSECS_PER_SECOND) /* 20s */
#define DMS_EVENT_MONITOR_INTERVAL (10 * MICROSECS_PER_SECOND) /* 10s */

#define DMS_STANDBY_GET_NODE_DATA_LEN(node_cnt)  ((node_cnt) + 1)  /* data 0: timestamp, other: node lfn */

/* biggest: pcr page ack: head + ack + page */
#define DMS_MESSAGE_BUFFER_SIZE (uint32)(SIZE_K(32) + 64)

typedef struct st_msg_error {
    dms_message_head_t head;
    int32 code;
} msg_error_t;

typedef struct st_dms_ask_res_req {
    dms_message_head_t head;
    union {
        struct {
            uint8   inst_id;            /* the instance that the request comes from */
            uint8   curr_mode;          /* current holding lock mode in request instance */
            uint8   req_mode;           /* the expected lock mode that request instance wants */
            uint8   is_try;             /* if is try request */
            uint8   intercept_type;
            uint8   is_upgrade;         /* used for table lock upgrade */
            uint16  sess_id;            /* the session id that the request comes from */
            uint64  ruid;               /* request packet ruid */
            uint32  srsn;
            date_t  req_time;
            uint32  req_proto_ver;
            dms_session_e sess_type;    /* session type */
        };
        drc_request_info_t drc_reg_info;
    };
    uint16 len;
    uint8  res_type;
    uint8  unused;
    uint64 scn; /* sync SCN to remote instance */
    char resid[DMS_RESID_SIZE];
} dms_ask_res_req_t;

// msg for notifying instance load page from disk
typedef struct st_dms_ask_res_ack_load {
    dms_message_head_t head;
    uint64 master_lsn;
    uint64 scn;
    bool8 master_grant;
} dms_ask_res_ack_ld_t;

// msg for notifying instance is already resource owner
typedef struct st_dms_already_owner_ack {
    dms_message_head_t head;
    uint64 scn;
} dms_already_owner_ack_t;

typedef struct st_dms_ask_res_ack {
    dms_message_head_t head;
    uint64 lsn;
    uint64 scn;
    uint64 edp_map;
#ifdef OPENGAUSS
    uint8 seg_fileno;
    uint32 seg_blockno;
    bool8 need_check_pincount;
    uint64 lsn_on_disk;
#endif
    bool8 enable_cks; // enable checksum
    uint8 unused;
    uint16 checksum;
#ifndef OPENGAUSS
    uint8 node_id;
    uint8 node_cnt;
    uint64 node_lfn;
#endif
} dms_ask_res_ack_t;

typedef struct st_dms_ask_res_ack_wrapper {
    dms_ask_res_ack_t res_ack;
    uint64 data[DMS_MAX_INSTANCES + 1]; /* index 0: timestamp, other: node_lfn */
} dms_ask_res_ack_wrapper;

typedef struct st_dms_claim_owner_req {
    dms_message_head_t head;
    dms_lock_mode_t req_mode;
    dms_session_e sess_type;
    bool8  has_edp;  // previous owner has earlier dirty page
    uint8  res_type;
    uint16 len;
    uint64 lsn;
    char resid[DMS_RESID_SIZE];
    uint32 srsn;
} dms_claim_owner_req_t;

typedef struct st_dms_invld_req {
    dms_message_head_t head;
    uint64 scn; /* sync SCN to remote instance */
    uint8  is_try;
    uint8  res_type;
    uint16 len;
    bool32 invld_owner;
    dms_session_e sess_type;
    char   resid[DMS_RESID_SIZE];
} dms_invld_req_t;

typedef struct st_dms_ask_res_owner_id_req {
    dms_message_head_t head;
    dms_session_e sess_type;
    uint16 len;
    uint8 res_type;
    uint8 intercept_type;
    uint64 lsn;
    char resid[DMS_RESID_SIZE];
} dms_ask_res_owner_id_req_t;

typedef struct st_dms_ask_res_owner_id_ack {
    dms_message_head_t head;
    uint8 owner_id;
    uint8 unused[3];
} dms_ask_res_owner_id_ack_t;

typedef struct st_dms_res_req_info {
    uint8 req_id;
    uint8 owner_id;
    uint8 res_type;
    bool8 is_try;
    uint8 unused;
    uint8 intercept_type;
    uint16 req_sid;
    dms_session_e sess_type;
    uint64 req_ruid;
    uint32 len;
    dms_lock_mode_t req_mode;
    dms_lock_mode_t curr_mode;
    char resid[DMS_RESID_SIZE];
    uint32 req_proto_ver;
    uint64 seq;
} dms_res_req_info_t;

typedef struct st_dms_cancel_request_res {
    dms_message_head_t head;
    union {
        struct {
            uint8   inst_id;            /* the instance that the request comes from */
            uint8   curr_mode;          /* current holding lock mode in request instance */
            uint8   req_mode;           /* the expected lock mode that request instance wants */
            uint8   is_try;             /* if is try request */
            uint8   intercept_type;
            uint8   is_upgrade;         /* used for table lock upgrade */
            uint16  sess_id;            /* the session id that the request comes from */
            uint64  ruid;               /* request packet ruid */
            uint32  srsn;
            date_t  req_time;
            uint32  req_proto_ver;
            dms_session_e sess_type;    /* session type */
        };
        drc_request_info_t drc_reg_info;
    };
    uint16 len;
    uint8  res_type;
    uint8  unused;
    char resid[DMS_RESID_SIZE];
} dms_cancel_request_res_t;

typedef struct st_dms_confirm_cvt_req {
    dms_message_head_t head;
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
    dms_message_head_t head;
    uint32 result;
    uint64 lsn;
    uint64 edp_map;
    uint8 lock_mode;
}dms_confirm_cvt_ack_t;

typedef struct st_dms_query_owner_req  {
    dms_message_head_t head;
    char resid[DMS_RESID_SIZE];
} dms_query_owner_req_t;

typedef struct st_dms_query_owner_ack  {
    dms_message_head_t head;
    uint8 owner_id;
} dms_query_owner_ack_t;

typedef enum en_dms_xa_oper_type {
    DMS_XA_OPER_CREATE = 0,
    DMS_XA_OPER_DELETE = 1
} dms_xa_oper_type_t;

typedef struct st_dms_xa_res_req {
    dms_message_head_t head;
    uint8 undo_set_id;
    drc_global_xid_t xa_xid;
    dms_xa_oper_type_t oper_type;
    bool32 check_xa_drc;
} dms_xa_res_req_t;

typedef struct st_dms_xa_res_ack {
    dms_message_head_t head;
    uint32 return_code;
} dms_xa_res_ack_t;

typedef struct st_dms_ask_xa_owner_req {
    dms_message_head_t head;
    dms_session_e sess_type;
    drc_global_xid_t xa_xid;
    bool32 check_xa_drc;
} dms_ask_xa_owner_req_t;

typedef struct st_dms_ask_xa_owner_ack {
    dms_message_head_t head;
    uint8 owner_id;
    uint8 unused[3];
} dms_ask_xa_owner_ack_t;

typedef struct st_dms_ask_xa_inuse_req {
    dms_message_head_t head;
    dms_session_e sess_type;
    drc_global_xid_t xa_xid;
} dms_ask_xa_inuse_req_t;

typedef struct st_dms_ask_xa_inuse_ack {
    dms_message_head_t head;
    bool8 inuse;
    uint8 unused[3];
} dms_ask_xa_inuse_ack_t;

typedef struct st_dms_end_xa_req {
    dms_message_head_t head;
    drc_global_xid_t xa_xid;
    bool8 is_commit;
    uint64 flags;
    uint64 commit_scn;
} dms_end_xa_req_t;

typedef struct st_dms_end_xa_ack {
    dms_message_head_t head;
    int32 return_code;
} dms_end_xa_ack_t;

typedef struct st_dms_common_ack {
    dms_message_head_t head;
    int32 ret;
} dms_common_ack_t;

typedef struct st_dms_invld_ack {
    dms_common_ack_t common_ack;
    uint64 scn;
} dms_invld_ack_t;

typedef struct st_dms_chk_ownership_req {
    dms_message_head_t head;
    char resid[DMS_RESID_SIZE];
    uint16 len;
    uint8  inst_id;
    uint8  curr_mode;
} dms_chk_ownership_req_t;

static inline void cm_print_error_msg(const void *msg_data)
{
    msg_error_t *error_msg = (msg_error_t *)msg_data;
    char *message = (char *)error_msg + sizeof(msg_error_t);
    LOG_DEBUG_ERR("errno code: %d, errno info: %s", error_msg->code, message);
}

static inline void cm_print_error_msg_and_throw_error(const void *msg_data)
{
    dms_message_head_t *head = (dms_message_head_t*)msg_data;
    if (head->size < sizeof(msg_error_t)) {
        LOG_DYN_TRC_ERR("invlid err msg size=%u", head->size);
    } else if (head->size == sizeof(msg_error_t)) {
        msg_error_t *error_msg = (msg_error_t *)msg_data;
        LOG_DYN_TRC_ERR("errcode=%d err=null", error_msg->code);
    } else {
        msg_error_t *error_msg = (msg_error_t *)msg_data;
        char *message = (char*)error_msg + sizeof(msg_error_t);
        LOG_DYN_TRC_ERR("errcode=%d errmsg=%s", error_msg->code, message);
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, message);
    }
}

#define CM_CHK_RESPONSE_SIZE_(msg, len, has_ack, release_msg)                                                   \
    do {                                                                                                        \
        if ((msg)->head->cmd == MSG_ACK_ERROR) {                                                                \
            cm_print_error_msg((msg)->buffer);                                                                  \
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_MSG_ACK, (msg)->buffer + sizeof(msg_error_t));                     \
            (release_msg) ? mfc_release_response(msg) : (void)0;                                                \
            return ERRNO_DMS_COMMON_MSG_ACK;                                                                    \
        }                                                                                                       \
        if ((msg)->head->size < (len)) {                                                                        \
            LOG_DEBUG_ERR("recv invalid msg, cmd:%u size:%u len:%u", (uint32)(msg)->head->cmd,                  \
                (uint32)(msg)->head->size, (uint32)(len));                                                      \
            if (has_ack) {                                                                                      \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg");                  \
            }                                                                                                   \
            (release_msg) ? mfc_release_response(msg) : (void)0;                                                \
            return ERRNO_DMS_MES_INVALID_MSG;                                                                   \
        }                                                                                                       \
    } while (0)

#define CM_CHK_RESPONSE_SIZE(msg, len, has_ack) CM_CHK_RESPONSE_SIZE_((msg), (len), (has_ack), (CM_TRUE))
#define CM_CHK_RESPONSE_SIZE2(msg, len, has_ack) CM_CHK_RESPONSE_SIZE_((msg), (len), (has_ack), (CM_FALSE))

#define CM_CHK_PROC_MSG_SIZE(msg, len, has_ack)                                                                 \
    do {                                                                                                        \
        if ((msg)->head->size < (len)) {                                                                        \
            LOG_DEBUG_ERR("recv invalid msg, cmd:%u size:%u len:%u",                                            \
                (uint32)(msg)->head->cmd, (uint32)(msg)->head->size, (uint32)(len));                            \
            if (has_ack) {                                                                                      \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg");                  \
            }                                                                                                   \
            return ERRNO_DMS_MES_INVALID_MSG;                                                                   \
        }                                                                                                       \
    } while (0)

/* do not release processed message */
#define CM_CHK_PROC_MSG_SIZE_NO_ERR(msg, len, has_ack)                                                          \
    do {                                                                                                        \
        if ((msg)->head->size < (len)) {                                                                        \
            LOG_DEBUG_ERR("recv invalid msg, cmd:%u size:%u len:%u",                                            \
                (uint32)(msg)->head->cmd, (uint32)(msg)->head->size, (uint32)(len));                            \
            if (has_ack) {                                                                                      \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg");                  \
            }                                                                                                   \
            return;                                                                                             \
        }                                                                                                       \
    } while (0)

#define CM_CHECK_PROC_MSG_RES_TYPE_NO_ERROR(msg, res_type, has_ack)                                             \
    do {                                                                                                        \
        if ((res_type) != DRC_RES_PAGE_TYPE && (res_type) != DRC_RES_LOCK_TYPE &&                               \
            (res_type) != DRC_RES_GLOBAL_XA_TYPE && (res_type) != DRC_RES_ALOCK_TYPE) {                         \
            LOG_DEBUG_ERR("recv invalid msg, res_type:%u", res_type);                                           \
            if (has_ack) {                                                                                      \
                cm_send_error_msg((msg)->head, ERRNO_DMS_MES_INVALID_MSG, "recv invalid msg");                  \
            }                                                                                                   \
            return;                                                                                             \
        }                                                                                                       \
    } while (0)

#define DMS_INIT_MESSAGE_HEAD(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid)               \
    do {                                                                                                        \
        dms_check_message_cmd(v_cmd, CM_TRUE);                                                                  \
        DMS_SECUREC_CHECK(memset_s((head), DMS_MSG_HEAD_SIZE, 0, DMS_MSG_HEAD_SIZE));                           \
        (head)->msg_proto_ver = dms_get_send_proto_version_by_cmd((v_cmd), ((uint8)v_dst_inst));                \
        (head)->sw_proto_ver = dms_get_node_proto_version(v_src_inst);                                          \
        (head)->cmd = (uint32)(v_cmd);                                                                          \
        (head)->flags = (uint32)(v_flags);                                                                      \
        (head)->ruid = 0;                                                                                       \
        (head)->src_inst = (uint8)(v_src_inst);                                                                 \
        (head)->dst_inst = (uint8)(v_dst_inst);                                                                 \
        (head)->cluster_ver = DMS_GLOBAL_CLUSTER_VER;                                                           \
        (head)->src_sid = (uint16)(v_src_sid);                                                                  \
        (head)->dst_sid = (uint16)(v_dst_sid);                                                                  \
    } while (0)

#define DMS_INIT_MESSAGE_HEAD2(head, v_cmd, v_flags, v_src_inst, v_dst_inst, v_src_sid, v_dst_sid,              \
    v_msg_proto_ver, v_size)                                                                                    \
    do {                                                                                                        \
        dms_check_message_cmd(v_cmd, CM_TRUE);                                                                  \
        (head)->msg_proto_ver = (uint32)v_msg_proto_ver;                                                        \
        (head)->sw_proto_ver = dms_get_node_proto_version(v_src_inst);                                          \
        (head)->cmd = (uint32)(v_cmd);                                                                          \
        (head)->flags = (uint32)(v_flags);                                                                      \
        (head)->ruid = 0;                                                                                       \
        (head)->src_inst = (uint8)(v_src_inst);                                                                 \
        (head)->dst_inst = (uint8)(v_dst_inst);                                                                 \
        (head)->size = (uint16)(v_size);                                                                        \
        (head)->cluster_ver = DMS_GLOBAL_CLUSTER_VER;                                                           \
        (head)->src_sid = (uint16)(v_src_sid);                                                                  \
        (head)->dst_sid = (uint16)(v_dst_sid);                                                                  \
        (head)->tickets = 0;                                                                                    \
        (head)->unused = 0;                                                                                     \
        DMS_SECUREC_CHECK(memset_s((head)->reserved, DMS_MSG_HEAD_UNUSED_SIZE, 0, DMS_MSG_HEAD_UNUSED_SIZE));   \
    } while (0)

#define DMS_MESSAGE_BODY(msg) ((msg)->buffer + sizeof(dms_message_head_t))

void cm_send_error_msg(dms_message_head_t *head, int32 err_code, char *err_info);
void cm_ack_result_msg(dms_process_context_t *process_ctx, dms_message_t *receive_msg, uint32 cmd, int32 ret);
void cm_ack_result_msg2(dms_process_context_t *process_ctx, dms_message_t *receive_msg, uint32 cmd, char *msg,
    uint32 len, char *ack_buf);

void dms_send_error_ack(dms_process_context_t *ctx, uint8 dst_inst, uint32 dst_sid, uint64 dst_ruid, int32 ret,
    uint32 req_proto_ver);
void dms_claim_ownership(dms_context_t *dms_ctx, uint8 master_id,
    dms_lock_mode_t mode, bool8 has_edp, uint64 page_lsn);
int32 dms_request_res_internal(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode);
void dms_proc_ask_master_for_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
void dms_proc_ask_owner_for_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
void dms_proc_invld_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
void dms_proc_claim_ownership_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dms_cancel_request_res(dms_context_t *dms_ctx);
void dms_proc_cancel_request_res(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
void dms_smon_entry(thread_t *thread);
void dms_proc_confirm_cvt_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
int32 dms_invalidate_ownership(dms_process_context_t* ctx, char* resid, uint16 len,
    uint8 type, dms_session_e sess_type, uint8 owner_id, uint64 seq);
int32 dms_invalidate_share_copy(dms_process_context_t* ctx, char* resid, uint16 len,
    uint8 type, uint64 copy_insts, dms_session_e sess_type, bool8 is_try, bool8 can_direct, uint64 seq);
int32 dms_ask_res_owner_id_r(dms_context_t *dms_ctx, uint8 master_id, uint8 *owner_id);
void dms_proc_ask_res_owner_id(dms_process_context_t *dms_ctx, dms_message_t *receive_msg);
void dms_proc_removed_req(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
dms_message_head_t* get_dms_head(dms_message_t *msg);
bool8 dms_cmd_is_broadcast(uint32 cmd);
bool8 dms_cmd_is_req(uint32 cmd);
bool8 dms_cmd_need_ack(uint32 cmd);
void dms_proc_check_page_ownership(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);
void dms_build_req_info_local(dms_context_t *dms_ctx, dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode,
    drc_request_info_t *req_info);
/*
* The following structs are used for communication
* between Primary and Standby to obtain relevant
* information about buffers on other nodes.
*/
typedef struct st_dms_req_buf_info {
    dms_message_head_t      head;
    unsigned long long      copy_insts;
    unsigned char           claimed_owner;
    unsigned char           master_id;
    unsigned char           from_inst;
    char                    resid[DMS_RESID_SIZE];
} dms_req_buf_info_t;

typedef struct st_dms_ack_buf_info {
    dms_message_head_t      head;
    stat_buf_info_t          buf_info;
} dms_ack_buf_info_t;

int dms_send_request_buf_info(dms_context_t *dms_ctx, dv_drc_buf_info *drc_info);
void dms_proc_ask_node_buf_info(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);

void dms_check_message_cmd(unsigned int cmd, bool8 is_req);

void dms_init_ack_head(const dms_message_head_t *req_head, dms_message_head_t *ack_head, unsigned int cmd,
    unsigned short size, unsigned int src_sid);

void dms_init_ack_head2(dms_message_head_t *ack_head, unsigned int cmd, unsigned int flags,
    unsigned char src_inst, unsigned char dst_inst, unsigned short src_sid, unsigned short dst_sid,
    unsigned int req_proto_ver);

void dms_inc_msg_stat(uint32 sid, dms_stat_cmd_e cmd, uint32 type, status_t ret);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_MSG_H__ */
