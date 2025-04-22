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
 * cmpt_msg_tran.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_tran.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_TRAN_H__
#define __CMPT_MSG_TRAN_H__

#include "cmpt_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_msg_txn_wait {
    dms_message_head_t head;
    char wxid[DMS_XID_SIZE];
}msg_txn_wait_t;

typedef struct st_msg_txn_info_request {
    dms_message_head_t head;
    uint64 xid;
    uint64 scn;
    bool32 is_scan;
} msg_txn_info_request_t;

typedef struct st_msg_txn_wait_request {
    dms_message_head_t head;
    uint64 xid;
} msg_txn_wait_request_t;

typedef struct st_msg_txn_wait_ack {
    dms_message_head_t head;
    int32 status;
    uint64 scn;
} msg_txn_wait_ack_t;

typedef struct st_msg_txn_awake_request {
    dms_message_head_t head;
    uint64 xid;
    uint64 scn;
} msg_txn_awake_request_t;

typedef struct st_msg_txn_snapshot {
    dms_message_head_t head;
    uint32 xmap;
} msg_txn_snapshot_t;

typedef enum en_dms_xa_oper_type {
    DMS_XA_OPER_CREATE = 0,
    DMS_XA_OPER_DELETE = 1
} dms_xa_oper_type_t;

typedef struct st_dms_xa_res_req {
    dms_message_head_t head;
    uint8 undo_set_id;
    drc_global_xid_t xa_xid;
    dms_xa_oper_type_t oper_type;
} dms_xa_res_req_t;

typedef struct st_dms_xa_res_ack {
    dms_message_head_t head;
    uint32 return_code;
} dms_xa_res_ack_t;

typedef struct st_dms_ask_xa_owner_req {
    dms_message_head_t head;
    dms_session_e sess_type;
    drc_global_xid_t xa_xid;
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

typedef struct st_msg_opengauss_xid_csn_request {
    dms_message_head_t head;
    dms_opengauss_xid_csn_t xid_csn_ctx;
} msg_opengauss_xid_csn_request_t;

typedef struct st_msg_opengauss_multixact_uxid_request {
    dms_message_head_t head;
    uint64 xid;
    uint16 t_infomask;
    uint16 t_infomask2;
} msg_opengauss_update_xid_request_t;

typedef struct st_msg_opengauss_txn_status_request {
    dms_message_head_t head;
    unsigned char request_type;
    uint64 xid;
} msg_opengauss_txn_status_request_t;

typedef struct st_msg_opengauss_lock_buffer_ctx {
    dms_message_head_t head;
    int32 buffer;
    unsigned char lock_mode;
    unsigned char recv_lock_mode;
} msg_opengauss_lock_buffer_ctx_t;

typedef struct st_msg_opengauss_page_status_request {
    dms_message_head_t head;
    dms_opengauss_relfilenode_t rnode;
    uint32 page;
    int page_num;
    int bit_count;
    unsigned long int page_map[8];
} msg_opengauss_page_status_request_t;

typedef struct st_msg_opengauss_txn_snapshot {
    dms_message_head_t head;
} msg_opengauss_txn_snapshot_t;

typedef struct st_msg_opengauss_txn_swinfo {
    dms_message_head_t head;
    uint32 proc_slot;
} msg_opengauss_txn_swinfo_t;

typedef struct st_msg_send_opengauss_oldest_xmin {
    dms_message_head_t head;
    uint64 oldest_xmin;
} msg_send_opengauss_oldest_xmin_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_TRAN_H__

