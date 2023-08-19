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
 * dcs_msg.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_msg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCS_MSG_H__
#define __DCS_MSG_H__

#include "cm_atomic.h"
#include "dms.h"
#include "mes_type.h"
#include "dms_msg.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_msg_flags {
    MSG_FLAG_DIRTY_PAGE = 0x01,  // sent local dirty page, owner has edp
    MSG_FLAG_REMOTE_DIRTY_PAGE = 0x02,  // sent remote dirty page, owner has edp
    MSG_FLAG_SHARED_PAGE = 0x04,  // sent page is shared copy
    MSG_FLAG_NO_PAGE = 0x08, // requester has shared copy, no page sent
    MSG_FLAG_CEIL = 0x80
}msg_flags_t;

#define DCS_ACK_PAGE_IS_DIRTY(msg) ((((msg)->head->flags & MSG_FLAG_DIRTY_PAGE) != 0) ? CM_TRUE : CM_FALSE)
#define DCS_ACK_PAGE_IS_REMOTE_DIRTY(msg) (((msg)->head->flags & MSG_FLAG_REMOTE_DIRTY_PAGE) ? CM_TRUE : CM_FALSE)

typedef enum en_cr_type {
    CR_TYPE_HEAP,
    CR_TYPE_BTREE,
} cr_type_t;

typedef struct st_msg_owner_clean_req {
    dms_message_head_t head;
    dms_lock_mode_t req_mode;
    char pageid[DMS_PAGEID_SIZE];
} msg_owner_clean_req_t;

typedef struct st_msg_pcr_request {
    dms_message_head_t head;
    uint8 cr_type;
    bool8 force_cvt; // force convert
    uint32 ssn;
    uint64 query_scn;
    char pageid[DMS_PAGEID_SIZE];
    char xid[DMS_XID_SIZE];
    dms_session_e sess_type;
} msg_pcr_request_t;

typedef struct st_msg_pcr_ack {
    dms_message_head_t head;
    bool8 force_cvt;
} msg_pcr_ack_t;

typedef struct st_msg_index_pcr_request {
    msg_pcr_request_t pcr_request;
    char entry[DMS_PAGEID_SIZE];
    char profile[DMS_INDEX_PROFILE_SIZE];
} msg_index_pcr_request_t;

typedef struct st_msg_txn_wait {
    dms_message_head_t head;
    char wxid[DMS_XID_SIZE];
}msg_txn_wait_t;

typedef struct st_msg_cr_check {
    dms_message_head_t head;
    uint64 query_scn;
    uint32 ssn;
    char xid[DMS_XID_SIZE];
    char rowid[DMS_ROWID_SIZE];
} msg_cr_check_t;

typedef struct st_msg_cr_check_ack {
    dms_message_head_t head;
    bool8 is_found;
} msg_cr_check_ack_t;

typedef struct st_msg_ack_owner_id {
    dms_message_head_t head;
    uint32 owner_id;
} msg_ack_owner_id_t;

typedef struct st_msg_txn_info_request {
    dms_message_head_t head;
    uint64 xid;
    bool32 is_scan;
} msg_txn_info_request_t;

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

typedef struct st_msg_opengauss_txn_snapshot {
    dms_message_head_t head;
} msg_opengauss_txn_snapshot_t;

typedef struct st_msg_opengauss_txn_swinfo {
    dms_message_head_t head;
    uint32 proc_slot;
} msg_opengauss_txn_swinfo_t;

typedef struct st_msg_txn_snapshot {
    dms_message_head_t head;
    uint32 xmap;
} msg_txn_snapshot_t;

typedef struct st_msg_rls_owner_req {
    dms_message_head_t head;
    uint64 owner_lsn;
    uint64 owner_scn;
    dms_session_e sess_type;
    char pageid[DMS_PAGEID_SIZE];
} msg_rls_owner_req_t;

typedef struct st_msg_rls_owner_ack {
    dms_message_head_t head;
    bool8 released;
} msg_rls_owner_ack_t;

typedef struct st_dcs_boc_req {
    dms_message_head_t head;
    uint64 commit_scn;
    uint64 min_scn;
    uint32 inst_id;
} dcs_boc_req_t;

typedef struct st_msg_send_opengauss_oldest_xmin {
    dms_message_head_t head;
    uint64 oldest_xmin;
} msg_send_opengauss_oldest_xmin_t;

#ifdef __cplusplus
}
#endif

#endif /* __DCS_MSG_H__ */

