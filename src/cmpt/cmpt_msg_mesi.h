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
 * cmpt_msg_mesi.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_mesi.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_MESI_H__
#define __CMPT_MSG_MESI_H__

#include "cmpt_msg_common.h"
#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_msg_owner_clean_req {
    dms_message_head_t head;
    dms_lock_mode_t req_mode;
    char pageid[DMS_PAGEID_SIZE];
} msg_owner_clean_req_t;

typedef struct st_msg_ack_owner_id {
    dms_message_head_t head;
    uint32 owner_id;
} msg_ack_owner_id_t;

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
    uint8 node_count;
} dms_ask_res_ack_ld_t;

typedef struct st_dms_ask_res_ack_load_wrapper {
    dms_ask_res_ack_ld_t ack;
    uint64 node_lfn[DMS_MAX_INSTANCES];
} dms_ask_res_ack_ld_wrapper_t;

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

typedef struct st_dms_invld_ack {
    dms_common_ack_t common_ack;
    uint64 scn;
    uint64 lfn;
} dms_invld_ack_t;

typedef struct st_dms_chk_ownership_req {
    dms_message_head_t head;
    char resid[DMS_RESID_SIZE];
    uint16 len;
    uint8  inst_id;
    uint8  curr_mode;
} dms_chk_ownership_req_t;

typedef enum en_req_flags {
    REQ_FLAG_DEFAULT = 0x00,
    REQ_FLAG_REFORM_SESSION = 0x01,
    REQ_FLAG_CEIL = 0x80,
} req_flags_t;

typedef struct st_dms_pre_cre_drc {
    dms_message_head_t head;
    char resid[DMS_RESID_SIZE];
} dms_pre_cre_drc_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_MESI_H__