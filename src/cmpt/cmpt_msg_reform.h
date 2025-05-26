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
 * cmpt_msg_reform.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_reform.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_REFORM_H__
#define __CMPT_MSG_REFORM_H__

#include "cmpt_msg_common.h"
#include "cmpt_msg_version.h"
#include "cmpt_reform_step.h"
#include "dms_cm.h"
#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_dms_reform_ack_common {
    dms_message_head_t  head;
    int                 result;         // proc result
    uint8               last_fail;      // for ack MSG_REQ_REFORM_PREPARE
    union {
        uint8               dms_status;     // for ack MSG_REQ_DATABASE_STATUS
        uint8               has_ddl_2phase;
    };
    uint8               lock_mode;
    bool8               is_edp;
    uint64              lsn;
    uint64              start_time;
    uint64              bitmap_has_xa;
    uint8               db_is_readwrite;
} dms_reform_ack_common_t;

typedef struct st_dms_reform_req_sync_step {
    dms_message_head_t  head;
    uint64              scn;
    uint64              start_time;
    uint8               last_step;
    uint8               curr_step;
    uint8               next_step;
} dms_reform_req_sync_step_t;

typedef struct st_dms_reform_req_partner_status {
    dms_message_head_t  head;
    uint64              lsn;
    driver_ping_info_t driver_ping_info;
} dms_reform_req_partner_status_t;

typedef struct st_dms_reform_req_prepare {
    dms_message_head_t  head;
    bool8               last_fail;
} dms_reform_req_prepare_t;

typedef struct st_dms_reform_req_gcv_sync {
    dms_message_head_t  head;
    bool8               pushing;
} dms_reform_req_gcv_sync_t;

typedef struct st_dms_reform_ack_gcv_sync {
    dms_message_head_t  head;
    bool8               updated;
} dms_reform_ack_gcv_sync_t;

typedef struct st_dms_reform_req_migrate {
    dms_message_head_t head;
    uint32 part_id;
    uint32 res_num;
    bool8  is_part_end;
    uint8  res_type;
} dms_reform_req_migrate_t;

typedef struct st_dms_reform_req_rebuild {
    dms_message_head_t head;
    uint32 offset;
} dms_reform_req_rebuild_t;

typedef enum dms_reform_req_page_action {
    DMS_REQ_FLUSH_COPY,
} page_action_t;

typedef struct st_dms_reform_req_switchover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_switchover_t;

typedef struct st_repair_item {
    char        page_id[DMS_PAGEID_SIZE];
    uint32      action;
} repair_item_t;

typedef struct st_migrate_task {
    uint8               export_inst;
    uint8               import_inst;
    uint8               part_id;
    uint8               unused;
} migrate_task_t;

typedef struct st_migrate_info {
    migrate_task_t      migrate_task[DRC_MAX_PART_NUM];
    uint8               migrate_task_num;
    uint8               unused[3];
} migrate_info_t;

typedef struct st_remaster_info {
    drc_part_t          part_map[DRC_MAX_PART_NUM];
    drc_inst_part_t     inst_part_tbl[DMS_MAX_INSTANCES];
    uint8               deposit_map[DMS_MAX_INSTANCES];
} remaster_info_t;

typedef struct st_dms_reform_ack_map {
    dms_message_head_t head;
    remaster_info_t remaster_info;
} dms_reform_ack_map_t;

typedef struct st_dms_reform_req_opengauss_ondemand_redo {
    dms_message_head_t head;
    uint16 len;
} dms_reform_req_opengauss_ondemand_redo_t;

typedef struct st_dms_reform_req_group {
    dms_message_head_t head;
    uint32 offset;
} dms_reform_req_group_t;

typedef struct st_dms_reform_req_az_switchover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_az_switchover_t;

typedef struct st_dms_reform_req_az_failover {
    dms_message_head_t head;
    uint64 start_time;
} dms_reform_req_az_failover_t;

typedef struct st_version_info {
    uint64              start_time;
    uint8               inst_id;
    uint8               unused[3];
} version_info_t;

typedef enum en_inst_list_type {
    INST_LIST_OLD_BASE = 0,
    INST_LIST_OLD_OUT = INST_LIST_OLD_BASE + DMS_ONLINE_STATUS_OUT,
    INST_LIST_OLD_JOIN = INST_LIST_OLD_BASE + DMS_ONLINE_STATUS_JOIN,
    INST_LIST_OLD_REFORM = INST_LIST_OLD_BASE + DMS_ONLINE_STATUS_REFORM,
    INST_LIST_OLD_IN = INST_LIST_OLD_BASE + DMS_ONLINE_STATUS_IN,
    INST_LIST_OLD_REMOVE,
    INST_LIST_NEW_BASE,
    INST_LIST_NEW_OUT = INST_LIST_NEW_BASE + DMS_ONLINE_STATUS_OUT,
    INST_LIST_NEW_JOIN = INST_LIST_NEW_BASE + DMS_ONLINE_STATUS_JOIN,
    INST_LIST_NEW_REFORM = INST_LIST_NEW_BASE + DMS_ONLINE_STATUS_REFORM,
    INST_LIST_NEW_IN = INST_LIST_NEW_BASE + DMS_ONLINE_STATUS_IN,
    INST_LIST_TYPE_COUNT
} inst_list_type_t;

#pragma pack(4)
/* Tips: Byte alignment is required, padding is not allowed */
typedef struct st_share_info {
    /* ============= start version 1 =================*/
    reform_step_t       reform_step[DMS_REFORM_STEP_TOTAL_COUNT];
    reform_phase_t      reform_phase[DMS_REFORM_PHASE_TOTAL_COUNT];
    instance_list_t     list_stable;
    instance_list_t     list_online;
    instance_list_t     list_offline;
    instance_list_t     list_reconnect;
    instance_list_t     list_disconnect;
    instance_list_t     list_clean;
    instance_list_t     list_rebuild;
    instance_list_t     list_recovery;
    instance_list_t     list_withdraw;
    instance_list_t     list_rollback;
    uint64              bitmap_stable;
    uint64              bitmap_online;
    uint64              bitmap_reconnect;
    uint64              bitmap_disconnect;
    uint64              bitmap_clean;
    uint64              bitmap_recovery;
    uint64              bitmap_in;
    uint64              bitmap_remove;
    remaster_info_t     remaster_info;
    migrate_info_t      migrate_info;
    version_info_t      reformer_version;       // record reformer version, find reformer restart in time
    version_info_t      switch_version;         // in reform of switchover, there is another reformer
    dms_reform_type_t   reform_type;
    uint8               reform_step_count;
    uint8               reform_phase_count;
    bool8               full_clean;
    uint8               reformer_id;            // current reformer id
    uint8               promote_id;             // instance promote to primary
    uint8               demote_id;              // instance demote to standy;
    uint8               last_reformer;          // last reformer
    bool8               catalog_centralized;
    uint64              version_num;
    dw_recovery_info_t  dw_recovery_info;
    uint64              start_times[DMS_MAX_INSTANCES];
    date_t              judge_time;
    uint32              proto_version;
    /* ============= end version 1 =================*/

    /* ============= start version 2 =================*/
    uint64              inst_bitmap[INST_LIST_TYPE_COUNT];
    /* ============= end version 2 =================*/

    /* ============= start version 5 =================*/
    remaster_info_t     old_master_info;
    uint8               drm_trigger;
    /* ============= end version 5 =================*/
} share_info_t;

#pragma pack()

extern dms_proto_version_attr g_req_share_info_version_ctrl[DMS_PROTO_VER_NUMS];

typedef struct st_dms_reform_req_sync_share_info {
    dms_message_head_t  head;
    share_info_t        share_info;
} dms_reform_req_sync_share_info_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_REFORM_H__