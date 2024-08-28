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
 * dms_reform.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_H__
#define __DMS_REFORM_H__

#include "dms.h"
#include "cm_thread.h"
#include "cm_utils.h"
#include "dms_cm.h"
#include "drc.h"
#include "dms_reform_cm_res.h"
#include "scrlock_adapter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_REFORM_PROC_THRD_NAME       "reform_proc"
#define DMS_REFORM_HEALTH_THRD_NAME     "reform_health"
#define DMS_REFORM_JUDG_THRD_NAME       "reform_judge"
#define DMS_REFORM_PREEMPT_THRD_NAME    "reform_preempt"
#define DMS_REFORM_FI_THRD_NAME         "reform_fi"
#define DMS_REFORM_PARA_THRD_NAME       "reform_para"

#define DMS_REFORM_LONG_SLEEP           cm_sleep(500)
#define DMS_REFORM_SHORT_SLEEP          cm_sleep(10)
#define DMS_REFORM_LONG_TIMEOUT         5000
#define DMS_REFORM_SHORT_TIMEOUT        500
#define DMS_REFORM_CONFIRM_TIMEOUT      5000000 // 5s
#define DMS_REFORM_LOCK_INST_TIMEOUT    (g_dms.max_wait_time * MICROSECS_PER_MILLISEC)
#define DMS_REFORM_CONTEXT              (&g_dms.reform_ctx)
#define DMS_REFORMER_CTRL               (&g_dms.reform_ctx.reformer_ctrl)
#define DMS_REFORM_INFO                 (&g_dms.reform_ctx.reform_info)
#define DMS_SHARE_INFO                  (&g_dms.reform_ctx.share_info)
#define DMS_REMASTER_INFO               (&g_dms.reform_ctx.share_info.remaster_info)
#define DMS_MIGRATE_INFO                (&g_dms.reform_ctx.share_info.migrate_info)
#define DMS_REBUILD_INFO                (&g_dms.reform_ctx.reform_info.rebuild_info)
#define DMS_SWITCHOVER_INFO             (&g_dms.reform_ctx.switchover_info)
#define DMS_HEALTH_INFO                 (&g_dms.reform_ctx.health_info)
#define DMS_PARALLEL_INFO               (&g_dms.reform_ctx.parallel_info)
#define DRC_PART_REMASTER_ID(part_id)   (g_dms.reform_ctx.share_info.remaster_info.part_map[(part_id)].inst_id)
#define DMS_AZ_SWITCHOVER_INFO          (&g_dms.reform_ctx.az_switchover_info)

#define LOG_DEBUG_FUNC_SUCCESS          LOG_DEBUG_INF("[DMS REFORM]%s success", __FUNCTION__)
#define LOG_DEBUG_FUNC_FAIL             LOG_DEBUG_ERR("[DMS REFORM]%s fail, error: %d", __FUNCTION__, ret)
#define LOG_RUN_FUNC_SUCCESS            LOG_RUN_INF("[DMS REFORM]%s success", __FUNCTION__)
#define LOG_RUN_FUNC_SKIP               LOG_RUN_INF("[DMS REFORM]%s skip", __FUNCTION__)
#define LOG_RUN_FUNC_FAIL               LOG_RUN_ERR("[DMS REFORM]%s fail, error: %d", __FUNCTION__, ret)
#define LOG_RUN_FUNC_ENTER              LOG_RUN_INF("[DMS REFORM]%s enter", __FUNCTION__)
#define DMS_INFO_DESC_LEN               2048
#define DMS_TEMP_DESC_LEN               128

#define DMS_IS_REFORMER                 (g_dms.reform_ctx.reform_info.dms_role == DMS_ROLE_REFORMER)
#define DMS_IS_PARTNER                  (g_dms.reform_ctx.reform_info.dms_role == DMS_ROLE_PARTNER)
#define DMS_IS_SHARE_REFORMER           (g_dms.reform_ctx.share_info.reformer_id == g_dms.inst_id)
#define DMS_IS_SHARE_PARTNER            (g_dms.reform_ctx.share_info.reformer_id != g_dms.inst_id)

#define DMS_REFORMER_ID_FOR_BUILD       0
#define DMS_FIRST_REFORM_FINISH         (g_dms.reform_ctx.reform_info.first_reform_finish)

#define DMS_MAINTAIN_ENV                "DMS_MAINTAIN"

#define MAX_ALIVE_TIME_FOR_ABNORMAL_STATUS               g_dms.max_alive_time_for_abnormal_status

#define DMS_RELEASE_DB_HANDLE(handle)                                               \
    do {                                                                            \
        if ((handle) != NULL && g_dms.callback.release_db_handle != NULL) {         \
            g_dms.callback.release_db_handle((handle));                             \
            (handle) = NULL;                                                        \
        }                                                                           \
    } while (CM_FALSE)

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

// The steps will be repeated, DMS_REFORM_STEP_TOTAL_COUNT > DMS_REFORM_STEP_COUNT
#define DMS_REFORM_STEP_TOTAL_COUNT     128
#define DMS_REFORM_PHASE_TOTAL_COUNT    8

// Notice: every step should not be dependent on its Value, Value is only used for distinguish different step
typedef enum en_reform_step {
    DMS_REFORM_STEP_DONE,
    DMS_REFORM_STEP_PREPARE,                        // just sync wait reformer. do nothing
    DMS_REFORM_STEP_START,                          // no need to set last_fail before this step
    DMS_REFORM_STEP_DISCONNECT,
    DMS_REFORM_STEP_RECONNECT,
    DMS_REFORM_STEP_DRC_CLEAN,
    DMS_REFORM_STEP_FULL_CLEAN,
    DMS_REFORM_STEP_MIGRATE,
    DMS_REFORM_STEP_REBUILD,
    DMS_REFORM_STEP_REMASTER,
    DMS_REFORM_STEP_REPAIR,
    DMS_REFORM_STEP_SWITCH_LOCK,
    DMS_REFORM_STEP_SWITCHOVER_DEMOTE,
    DMS_REFORM_STEP_RECOVERY,
    DMS_REFORM_STEP_RECOVERY_OPENGAUSS,
    DMS_REFORM_STEP_DRC_RCY_CLEAN,
    DMS_REFORM_STEP_CTL_RCY_CLEAN,
    DMS_REFORM_STEP_TXN_DEPOSIT,
    DMS_REFORM_STEP_ROLLBACK_PREPARE,
    DMS_REFORM_STEP_ROLLBACK_START,
    DMS_REFORM_STEP_SUCCESS,
    DMS_REFORM_STEP_SELF_FAIL,                      // cause by self
    DMS_REFORM_STEP_REFORM_FAIL,                    // cause by notification from reformer
    DMS_REFORM_STEP_SYNC_WAIT,                      // tips: can not use before reconnect
    DMS_REFORM_STEP_PAGE_ACCESS,                    // set page accessible
    DMS_REFORM_STEP_DW_RECOVERY,                    // recovery the dw area
    DMS_REFORM_STEP_DF_RECOVERY,
    DMS_REFORM_STEP_SPACE_RELOAD,
    DMS_REFORM_STEP_DRC_ACCESS,                     // set drc accessible
    DMS_REFORM_STEP_DRC_INACCESS,                   // set drc inaccessible
    DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS,
    DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS,
    DMS_REFORM_STEP_STARTUP_OPENGAUSS,              // for opengauss
    DMS_REFORM_STEP_DONE_CHECK,
    DMS_REFORM_STEP_SET_PHASE,                      // for Gauss100
    DMS_REFORM_STEP_WAIT_DB,                        // for Gauss100
    DMS_REFORM_STEP_FILE_UNBLOCKED,                   // for Gauss100
    DMS_REFORM_STEP_FILE_BLOCKED,                   // for Gauss100
    DMS_REFORM_STEP_UPDATE_SCN,
    DMS_REFORM_STEP_WAIT_CKPT,                      // for Gauss100
    DMS_REFORM_STEP_DRC_VALIDATE,
    DMS_REFORM_STEP_LOCK_INSTANCE,                  // get X mode instance lock for reform
    DMS_REFORM_STEP_PUSH_GCV_AND_UNLOCK,            // push GCV in X instance lock, then unlock X
    DMS_REFORM_STEP_SET_REMOVE_POINT,               // for Gauss100, set rcy point who is removed node after ckpt
    DMS_REFORM_STEP_RESET_USER,
    DMS_REFORM_STEP_RECOVERY_ANALYSE,               // for Gauss100, set rcy flag for pages which in redo log
    DMS_REFORM_STEP_XA_DRC_ACCESS,                  // for Gauss100, set xa drc access
    DMS_REFORM_STEP_DDL_2PHASE_DRC_ACCESS,
    DMS_REFORM_STEP_DDL_2PHASE_RCY,
    DMS_REFORM_STEP_DRC_LOCK_ALL_ACCESS,
    DMS_REFORM_STEP_SET_CURRENT_POINT,
    DMS_REFORM_STEP_STANDBY_UPDATE_REMOVE_NODE_CTRL,
    DMS_REFORM_STEP_STANDBY_STOP_THREAD,
    DMS_REFORM_STEP_STANDBY_RELOAD_NODE_CTRL,
    DMS_REFORM_STEP_STANDBY_SET_ONLINE_LIST,
    DMS_REFORM_STEP_STOP_SERVER,
    DMS_REFORM_STEP_RESUME_SERVER_FOR_REFORMER,
    DMS_REFORM_STEP_RESUME_SERVER_FOR_PARTNER,
    DMS_REFORM_STEP_START_LRPL,                     // for Gauss100, start log replay
    DMS_REFORM_STEP_STOP_LRPL,                      // for Gauss100, stop log replay

    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE1,        // for Gauss100, AZ SWITCHOVER primary to standby
    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_UPDATE_NODE_CTRL,
    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_CHANGE_ROLE,
    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_APPROVE,       // for Gauss100, AZ SWITCHOVER primary to standby
    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE2,        // for Gauss100, AZ SWITCHOVER primary to standby
    DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PREPARE,             // for Gauss100, AZ SWITCHOVER standby to primary
    DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE1,              // for Gauss100, AZ SWITCHOVER standby to primary
    DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE2,              // for Gauss100, AZ SWITCHOVER standby to primary
    DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE1,     // for Gauss100, AZ FAILOVER standby to primary
    DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_RESETLOG,   // for Gauss100, AZ FAILOVER standby to primary
    DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE2,     // for Gauss100, AZ FAILOVER standby to primary
    DMS_REFORM_STEP_RELOAD_TXN,
    DMS_REFORM_STEP_COUNT
} reform_step_t;

#define DMS_REFORM_STEP_DESC_STR_LEN 30

typedef enum en_dms_thread_status {
    DMS_THREAD_STATUS_IDLE = 0,
    DMS_THREAD_STATUS_RUNNING,
    DMS_THREAD_STATUS_PAUSING,
    DMS_THREAD_STATUS_PAUSED,
} dms_thread_status_t;

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

typedef struct st_version_info {
    uint64              start_time;
    uint8               inst_id;
    uint8               unused[3];
} version_info_t;

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
} share_info_t;

#pragma pack()

typedef struct st_rebuild_info {
    void                *rebuild_data[DMS_MAX_INSTANCES];
} rebuild_info_t;

typedef struct st_reformer_ctrl {
    bool8               instance_fail[DMS_MAX_INSTANCES];
    uint8               instance_step[DMS_MAX_INSTANCES];
} reformer_ctrl_t;

typedef struct st_log_point {
    uint32              asn;
    uint32              block_id;
    uint64              rst_id : 18;
    uint64              lfn : 46;
} log_point_t;

/* REBUILD

            +--[NULL]--[EDP]---------------------->[must be EDP]   --> [do nothing]
            |
            |                     +--[dirty or flushed_lsn==page_lsn]--->[must be OWNER] --> [REFORM_ASSIST_LIST_OWNER]
            |       +--[not EDP]--|
 [REBUILD]--+--[S]--|             +--[else]-->[can be OWNER]  --> [REFORM_ASSIST_LIST_NORMAL_COPY]
            |       |
            |       +--[EDP]---------------------->[can be OWNER]  --> [REFORM_ASSIST_LIST_EDP_COPY]
            |
            |       +--[dirty or flushed_lsn==page_lsn]----------------->[must be OWNER] --> [REFORM_ASSIST_LIST_OWNER]
            +--[X]--|
                    +--[else]---------------->[can be OWNER]  --> [REFORM_ASSIST_LIST_NORMAL_COPY]

tips:
 1. According to the priority of the list, DRC are moved between different lists during REBUILD.
 2. If page is dirty or flushed_lsn == page_lsn, we treat the page as DIRTY.
 3. To reduce conflicts in list operations between parallel threads, the list is divided into 128 parts.
 */

/* RECOVERY_ANALYSE

 [REFORM_ASSIST_LIST_OWNER]       -->[in_recovery=false,validate lsn]
 [REFORM_ASSIST_LIST_NORMAL_COPY] -->[in_recovery=false,validate lsn] --> [REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO]
 [REFORM_ASSIST_LIST_EDP_COPY]    -->[in_recovery=false,validate lsn]
 [REFORM_ASSIST_LIST_EDP]         -->[in_recovery=true]
 [DRC not exists]                 -->[in_recovery=true] --> [LIST_NONE]

 tips:
 1. If DRC is in REFORM_ASSIST_LIST_NORMAL_COPY, promote to REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO.
 2. If DRC is created for recovery analyze, add to REFORM_ASSIST_LIST_NEW_DRC.
 3. If DRC skip recover, lsn is validated in RECOVERY_ANALYSE.
 4. If DRC does not skip recover, need not to validate lsn again.
*/

/* REPAIR_NEW

 [REFORM_ASSIST_LIST_NONE]                  --> [do RECOVER] drc_get_page_no_owner should deal with last_edp
 [REFORM_ASSIST_LIST_NORMAL_COPY]           --> [do nothing]
 [REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO] --> [FLUSH_COPY]
 [REFORM_ASSIST_LIST_EDP_COPY]              --> [do nothing] ss_ckpt_remote_edp should deal edp as owner
 [REFORM_ASSIST_LIST_OWNER]                 --> [do nothing]

 tips:
 1. If DRC is in REFORM_ASSIST_LIST_NONE, its page will be recover later.
 2. If DRC is in REFORM_ASSIST_LIST_NORMAL_COPY, it is not mentioned in redo, and need not to do recover or flush.
 3. If DRC is in REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO, it is mentioned in redo, need to do force flush to disk.
 4. If DRC is in REFORM_ASSIST_LIST_EDP_COPY, need not to do recover, but should flush to disk.
 5. If DRC is in REFORM_ASSIST_LIST_OWNER, the page will be flushed or has been flushed.
*/

typedef enum en_reform_assist_list_type {
    REFORM_ASSIST_LIST_NONE = 0,
    REFORM_ASSIST_LIST_NORMAL_COPY = 1,
    REFORM_ASSIST_LIST_NORMAL_COPY_WITH_REDO = 2,
    REFORM_ASSIST_LIST_EDP_COPY = 3,
    REFORM_ASSIST_LIST_OWNER = 4,

    REFORM_ASSIST_LIST_COUNT
} reform_assist_list_type_e;

typedef struct st_reform_info {
    latch_t             file_latch;
    uint64              max_scn;
    spinlock_t          version_lock;
    spinlock_t          mes_lock;
    spinlock_t          xa_bitmap_lock;
    uint64              bitmap_mes;
    uint64              bitmap_connect;
    uint64              bitmap_has_xa;
    rebuild_info_t      rebuild_info;
    version_info_t      reformer_version;
    uint64              start_time;
    uint64              proc_time;              // check proc if active or fall into an endless loop
    int32               err_code;
    dms_thread_status_t thread_status;
    char                aligned1[CM_CACHE_LINE_SIZE];
    latch_t             instance_lock;          // latch to avoid concurrent modifications on db buf and dms drc
    char                aligned2[CM_CACHE_LINE_SIZE];
    uint8               dms_role;
    uint8               reformer_id;            // who hold dms_reformer_lock, it is realtime
    bool8               last_fail;              // record last round reform result
    bool8               first_reform_finish;    // db_open after first reform success
    bool8               reform_fail;            // used for stop current reform
    uint8               next_step;              // get next_step when current_step=SYNC_WAIT
    uint8               current_step;
    uint8               last_step;              // record last_step when current_step=SYNC_WAIT
    uint8               reform_step_index;
    uint8               sync_step;              // for DMS_REFORM_STEP_SYNC_WAIT
    bool8               sync_send_success;
    bool8               build_complete;         // build_complete when dms_reform_init, it is not realtime
    bool8               maintain;               // env DMS_MAINTAIN, if true, DMS is not dependent on CM
    uint8               reform_done;
    bool8               true_start;
    uint8               reform_phase_index;
    uint8               reform_phase;           // set by reform_proc
    bool8               reform_pause;
    bool8               ddl_unable;
    bool8               file_unable;
    bool8               parallel_enable;        // dms reform proc parallel enable
    bool8               use_default_map;        // if use default part_map in this judgement
    bool8               rst_recover;            // recover after restore for Gauss100
    uint8               unused[1];
    log_point_t         curr_points[DMS_MAX_INSTANCES];
    uint64              bitmap_in;
    bool8               is_locking;
    bool8               has_ddl_2phase;
    drc_part_list_t     normal_copy_lists[DRC_MAX_PART_NUM];
} reform_info_t;

typedef struct st_switchover_info {
    // var below used for origin primary
    uint64              start_time;             // start lsn
    spinlock_t          lock;
    bool8               switch_req;             // concurrency control & used in dms_reform_judgement
    uint8               inst_id;                // instance id of initiator
    uint16              sess_id;                // session id of initiator, use for message reentry
    // var below used for origin standby
    version_info_t      reformer_version;       // for origin standby record, if version changed, stop request session
    bool8               switch_start;           // if current node request switchover
} switchover_info_t;

typedef enum st_az_dms_switch_type {
    AZ_IDLE = 0,
    AZ_SWITCHOVER = 1,
    AZ_FAILOVER = 2,
} az_dms_switch_type_t;

typedef struct st_az_switchover_info {
    uint64                start_time;
    spinlock_t            lock;
    bool8                 switch_req;
    uint8                  inst_id;
    uint16                sess_id;
    version_info_t        reformer_version;
    bool8                 switch_start;
    az_dms_switch_type_t  switch_type;
} az_switchover_info_t;

typedef struct st_reform_scrlock_context {
    unsigned char log_path[DMS_OCK_LOG_PATH_LEN];
    uint8 log_level;
    uint8 worker_num;
    bool8 worker_bind_core;
    uint8 worker_bind_core_start;
    uint8 worker_bind_core_end;
    uint8 scrlock_server_id;
    uint32 scrlock_server_port;
    bool8 sleep_mode;
    uint8 server_bind_core_start;
    uint8 server_bind_core_end;
    bool8 enable_ssl;
    bool8 is_server;
    uint8 recovery_node_num;
    dms_instance_net_addr_t inst_net_addr[DMS_MAX_INSTANCES];
} reform_scrlock_context_t;

typedef struct st_health_info {
    uint8               online_status[DMS_MAX_INSTANCES];
    uint64              online_times[DMS_MAX_INSTANCES];
    uint8               online_rw_status[DMS_MAX_INSTANCES];
    dms_thread_status_t thread_status;
    date_t              dyn_log_time;
} health_info_t;

#define DMS_PARALLEL_MAX_THREAD         64
#define DMS_PARALLEL_MAX_RESOURCE       (CM_MES_MAX_CHANNEL_NUM * DMS_MAX_INSTANCES / 2)

typedef union st_resource_id {
    uint32          resource_id;
    struct {
        uint16      part_id;                    // for drc part
    };
    struct {
        uint8       node_id;                    // for reconnect
        uint8       channel_index;
    };
    migrate_task_t  migrate_task;               // for migrate
    struct {
        uint8       thread_index;               // for rebuild
        uint8       thread_num;
    };
} resource_id_t;

typedef struct st_full_clean_assist {
    bilist_t            temp_convert_q;
    bilist_t            temp_page;
    bilist_t            temp_lock;
    bilist_t            temp_alock;
    bilist_t            temp_xa;
} full_clean_assist_t;

typedef struct st_parallel_thread {
    cm_sem_t            sem;
    thread_t            thread;
    dms_thread_status_t thread_status;
    void                *handle;
    uint32              sess_id;
    uint32              index;
    int                 res_num;                            // assigned resource num
    resource_id_t       res_id[DMS_PARALLEL_MAX_RESOURCE];  // assigned resource id
    void                *data[DMS_MAX_INSTANCES];           // if need send message in parallel proc
    full_clean_assist_t full_clean_assist;
} parallel_thread_t;

typedef void(*dms_assign_proc)(void);
typedef int(*dms_parallel_proc)(resource_id_t *res_id, parallel_thread_t *parallel);

typedef struct st_parallel_info {
    spinlock_t          parallel_lock;
    cm_sem_t            parallel_sem;
    parallel_thread_t   parallel[DMS_PARALLEL_MAX_THREAD];
    dms_parallel_proc   parallel_proc;          // parallel callback function
    uint32              parallel_num;           // parallel thread total num
    atomic32_t          parallel_fail;          // parallel thread proc fail num
    uint32              parallel_res_num;       // parallel total res num
} parallel_info_t;

typedef struct st_reform_context {
    thread_t            thread_judgement;       // dms_reform_judgement_thread
    thread_t            thread_reformer;        // dms_reformer_thread
    thread_t            thread_reform;          // reform
    thread_t            thread_health;          // health check
    /*
        1. handle_judge&sess_judge used in thread<dms_reform_judgement_thread>
        2. handle_proc&sess_proc used in thread<dms_reform_proc_thread> while step before RECOVERY, include RECOVERY
           it will set drc->in_recovery True when access page
    */
    void                *handle_judge;          // used in reform judgment
    void                *handle_proc;           // used in reform, and set recovery flag in buf_res
    void                *handle_normal;
    void                *handle_health;
    cm_sem_t            sem_proc;
    cm_sem_t            sem_health;
    uint32              sess_judge;             // used to send message in reform judgment
    uint32              sess_proc;              // used to send message in reform proc
    uint32              sess_normal;
    uint32              sess_health;
    reformer_ctrl_t     reformer_ctrl;
    reform_info_t       reform_info;
    spinlock_t          share_info_lock;
    share_info_t        share_info;
    reform_info_t       last_reform_info;       // for debug
    share_info_t        last_share_info;        // for debug
    switchover_info_t   switchover_info;
    health_info_t       health_info;
    parallel_info_t     parallel_info;
    uint32              channel_cnt;            // used for channel check
    bool8               catalog_centralized;    // centralized or distributed
    bool8               ignore_offline;         // treat old off-line as old remove
    bool8               mes_has_init;
    bool8               unused;
    reform_scrlock_context_t scrlock_reinit_ctx;
    az_switchover_info_t  az_switchover_info;
    latch_t             res_ctrl_latch; // lock control for reform dependent db resources
} reform_context_t;

typedef struct st_dms_driver_ping_info {
    spinlock_t lock;
    driver_ping_info_t driver_ping_info;
} dms_driver_ping_info_t;

#define REFORM_TYPE_IS_SWITCHOVER(type) (type == DMS_REFORM_TYPE_FOR_SWITCHOVER || \
    type == DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS)

#define REFORM_TYPE_IS_AZ_SWITCHOVER(type) (type == DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE || \
    type == DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE || type == DMS_REFORM_TYPE_FOR_AZ_FAILOVER)

typedef int(*dms_reform_proc)();
typedef struct st_dms_reform_proc {
    char                desc[DMS_REFORM_STEP_DESC_STR_LEN];
    dms_reform_proc     proc;
    dms_reform_proc     proc_parallel;
    bool32              drc_block;
} dms_reform_proc_t;

int dms_reform_init(dms_profile_t *dms_profile);
void dms_reform_judgement_step_log(void);
void dms_reform_set_start(void);
void dms_reform_uninit(void);
void dms_reform_list_to_bitmap(uint64 *bitmap, instance_list_t *list);
void dms_reform_bitmap_to_list(instance_list_t *list, uint64 bitmap);
bool8 dms_dst_id_is_self(uint8 dst_id);
bool8 dms_reform_list_exist(instance_list_t *list, uint8 inst_id);
bool8 dms_reform_type_is(dms_reform_type_t type);
char *dms_reform_phase_desc(uint8 reform_phase);
void dms_reform_add_step(reform_step_t step);
#ifndef OPENGAUSS
void dms_reform_list_remove(instance_list_t *list, int index);
#endif
void dms_reform_list_init(instance_list_t *list);
void dms_reform_list_add(instance_list_t *list_dst, uint8 inst_id);
void dms_reform_inst_list_add(instance_list_t *inst_lists, uint8 list_index, uint8 inst_id);
void dms_reform_list_add_all(instance_list_t *list_dst);
void dms_reform_list_cancat(instance_list_t *list_dst, instance_list_t *list_src);
void dms_reform_list_minus(instance_list_t *list_dst, instance_list_t *list_src);

#ifdef __cplusplus
}
#endif
#endif
