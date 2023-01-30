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

#define DMS_REFORM_LONG_SLEEP           cm_sleep(500)
#define DMS_REFORM_SHORT_SLEEP          cm_sleep(10)
#define DMS_REFORM_LONG_TIMEOUT         5000
#define DMS_REFORM_SHORT_TIMEOUT        500
#define DMS_REFORM_CONFIRM_TIMEOUT      5000000 // 5s
#define DMS_REFORM_CONTEXT              (&g_dms.reform_ctx)
#define DMS_REFORMER_CTRL               (&g_dms.reform_ctx.reformer_ctrl)
#define DMS_REFORM_INFO                 (&g_dms.reform_ctx.reform_info)
#define DMS_SHARE_INFO                  (&g_dms.reform_ctx.share_info)
#define DMS_REMASTER_INFO               (&g_dms.reform_ctx.share_info.remaster_info)
#define DMS_MIGRATE_INFO                (&g_dms.reform_ctx.share_info.migrate_info)
#define DMS_REBUILD_INFO                (&g_dms.reform_ctx.reform_info.rebuild_info)
#define DMS_SWITCHOVER_INFO             (&g_dms.reform_ctx.switchover_info)
#define DMS_HEALTH_INFO                 (&g_dms.reform_ctx.health_info)
#define DRC_PART_REMASTER_ID(part_id)   (g_dms.reform_ctx.share_info.remaster_info.part_map[(part_id)].inst_id)
#define DMS_CATALOG_IS_CENTRALIZED      (g_dms.reform_ctx.catalog_centralized)
#define DMS_CATALOG_IS_PRIMARY_STANDBY  (g_dms.reform_ctx.primary_standby)

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

#define DMS_MAX_FAIL_TIME               30

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
#define DMS_REFORM_STEP_TOTAL_COUNT     64
#define DMS_REFORM_PHASE_TOTAL_COUNT    8

// Notice: every step should not be dependent on its Value, Value is only used for distinguish different step
typedef enum en_reform_step {
    DMS_REFORM_STEP_DONE,
    DMS_REFORM_STEP_PREPARE,                        // just sync wait reformer. do nothing
    DMS_REFORM_STEP_START,                          // no need to set last_fail before this step
    DMS_REFORM_STEP_DISCONNECT,
    DMS_REFORM_STEP_RECONNECT,
    DMS_REFORM_STEP_DRC_CLEAN,
    DMS_REFORM_STEP_MIGRATE,
    DMS_REFORM_STEP_REBUILD,
    DMS_REFORM_STEP_REMASTER,
    DMS_REFORM_STEP_REPAIR,
    DMS_REFORM_STEP_SWITCH_LOCK,
    DMS_REFORM_STEP_SWITCHOVER_DEMOTE,
    DMS_REFORM_STEP_SWITCHOVER_PROMOTE,
    DMS_REFORM_STEP_RECOVERY,
    DMS_REFORM_STEP_RECOVERY_OPENGAUSS,
    DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN,
    DMS_REFORM_STEP_TXN_DEPOSIT,
    DMS_REFORM_STEP_ROLLBACK,
    DMS_REFORM_STEP_SUCCESS,
    DMS_REFORM_STEP_SELF_FAIL,                      // cause by self
    DMS_REFORM_STEP_REFORM_FAIL,                    // cause by notification from reformer
    DMS_REFORM_STEP_SYNC_WAIT,                      // tips: can not use before reconnect
    DMS_REFORM_STEP_PAGE_ACCESS,                    // set page accessible
    DMS_REFORM_STEP_DRC_ACCESS,                     // set drc accessible
    DMS_REFORM_STEP_DRC_INACCESS,                   // set drc inaccessible
    DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS,
    DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS,
    DMS_REFORM_STEP_STARTUP_OPENGAUSS,              // for opengauss
    DMS_REFORM_STEP_FLUSH_COPY,
    DMS_REFORM_STEP_DONE_CHECK,
    DMS_REFORM_STEP_SET_PHASE,                      // for Gauss100
    DMS_REFORM_STEP_WAIT_DB,                        // for Gauss100
    DMS_REFORM_STEP_BCAST_ENABLE,                   // for Gauss100
    DMS_REFORM_STEP_BCAST_UNABLE,                   // for Gauss100
    DMS_REFORM_STEP_UPDATE_SCN,
    DMS_REFORM_STEP_WAIT_CKPT,                      // for Gauss100
    DMS_REFORM_STEP_DRC_VALIDATE,

    DMS_REFORM_STEP_COUNT
} reform_step_t;

#define DMS_REFORM_STEP_DESC_STR_LEN 30

typedef enum en_dms_reform_type {
    // for multi_write
    DMS_REFORM_TYPE_FOR_NORMAL = 0,

    // for Gauss100
    DMS_REFORM_TYPE_FOR_BUILD,
    DMS_REFORM_TYPE_FOR_FAILOVER,
    DMS_REFORM_TYPE_FOR_SWITCHOVER,

    // for openGauss
    DMS_REFORM_TYPE_FOR_OPENGAUSS,
    DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS,
    DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS,

    // common
    DMS_REFORM_TYPE_FOR_FULL_CLEAN, // for all instances are online and stable, and all instances status is IN
    DMS_REFORM_TYPE_FOR_MAINTAIN,   // for start database without CM, every instance is supported
    // New type need to be added start from here
    DMS_REFORM_TYPE_COUNT
} dms_reform_type_t;

typedef enum en_db_open_status {
    DB_OPEN_STATUS_NORMAL = 0,
    DB_OPEN_STATUS_RESTRICT = 1,
    DB_OPEN_STATUS_EMERGENCY = 2,
    DB_OPEN_STATUS_UPGRADE = 3,
    DB_OPEN_STATUS_UPGRADE_PHASE_2 = 4,
} db_open_status_t;

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

typedef struct st_share_info {
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
    uint8               unused[2];
    uint64              version_num;
} share_info_t;

typedef struct st_rebuild_info {
    void                *rebuild_data[DMS_MAX_INSTANCES];
} rebuild_info_t;

typedef struct st_reformer_ctrl {
    bool8               instance_fail[DMS_MAX_INSTANCES];
    uint8               instance_step[DMS_MAX_INSTANCES];
} reformer_ctrl_t;

typedef struct st_reform_info {
    latch_t             bcast_latch;
    latch_t             ddl_latch;
    uint64              max_scn;
    spinlock_t          version_lock;
    spinlock_t          mes_lock;
    uint64              bitmap_mes;
    uint64              bitmap_connect;
    rebuild_info_t      rebuild_info;
    version_info_t      reformer_version;
    uint64              start_time;
    uint64              proc_time;              // check proc if active or fall into an endless loop
    spinlock_t          status_lock;
    int32               err_code;
    dms_thread_status_t thread_status;
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
    bool8               bcast_unable;
    bool8               ddl_unable;
    bool8               parallel_enable;        // dms reform proc parallel enable
    uint8               unused[3];
} reform_info_t;

typedef struct st_switchover_info {
    uint64              start_time;             // start lsn
    spinlock_t          lock;
    bool8               switch_req;             // concurrency control & used in dms_reform_judgement
    uint8               inst_id;                // instance id of initiator
    uint16              sess_id;                // session id of initiator, use for message reentry
} switchover_info_t;

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
    bool8 enable_ssl_param;
    bool8 is_server;
    uint8 recovery_node_num;
} reform_scrlock_context_t;

typedef struct st_health_info {
    uint8               online_status[DMS_MAX_INSTANCES];
    uint64              online_times[DMS_MAX_INSTANCES];
    dms_thread_status_t thread_status;
} health_info_t;

typedef struct st_reform_context {
    thread_t            thread_judgement;       // dms_reform_judgement_thread
    thread_t            thread_reformer;        // dms_reformer_thread
    thread_t            thread_reform;          // reform
    thread_t            thread_health;          // health check
    /*
        1. handle_judge&sess_judge used in thread<dms_reform_judgement_thread>
        2. handle_proc&sess_proc used in thread<dms_reform_proc_thread> while step before RECOVERY, include RECOVERY
           it will set buf_res->in_recovery True when access page
    */
    void                *handle_judge;          // used in reform judgment
    void                *handle_proc;           // used in reform, and set recovery flag in buf_res
    void                *handle_normal;
    void                *handle_health;
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
    uint32              channel_cnt;            // used for channel check
    bool8               catalog_centralized;    // centralized or distributed
    bool8               primary_standby;        // primary_standby or not
    bool8               ignore_offline;         // treat old off-line as old remove
    bool8               init_success;
    bool8               mes_has_init;
    uint8               unused[3];
    reform_scrlock_context_t scrlock_reinit_ctx;
} reform_context_t;

#define REFORM_TYPE_IS_SWITCHOVER(type) (type == DMS_REFORM_TYPE_FOR_SWITCHOVER || \
    type == DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS)

typedef int(*dms_reform_proc)();
typedef struct st_dms_reform_proc {
    char                desc[DMS_REFORM_STEP_DESC_STR_LEN];
    dms_reform_proc     proc;
    dms_reform_proc     proc_parallel;
} dms_reform_proc_t;

int dms_reform_init(dms_profile_t *dms_profile);
void dms_reform_judgement_step_log(void);
void dms_reform_set_start(void);
void dms_reform_uninit(void);
void dms_reform_list_to_bitmap(uint64 *bitmap, instance_list_t *list);
void dms_reform_set_fail(void);
bool8 dms_dst_id_is_self(uint8 dst_id);
bool8 dms_reform_list_exist(instance_list_t *list, uint8 inst_id);
bool8 dms_reform_type_is(dms_reform_type_t type);
char *dms_reform_phase_desc(uint8 reform_phase);

#ifdef __cplusplus
}
#endif
#endif