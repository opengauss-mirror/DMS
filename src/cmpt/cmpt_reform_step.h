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
 * cmpt_reform_step.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_reform_step.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_REFORM_STEP_H__
#define __CMPT_REFORM_STEP_H__

#ifdef __cplusplus
extern "C" {
#endif

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
    DMS_REFORM_STEP_CALIBRATE_LOG_FILE,

    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE1,        // for Gauss100, AZ SWITCHOVER primary to standby
    DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_STOP_CKPT,
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

    DMS_REFORM_STEP_SYNC_NODE_LFN,
    DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_SWITCH_LOG,   // for Gauss100, AZ SWITCHOVER standby to primary
    DMS_REFORM_STEP_AZ_PROMOTE_SUCCESS,
    DMS_REFORM_STEP_COUNT
} reform_step_t;

// The steps will be repeated, DMS_REFORM_STEP_TOTAL_COUNT > DMS_REFORM_STEP_COUNT
#define DMS_REFORM_STEP_TOTAL_COUNT     128
#define DMS_REFORM_PHASE_TOTAL_COUNT    8

#ifdef __cplusplus
}
#endif

#endif // __CMPT_REFORM_STEP_H__