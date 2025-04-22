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
 * cmpt_msg_proc.c
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_proc.c
 *
 * -------------------------------------------------------------------------
 */

#include "cmpt_msg_version.h"
#include "cmpt_msg_reform.h"
#include "dms_reform_judge.h"
#include "dms_reform_judge_step.h"
#include "dms_reform_judge_switch.h"
#include "dms_reform_judge_stat.h"
#include "dms_reform.h"
#include "dms_process.h"
#include "drc_res_mgr.h"

static void dms_reform_judgement_normal(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_recovery_analyse(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_reset_user();
    dms_reform_judgement_sync_node_lfn();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_new_join(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    dms_reform_judgement_prepare();
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    if (!share_info->catalog_centralized) {
        dms_reform_judgement_lock_instance();
        dms_reform_judgement_drc_clean(inst_lists);
        dms_reform_judgement_rebuild(inst_lists);
    }
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_set_curr_point();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_update_scn();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_new_join_v4(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    dms_reform_judgement_prepare();
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    if (!share_info->catalog_centralized) {
        dms_reform_judgement_lock_instance();
        dms_reform_judgement_drc_clean(inst_lists);
        dms_reform_judgement_rebuild(inst_lists);
    }
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_sync_node_lfn();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_set_curr_point();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_update_scn();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_new_join_v5(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    dms_reform_judgement_prepare();
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    if (share_info->catalog_centralized || share_info->drm_trigger) {
        dms_reform_judgement_remaster(inst_lists);
    } else {
        dms_reform_judgement_lock_instance();
        dms_reform_judgement_remaster(inst_lists);
        dms_reform_judgement_drc_clean(inst_lists);
        dms_reform_judgement_rebuild(inst_lists);
    }
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_sync_node_lfn();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_set_curr_point();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_update_scn();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_old_remove(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_recovery_analyse(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_reset_user();
    dms_reform_judgement_sync_node_lfn();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_success();
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_shutdown_consistency(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_success();
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_shutdown_consistency_v4(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_sync_node_lfn();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_success();
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_normal_standby(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_reset_user();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_standby_sync();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_stop_server();
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_page_access();
    /* stop lrpl must after page access and before txn_deposit */
    dms_reform_judgement_stop_lrpl();
    dms_reform_judgement_calibrate_log_file();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_space_reload();
    // file_unblocked must be done before txn_deposit
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_start_lrpl();
    dms_reform_judgement_resume_server();
    dms_reform_judgement_done();
}

#ifdef OPENGAUSS
static void dms_reform_judgement_switchover_opengauss(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_validate(false);
    dms_reform_judgement_switchover_demote(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_switch_lock();
    dms_reform_judgement_switchover_promote_opengauss();
    dms_reform_judgement_drc_validate(false);
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_failover_opengauss(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_drc_validate(true); /* maintain drc inaccess as failover not finished */
    dms_reform_judgement_failover_promote_opengauss();
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_repair();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_recovery_opengauss(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_drc_validate(false);
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_normal_opengauss(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_repair();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_recovery_opengauss(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_drc_validate(false);
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}
#endif

static void dms_reform_judgement_build(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_page_access();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_full_clean(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair();
#ifndef OPENGAUSS
    dms_reform_judgement_reset_user();
#endif
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_maintain(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_rst_recover(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_standby_maintain(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_start_lrpl();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_az_switchover_demote(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_az_demote_phase1(inst_lists);
    dms_reform_judgement_az_demote_change_role(inst_lists);
    dms_reform_judgement_az_demote_approve(inst_lists);
    dms_reform_judgement_az_demote_phase2(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_success();
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_start_lrpl();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_az_switchover_to_promote(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_az_promote_phase1();
    dms_reform_judgement_reload_txn();
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_az_promote_phase2();
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_space_reload();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_success();
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_az_failover(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_az_failover_promote_phase1();
    dms_reform_judgement_az_failover_promote_resetlog();
    dms_reform_judgement_reload_txn();
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_az_failover_promote_phase2();
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_space_reload();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_success();
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static bool32 dms_reform_judgement_normal_check(instance_list_t *inst_lists)
{
    // there are instances which status is out or reform, no need reform.
    if (inst_lists[INST_LIST_OLD_OUT].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REFORM].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_OUT].inst_id_count != 0 || inst_lists[INST_LIST_NEW_REFORM].inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, "
            "old_out: %d, old_reform: %d, new_out: %d, new_reform: %d",
            inst_lists[INST_LIST_OLD_OUT].inst_id_count, inst_lists[INST_LIST_OLD_REFORM].inst_id_count,
            inst_lists[INST_LIST_NEW_OUT].inst_id_count, inst_lists[INST_LIST_NEW_REFORM].inst_id_count);
        return CM_FALSE;
    }

#ifndef OPENGAUSS
    if (dms_reform_judgement_az_switchover_check(inst_lists)) {
        return CM_TRUE;
    }
#endif

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 &&
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        dms_reform_judgement_stat_cancel();
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, old_remove: 0, new_join: 0");
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool32 dms_reform_judgement_new_join_check(instance_list_t *inst_lists)
{
    // there are instances which status is out or reform, no need reform.
    if (inst_lists[INST_LIST_OLD_OUT].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REFORM].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_OUT].inst_id_count != 0 || inst_lists[INST_LIST_NEW_REFORM].inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, "
            "old_out: %d, old_reform: %d, new_out: %d, new_reform: %d",
            inst_lists[INST_LIST_OLD_OUT].inst_id_count, inst_lists[INST_LIST_OLD_REFORM].inst_id_count,
            inst_lists[INST_LIST_NEW_OUT].inst_id_count, inst_lists[INST_LIST_NEW_REFORM].inst_id_count);
        return CM_FALSE;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    if (g_dms.callback.db_in_rollback(g_dms.reform_ctx.handle_judge)) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, db in rollback");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool32 dms_reform_judgement_new_join_check_v5(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    // there are instances which status is out or reform, no need reform.
    if (inst_lists[INST_LIST_OLD_OUT].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REFORM].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_OUT].inst_id_count != 0 || inst_lists[INST_LIST_NEW_REFORM].inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, "
            "old_out: %d, old_reform: %d, new_out: %d, new_reform: %d",
            inst_lists[INST_LIST_OLD_OUT].inst_id_count, inst_lists[INST_LIST_OLD_REFORM].inst_id_count,
            inst_lists[INST_LIST_NEW_OUT].inst_id_count, inst_lists[INST_LIST_NEW_REFORM].inst_id_count);
        return CM_FALSE;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    if (g_dms.callback.db_in_rollback(g_dms.reform_ctx.handle_judge)) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, db in rollback");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    // waiting for DRM
    if (!drc_cmp_part_info()) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, DRM has not yet completed");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    // if drc is centralized, no need to do DRM
    if (share_info->catalog_centralized) {
        share_info->drm_trigger = CM_FALSE;
    } else {
        share_info->drm_trigger = CM_TRUE;
    }
    return CM_TRUE;
}

static bool32 dms_reform_judgement_old_remove_check(instance_list_t *inst_lists)
{
    // there are instances which status is out or reform, no need reform.
    if (inst_lists[INST_LIST_OLD_OUT].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REFORM].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_OUT].inst_id_count != 0 || inst_lists[INST_LIST_NEW_REFORM].inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, "
            "old_out: %d, old_reform: %d, new_out: %d, new_reform: %d",
            inst_lists[INST_LIST_OLD_OUT].inst_id_count, inst_lists[INST_LIST_OLD_REFORM].inst_id_count,
            inst_lists[INST_LIST_NEW_OUT].inst_id_count, inst_lists[INST_LIST_NEW_REFORM].inst_id_count);
        return CM_FALSE;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool32 dms_reform_judgement_shutdown_consistency_check(instance_list_t *inst_lists)
{
    return dms_reform_judgement_old_remove_check(inst_lists);
}

static bool32 dms_reform_judgement_build_check(instance_list_t *inst_lists)
{
    if (DMS_FIRST_REFORM_FINISH) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, first reform has finished");
        return CM_FALSE;
    }
    return CM_TRUE;
}

#ifdef OPENGAUSS
static bool32 dms_reform_judgement_normal_opengauss_check(instance_list_t *inst_lists)
{
    // there are instances which status is out or reform, no need reform.
    if (inst_lists[INST_LIST_OLD_OUT].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REFORM].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_OUT].inst_id_count != 0 || inst_lists[INST_LIST_NEW_REFORM].inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, "
            "old_out: %d, old_reform: %d, new_out: %d, new_reform: %d",
            inst_lists[INST_LIST_OLD_OUT].inst_id_count, inst_lists[INST_LIST_OLD_REFORM].inst_id_count,
            inst_lists[INST_LIST_NEW_OUT].inst_id_count, inst_lists[INST_LIST_NEW_REFORM].inst_id_count);
        return CM_FALSE;
    }

    if (dms_reform_judgement_switchover_opengauss_check(inst_lists)) {
        return CM_TRUE;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 &&
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, old_remove: 0, new_join: 0");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    return CM_TRUE;
}
#endif

static bool32 dms_reform_judgement_full_clean_check(instance_list_t *inst_lists)
{
    return CM_TRUE;
}

static bool32 dms_reform_judgement_maintain_check(instance_list_t *inst_lists)
{
    if (DMS_FIRST_REFORM_FINISH) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, first reform has finished");
        return CM_FALSE;
    }

    // if instance status is not join, finish current judgement
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, new_join: 0");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->promote_id = (uint8)g_dms.inst_id;
    return CM_TRUE;
}

static bool32 dms_reform_judgement_rst_recover_check(instance_list_t *inst_lists)
{
    // if instance status is not join, finish current judgement, that means last rst recover has finished
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, new_join: 0");
        dms_reform_judgement_stat_cancel();
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool32 dms_reform_judgement_standby_maintain_check(instance_list_t *inst_lists)
{
    if (DMS_FIRST_REFORM_FINISH) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, first reform has finished");
        return CM_FALSE;
    }

    // if instance status is not join, finish current judgement
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, new_join: 0");
        return CM_FALSE;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->promote_id = (uint8)g_dms.inst_id;
    return CM_TRUE;
}

static dms_reform_judgement_proc_t g_reform_judgement_proc_base[DMS_REFORM_TYPE_COUNT] = {
    [DMS_REFORM_TYPE_FOR_NORMAL] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS] = {
    dms_reform_judgement_normal_opengauss_check, dms_reform_judgement_normal_opengauss },

    [DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS] = {
    dms_reform_judgement_failover_opengauss_check, dms_reform_judgement_failover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_BUILD] = {
    dms_reform_judgement_build_check, dms_reform_judgement_build },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS] = {
    dms_reform_judgement_switchover_opengauss_check, dms_reform_judgement_switchover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_FULL_CLEAN] = {
    dms_reform_judgement_full_clean_check, dms_reform_judgement_full_clean },

    [DMS_REFORM_TYPE_FOR_MAINTAIN] = {
    dms_reform_judgement_maintain_check, dms_reform_judgement_maintain },

    [DMS_REFORM_TYPE_FOR_RST_RECOVER] = {
    dms_reform_judgement_rst_recover_check, dms_reform_judgement_rst_recover },

    [DMS_REFORM_TYPE_FOR_NEW_JOIN] = {
    dms_reform_judgement_new_join_check, dms_reform_judgement_new_join },

    [DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN] = {
    dms_reform_judgement_standby_maintain_check, dms_reform_judgement_standby_maintain },

    [DMS_REFORM_TYPE_FOR_NORMAL_STANDBY] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal_standby },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_demote },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_to_promote },

    [DMS_REFORM_TYPE_FOR_AZ_FAILOVER] = {
    dms_reform_judgement_az_failover_check, dms_reform_judgement_az_failover },

    [DMS_REFORM_TYPE_FOR_OLD_REMOVE] = {
    dms_reform_judgement_old_remove_check, dms_reform_judgement_old_remove },

    [DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY] = {
    dms_reform_judgement_shutdown_consistency_check, dms_reform_judgement_shutdown_consistency },
};

static dms_reform_judgement_proc_t g_reform_judgement_proc_v4[DMS_REFORM_TYPE_COUNT] = {
    [DMS_REFORM_TYPE_FOR_NORMAL] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS] = {
    dms_reform_judgement_normal_opengauss_check, dms_reform_judgement_normal_opengauss },

    [DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS] = {
    dms_reform_judgement_failover_opengauss_check, dms_reform_judgement_failover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_BUILD] = {
    dms_reform_judgement_build_check, dms_reform_judgement_build },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS] = {
    dms_reform_judgement_switchover_opengauss_check, dms_reform_judgement_switchover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_FULL_CLEAN] = {
    dms_reform_judgement_full_clean_check, dms_reform_judgement_full_clean },

    [DMS_REFORM_TYPE_FOR_MAINTAIN] = {
    dms_reform_judgement_maintain_check, dms_reform_judgement_maintain },

    [DMS_REFORM_TYPE_FOR_RST_RECOVER] = {
    dms_reform_judgement_rst_recover_check, dms_reform_judgement_rst_recover },

    [DMS_REFORM_TYPE_FOR_NEW_JOIN] = {
    dms_reform_judgement_new_join_check, dms_reform_judgement_new_join_v4 },

    [DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN] = {
    dms_reform_judgement_standby_maintain_check, dms_reform_judgement_standby_maintain },

    [DMS_REFORM_TYPE_FOR_NORMAL_STANDBY] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal_standby },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_demote },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_to_promote },

    [DMS_REFORM_TYPE_FOR_AZ_FAILOVER] = {
    dms_reform_judgement_az_failover_check, dms_reform_judgement_az_failover },

    [DMS_REFORM_TYPE_FOR_OLD_REMOVE] = {
    dms_reform_judgement_old_remove_check, dms_reform_judgement_old_remove },

    [DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY] = {
    dms_reform_judgement_shutdown_consistency_check, dms_reform_judgement_shutdown_consistency_v4 },
};

static dms_reform_judgement_proc_t g_reform_judgement_proc_v5[DMS_REFORM_TYPE_COUNT] = {
    [DMS_REFORM_TYPE_FOR_NORMAL] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS] = {
    dms_reform_judgement_normal_opengauss_check, dms_reform_judgement_normal_opengauss },

    [DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS] = {
    dms_reform_judgement_failover_opengauss_check, dms_reform_judgement_failover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_BUILD] = {
    dms_reform_judgement_build_check, dms_reform_judgement_build },
#ifdef OPENGAUSS
    [DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS] = {
    dms_reform_judgement_switchover_opengauss_check, dms_reform_judgement_switchover_opengauss },
#endif
    [DMS_REFORM_TYPE_FOR_FULL_CLEAN] = {
    dms_reform_judgement_full_clean_check, dms_reform_judgement_full_clean },

    [DMS_REFORM_TYPE_FOR_MAINTAIN] = {
    dms_reform_judgement_maintain_check, dms_reform_judgement_maintain },

    [DMS_REFORM_TYPE_FOR_RST_RECOVER] = {
    dms_reform_judgement_rst_recover_check, dms_reform_judgement_rst_recover },

    [DMS_REFORM_TYPE_FOR_NEW_JOIN] = {
    dms_reform_judgement_new_join_check_v5, dms_reform_judgement_new_join_v5 },

    [DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN] = {
    dms_reform_judgement_standby_maintain_check, dms_reform_judgement_standby_maintain },

    [DMS_REFORM_TYPE_FOR_NORMAL_STANDBY] = {
    dms_reform_judgement_normal_check, dms_reform_judgement_normal_standby },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_demote },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE] = {
    dms_reform_judgement_az_switchover_check, dms_reform_judgement_az_switchover_to_promote },

    [DMS_REFORM_TYPE_FOR_AZ_FAILOVER] = {
    dms_reform_judgement_az_failover_check, dms_reform_judgement_az_failover },

    [DMS_REFORM_TYPE_FOR_OLD_REMOVE] = {
    dms_reform_judgement_old_remove_check, dms_reform_judgement_old_remove },

    [DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY] = {
    dms_reform_judgement_shutdown_consistency_check, dms_reform_judgement_shutdown_consistency_v4 },
};

static dms_reform_judgement_proc_t *g_reform_judgement_proc_map[DMS_PROTO_VER_NUMS] = {
    [DMS_PROTO_VER_1] = g_reform_judgement_proc_base,
    [DMS_PROTO_VER_2] = g_reform_judgement_proc_base,
    [DMS_PROTO_VER_3] = g_reform_judgement_proc_base,
    [DMS_PROTO_VER_4] = g_reform_judgement_proc_v4,
    [DMS_PROTO_VER_5] = g_reform_judgement_proc_v5,
};

static dms_proto_version_attr g_req_share_info_version_ctrl[DMS_PROTO_VER_NUMS] = {
     [DMS_PROTO_VER_1] = { CM_ALIGN8(sizeof(dms_message_head_t) + OFFSET_OF(share_info_t, inst_bitmap)) },
     [DMS_PROTO_VER_2] = { CM_ALIGN8(sizeof(dms_message_head_t) + OFFSET_OF(share_info_t, old_master_info)) },
     [DMS_PROTO_VER_3] = { CM_ALIGN8(sizeof(dms_message_head_t) + OFFSET_OF(share_info_t, old_master_info)) },
     [DMS_PROTO_VER_4] = { CM_ALIGN8(sizeof(dms_message_head_t) + OFFSET_OF(share_info_t, old_master_info)) },
     [DMS_PROTO_VER_5] = { CM_ALIGN8(sizeof(dms_message_head_t) + sizeof(share_info_t)) },
};

