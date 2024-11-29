/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
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
 * dms_reform_judge_step.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_step.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_JUDGE_STEP_H__
#define __DMS_REFORM_JUDGE_STEP_H__

#include "cm_thread.h"
#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_judgement_prepare(void);
void dms_reform_judgement_start(void);
void dms_reform_judgement_disconnect(instance_list_t *inst_lists);
void dms_reform_judgement_reconnect(instance_list_t *inst_lists);
void dms_reform_judgement_drc_clean(instance_list_t *inst_lists);
void dms_reform_part_copy(void);
void dms_reform_part_recalc_for_distribute(instance_list_t *inst_lists);
void dms_reform_part_recalc_for_centralized(instance_list_t *inst_lists);
void dms_reform_part_recalc(instance_list_t *inst_lists);
void dms_reform_part_collect_inner(drc_inst_part_t *inst_part, uint16 *parts, uint8 *part_num);
void dms_reform_part_collect(uint16 *parts, uint8 *part_num);
void dms_reform_part_assign_inner(drc_inst_part_t *inst_part, uint8 inst_id, uint16 *parts, uint8 *part_num);
void dms_reform_part_assign(uint16 *parts, uint8 part_num);
void dms_reform_judgement_remaster(instance_list_t *inst_lists);
void dms_reform_judgement_repair(void);
void dms_reform_judgement_switch_lock(void);
void dms_reform_judgement_switchover_demote(instance_list_t *inst_lists);
void dms_reform_judgement_switchover_promote_opengauss(void);
void dms_reform_judgement_failover_promote_opengauss(void);
void dms_reform_migrate_task_inner(uint8 part_id, drc_part_t *part_now, drc_part_t *part_remaster,
    uint64 bitmap_online);
void dms_reform_migrate_task(void);
void dms_reform_judgement_migrate(instance_list_t *inst_lists);
void dms_reform_judgement_rebuild(instance_list_t *inst_lists);
void dms_reform_judgement_recovery_analyse(instance_list_t *inst_lists);
void dms_reform_judgement_set_curr_point(void);
void dms_reform_judgement_recovery(instance_list_t *inst_lists);
void dms_reform_judgement_dw_recovery(instance_list_t *inst_lists);
void dms_reform_judgement_df_recovery();
void dms_reform_judgement_space_reload();
void dms_reform_judgement_recovery_opengauss(instance_list_t *inst_lists);
void dms_reform_judgement_rollback_prepare(instance_list_t *inst_lists);
void dms_reform_judgement_reload_txn(void);
void dms_reform_judgement_rollback_start(instance_list_t *inst_lists);
void dms_reform_judgement_ddl_2phase_rcy();
void dms_reform_judgement_txn_deposit(instance_list_t *inst_lists);
void dms_reform_judgement_drc_inaccess(void);
void dms_reform_judgement_page_access(void);
void dms_reform_judgement_drc_access(void);
void dms_reform_judgement_lock_instance(void);
void dms_reform_judgement_reset_user(void);
void dms_reform_judgement_set_remove_point(instance_list_t *inst_lists);
void dms_reform_judgement_success(void);
void dms_reform_judgement_done(void);
void dms_refrom_judgement_startup_opengauss(void);
void dms_reform_judgement_set_phase(reform_phase_t reform_phase);
void dms_reform_judgement_file_blocked(instance_list_t *inst_lists);
void dms_reform_judgement_update_scn(void);
void dms_reform_judgement_wait_ckpt(void);
void dms_reform_judgement_file_unblocked(void);
void dms_reform_judgement_xa_access(void);
void dms_reform_judgement_standby_sync(void);
void dms_reform_judgement_stop_server(void);
void dms_reform_judgement_resume_server(void);
void dms_reform_judgement_start_lrpl(void);
void dms_reform_judgement_stop_lrpl(void);
void dms_reform_judgement_calibrate_log_file(void);
void dms_reform_judgement_rollback_for_az_standby(instance_list_t *inst_lists);
void dms_reform_judgement_drc_validate(bool8 set_inaccess);

#ifdef __cplusplus
}
#endif
#endif