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
 * dms_reform_judge_step.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_step.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_judge_step.h"
#include "cm_timer.h"
#include "dms_error.h"
#include "dms_process.h"

void dms_reform_judgement_prepare(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->reform_step_count = 0;
    share_info->reform_phase_count = 0;
    share_info->judge_time = g_timer()->now;
    dms_reform_add_step(DMS_REFORM_STEP_PREPARE);
}

void dms_reform_judgement_start(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_START);
}

void dms_reform_judgement_disconnect(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_disconnect);
    if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_disconnect, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_list_to_bitmap(&share_info->bitmap_disconnect, &share_info->list_disconnect);
        dms_reform_add_step(DMS_REFORM_STEP_DISCONNECT);
    }
}

void dms_reform_judgement_reconnect(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_reconnect);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_reconnect, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_reconnect, &inst_lists[INST_LIST_NEW_JOIN]);
        dms_reform_list_to_bitmap(&share_info->bitmap_reconnect, &share_info->list_reconnect);
        dms_reform_add_step(DMS_REFORM_STEP_RECONNECT);
    }
}

// Notice: DRC_CLEAN and REBUILD must be used in pairs
void dms_reform_judgement_drc_clean(instance_list_t *inst_lists)
{
    // if reform_type is fail-over, all DRC has lost, no need to do drc_clean
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
        return;
    }

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FULL_CLEAN);
}

void dms_reform_part_copy(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    uint32 size;
    errno_t err;

    if (reform_info->use_default_map) {
        size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
        err = memset_s(remaster_info->inst_part_tbl, size, 0, size);
        DMS_SECUREC_CHECK(err);
        size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
        err = memset_s(remaster_info->part_map, size, 0, size);
        DMS_SECUREC_CHECK(err);
    } else {
        size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
        err = memcpy_s(remaster_info->inst_part_tbl, size, part_mngr->inst_part_tbl, size);
        DMS_SECUREC_CHECK(err);
        size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
        err = memcpy_s(remaster_info->part_map, size, part_mngr->part_map, size);
        DMS_SECUREC_CHECK(err);
    }
}

void dms_reform_part_recalc_for_distribute(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    instance_list_t *list_online = &share_info->list_online;
    instance_list_t *list_old_remove = &inst_lists[INST_LIST_OLD_REMOVE];
    drc_inst_part_t *inst_part = NULL;
    uint16 avg_part_num = DRC_MAX_PART_NUM / list_online->inst_id_count;
    uint16 rest_part_num = DRC_MAX_PART_NUM % list_online->inst_id_count;
    uint8 inst = CM_INVALID_ID8;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        inst = list_online->inst_id_list[i];
        inst_part = &remaster_info->inst_part_tbl[inst];
        inst_part->expected_num = avg_part_num;

        // if expected_num is equal to count, don't assign one more
        if (rest_part_num > 0 && inst_part->expected_num != inst_part->count) {
            inst_part->expected_num++;
            rest_part_num--;
        }
    }
    CM_ASSERT(rest_part_num == 0);

    for (uint8 i = 0; i < list_old_remove->inst_id_count; i++) {
        inst = list_old_remove->inst_id_list[i];
        inst_part = &remaster_info->inst_part_tbl[inst];
        inst_part->expected_num = 0;
    }
}

void dms_reform_part_recalc_for_centralized(instance_list_t *inst_lists)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_inst_part_t *inst_part = NULL;
    uint8 inst = CM_INVALID_ID8;

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        inst_part = &remaster_info->inst_part_tbl[i];
        inst_part->expected_num = 0;
    }

    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        inst = share_info->promote_id;
    } else {
        inst = (uint8)g_dms.inst_id;
    }
    inst_part = &remaster_info->inst_part_tbl[inst];
    inst_part->expected_num = DRC_MAX_PART_NUM;
}

void dms_reform_part_recalc(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    if (share_info->catalog_centralized) {
        dms_reform_part_recalc_for_centralized(inst_lists);
    } else {
        dms_reform_part_recalc_for_distribute(inst_lists);
    }
}

void dms_reform_part_collect_inner(drc_inst_part_t *inst_part, uint16 *parts, uint8 *part_num)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_part_t *part_map = NULL;
    uint16 part_id = CM_INVALID_ID16;

    while (inst_part->count > inst_part->expected_num) {
        part_id = inst_part->first;
        cm_panic(part_id < DRC_MAX_PART_NUM);
        part_map = &remaster_info->part_map[part_id];
        inst_part->first = part_map->next;
        inst_part->count--;
        parts[(*part_num)++] = part_id;
        cm_panic_log((*part_num) <= DRC_MAX_PART_NUM, "dms_reform_part_collect part_num error: %d", *part_num);
    }
}

void dms_reform_part_collect(uint16 *parts, uint8 *part_num)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_inst_part_t *inst_part = NULL;

    // part map not exists in all instances, should assign all parts
    if (reform_info->use_default_map) {
        for (uint16 i = 0; i < DRC_MAX_PART_NUM; i++) {
            parts[i] = i;
        }
        *part_num = DRC_MAX_PART_NUM;
        return;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        inst_part = &remaster_info->inst_part_tbl[i];
        dms_reform_part_collect_inner(inst_part, parts, part_num);
    }
}

void dms_reform_part_assign_inner(drc_inst_part_t *inst_part, uint8 inst_id, uint16 *parts, uint8 *part_num)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_part_t *part_map = NULL;
    uint16 part_id = CM_INVALID_ID16;

    while (inst_part->count < inst_part->expected_num) {
        part_id = parts[--(*part_num)];
        CM_ASSERT(part_id < DRC_MAX_PART_NUM);
        part_map = &remaster_info->part_map[part_id];
        part_map->inst_id = inst_id;
        part_map->next = inst_part->first;
        if (inst_part->count == 0) {
            inst_part->last = part_id;
        }
        inst_part->first = part_id;
        inst_part->count++;
    }
}

void dms_reform_part_assign(uint16 *parts, uint8 part_num)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_inst_part_t *inst_part = NULL;

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        inst_part = &remaster_info->inst_part_tbl[i];
        dms_reform_part_assign_inner(inst_part, i, parts, &part_num);
    }
    CM_ASSERT(part_num == 0);
}

void dms_reform_judgement_remaster(instance_list_t *inst_lists)
{
    uint16 parts[DRC_MAX_PART_NUM];
    uint8 part_num = 0;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_REMASTER);
    dms_reform_part_copy();
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NEW_JOIN)) {
        return;
    }
    dms_reform_part_recalc(inst_lists);
    dms_reform_part_collect(parts, &part_num);
    dms_reform_part_assign(parts, part_num);
}

void dms_reform_judgement_repair(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_REPAIR);
}

void dms_reform_judgement_switch_lock(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCH_LOCK);
}

void dms_reform_judgement_switchover_demote(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_DEMOTE);
    share_info->demote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_switchover_promote_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS);
}

void dms_reform_judgement_failover_promote_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS);
}

void dms_reform_migrate_task_inner(uint8 part_id, drc_part_t *part_now, drc_part_t *part_remaster,
    uint64 bitmap_online)
{
    migrate_info_t *migrate_info = DMS_MIGRATE_INFO;
    migrate_task_t migrate_task = { 0 };

    if (part_now->inst_id == part_remaster->inst_id) {
        return;
    }

    migrate_task.export_inst = part_now->inst_id;
    migrate_task.import_inst = part_remaster->inst_id;
    migrate_task.part_id = part_id;

    migrate_info->migrate_task[migrate_info->migrate_task_num++] = migrate_task;
}

void dms_reform_migrate_task(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    migrate_info_t *migrate_info = DMS_MIGRATE_INFO;
    uint64 bitmap_online = 0;
    drc_part_t *part_now = NULL;
    drc_part_t *part_remaster = NULL;

    migrate_info->migrate_task_num = 0;
    dms_reform_list_to_bitmap(&bitmap_online, &share_info->list_online);
    for (uint8 i = 0; i < DRC_MAX_PART_NUM; i++) {
        part_now = &part_mngr->part_map[i];
        part_remaster = &remaster_info->part_map[i];
        dms_reform_migrate_task_inner(i, part_now, part_remaster, bitmap_online);
    }
}

void dms_reform_judgement_migrate(instance_list_t *inst_lists)
{
    migrate_info_t *migrate_info = DMS_MIGRATE_INFO;
    dms_reform_migrate_task();
    if (migrate_info->migrate_task_num != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_MIGRATE);
    }
}

// Notice1: DRC_CLEAN and REBUILD must be used in pairs
// Notice2: REBUILD must be used before REMASTER
void dms_reform_judgement_rebuild(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->full_clean) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REBUILD);
        return;
    }

#ifdef OPENGAUSS
    // 1) primary restart 2) failover need rebuild phase
    dms_reform_list_init(&share_info->list_rebuild);
    uint32 primary_id;
    g_dms.callback.get_db_primary_id(g_dms.reform_ctx.handle_judge, &primary_id);
    if ((dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS) &&
        dms_reform_list_exist(&inst_lists[INST_LIST_OLD_JOIN], (uint8)primary_id))
        || dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
            dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_JOIN]);
            dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_REMOVE]);
            dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
            dms_reform_add_step(DMS_REFORM_STEP_REBUILD);
    }
#else
    dms_reform_list_init(&share_info->list_rebuild);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REBUILD);
    }
#endif
}

void dms_reform_judgement_recovery_analyse(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_recovery);
    dms_reform_list_add_all(&share_info->list_recovery);
    // if instance is IN, ignore redo log, because all dirty pages in data_buffer
    dms_reform_list_minus(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_IN]);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_ANALYSE);
}

void dms_reform_judgement_set_curr_point(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SET_CURRENT_POINT);
}

void dms_reform_judgement_recovery(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_recovery);
    dms_reform_list_add_all(&share_info->list_recovery);
    // if instance is IN, ignore redo log, because all dirty pages in data_buffer
    if (!dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE) &&
        !dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN) &&
        !dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_STANDBY)) {
        dms_reform_list_minus(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_IN]);
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_RCY_CLEAN);
    dms_reform_add_step(DMS_REFORM_STEP_CTL_RCY_CLEAN);
}

// Notice: must be used before DRC_ACCESS
void dms_reform_judgement_dw_recovery(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
        share_info->dw_recovery_info.bitmap_old_join = 0L;
        share_info->dw_recovery_info.bitmap_old_remove = 0L;
        share_info->dw_recovery_info.bitmap_new_join = 0L;
        dms_reform_list_to_bitmap(&share_info->dw_recovery_info.bitmap_old_join, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_to_bitmap(&share_info->dw_recovery_info.bitmap_old_remove, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_list_to_bitmap(&share_info->dw_recovery_info.bitmap_new_join, &inst_lists[INST_LIST_NEW_JOIN]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DW_RECOVERY);
    }
}

void dms_reform_judgement_df_recovery()
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DF_RECOVERY);
}

void dms_reform_judgement_space_reload()
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SPACE_RELOAD);
}

void dms_reform_judgement_recovery_opengauss(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    dms_reform_list_init(&share_info->list_recovery);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0 ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
        dms_reform_list_cancat(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_recovery, &inst_lists[INST_LIST_NEW_JOIN]);
        dms_reform_list_to_bitmap(&share_info->bitmap_recovery, &share_info->list_recovery);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_OPENGAUSS);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DRC_RCY_CLEAN);
        dms_reform_add_step(DMS_REFORM_STEP_CTL_RCY_CLEAN);
    }
}

void dms_reform_judgement_rollback_prepare(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    for (uint8 inst_id = 0; inst_id < DMS_MAX_INSTANCES; inst_id++) {
        remaster_info->deposit_map[inst_id] = ctx->deposit_map[inst_id];
    }
    dms_reform_list_init(&share_info->list_rollback);

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN)) {
        for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
            remaster_info->deposit_map[inst_id] = share_info->reformer_id;
            if (inst_id != g_dms.inst_id) {
                dms_reform_list_add(&share_info->list_rollback, inst_id);
            }
        }

        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK_PREPARE);
        return;
    }

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_STANDBY)) {
        dms_reform_judgement_rollback_for_az_standby(inst_lists);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK_PREPARE);
        return;
    }

    // just init deposit_map, no need to do txn deposit
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NEW_JOIN) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_FAILOVER)) {
        return;
    }

    // restart instances rollback by themselves
    // not only removed instances rollback by reformer, but also other has been removed instances should rollback again
    // rollback thread run after db_status=WAIT_CLEAN, and we have save stable list before
    // if rollback has not run and crash, instance restart and txn info in removed instances is lost
    for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
        // if instance is online, skip
        if (dms_reform_list_exist(&share_info->list_online, inst_id)) {
            continue;
        }

        // if instance is offline but deposit instance is old IN, skip
        uint8 deposit_id = drc_get_deposit_id(inst_id);
        if (dms_reform_list_exist(&inst_lists[INST_LIST_OLD_IN], deposit_id)) {
            continue;
        }

        // instance is offline and deposit instance is not IN, should be deposited by reformer
        dms_reform_list_add(&share_info->list_rollback, inst_id);
        remaster_info->deposit_map[inst_id] = share_info->reformer_id;
    }

    if (share_info->list_rollback.inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK_PREPARE);
    }
}

void dms_reform_judgement_reload_txn(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    dms_reform_list_init(&share_info->list_rollback);
    for (uint8 inst_id = 0; inst_id < DMS_MAX_INSTANCES; inst_id++) {
        remaster_info->deposit_map[inst_id] = ctx->deposit_map[inst_id];
    }

    for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
        if (inst_id == g_dms.inst_id) {
            dms_reform_list_add(&share_info->list_rollback, inst_id);
        }

        if (dms_reform_list_exist(&share_info->list_online, inst_id)) {
            continue;
        }

        dms_reform_list_add(&share_info->list_rollback, inst_id);
    }

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RELOAD_TXN);
}

void dms_reform_judgement_rollback_start(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->list_rollback.inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK_START);
    }
}


void dms_reform_judgement_ddl_2phase_rcy()
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (reform_info->has_ddl_2phase) {
        dms_reform_add_step(DMS_REFORM_STEP_DDL_2PHASE_RCY);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DRC_LOCK_ALL_ACCESS);
    }
}

void dms_reform_judgement_txn_deposit(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;

    dms_reform_list_init(&share_info->list_withdraw);
    if (!dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE) &&
        !dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN) &&
        !dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_STANDBY)) {
        // instance is online should withdraw txn
        for (uint8 i = 0; i < share_info->list_online.inst_id_count; i++) {
            uint8 inst_id = share_info->list_online.inst_id_list[i];
            uint8 deposit_id = drc_get_deposit_id(inst_id);
            if (deposit_id != inst_id) {
                dms_reform_list_add(&share_info->list_withdraw, inst_id);
                remaster_info->deposit_map[inst_id] = inst_id;
            }
        }
    }

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_TXN_DEPOSIT);
}

// Notice1: LOCK_ACCESS must be used after
// Notice2: PAGE_ACCESS must be used after
void dms_reform_judgement_drc_inaccess(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_INACCESS);
}

// Notice: DRC_INACCESS must be used before
void dms_reform_judgement_page_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_PAGE_ACCESS);
}

// Notice: DRC_INACCESS must be used before
void dms_reform_judgement_drc_access(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);

    if (reform_info->has_ddl_2phase) {
        dms_reform_add_step(DMS_REFORM_STEP_DDL_2PHASE_DRC_ACCESS);
    } else {
        dms_reform_add_step(DMS_REFORM_STEP_DRC_ACCESS);
    }
}

/* sync between lock-push, to prevent internode gcv diff followed by upper level endless loop */
void dms_reform_judgement_lock_instance(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_LOCK_INSTANCE);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_PUSH_GCV_AND_UNLOCK);
}

void dms_reform_judgement_reset_user(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RESET_USER);
}

void dms_reform_judgement_set_remove_point(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_to_bitmap(&share_info->bitmap_remove, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_SET_REMOVE_POINT);
    }
}

void dms_reform_judgement_success(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SUCCESS);
}

void dms_reform_judgement_done(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_DONE);
    dms_reform_add_step(DMS_REFORM_STEP_DONE_CHECK);
}

void dms_refrom_judgement_startup_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STARTUP_OPENGAUSS);
}

void dms_reform_judgement_set_phase(reform_phase_t reform_phase)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SET_PHASE);
    dms_reform_add_step(DMS_REFORM_STEP_WAIT_DB);
    share_info->reform_phase[share_info->reform_phase_count++] = reform_phase;
}

void dms_reform_judgement_file_blocked(instance_list_t *inst_lists)
{
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_FILE_BLOCKED);
    }
}

void dms_reform_judgement_update_scn(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_UPDATE_SCN);
}

void dms_reform_judgement_wait_ckpt(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_WAIT_CKPT);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
}

void dms_reform_judgement_file_unblocked(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FILE_UNBLOCKED);
}

void dms_reform_judgement_xa_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_XA_DRC_ACCESS);
}

void dms_reform_judgement_standby_sync(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_UPDATE_REMOVE_NODE_CTRL);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_STOP_THREAD);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_RELOAD_NODE_CTRL);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_SET_ONLINE_LIST);
}

void dms_reform_judgement_stop_server(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STOP_SERVER);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
}

void dms_reform_judgement_resume_server(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_RESUME_SERVER_FOR_REFORMER);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RESUME_SERVER_FOR_PARTNER);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
}

void dms_reform_judgement_start_lrpl(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_START_LRPL);
}

void dms_reform_judgement_stop_lrpl(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STOP_LRPL);
}

void dms_reform_judgement_rollback_for_az_standby(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;

    // in standby az, reformer is other instance's deposit instance.
    // reformer is old IN, reformer should deposit other instance which not by deposited by reformer including itself.
    // reformer is not old IN, reformer should rollback other instance except itself.
    if (dms_reform_list_exist(&inst_lists[INST_LIST_OLD_IN], share_info->reformer_id)) {
        for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
            if (remaster_info->deposit_map[inst_id] == share_info->reformer_id) {
                continue;
            }
            remaster_info->deposit_map[inst_id] = share_info->reformer_id;
            dms_reform_list_add(&share_info->list_rollback, inst_id);
        }
    } else {
        for (uint8 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
            remaster_info->deposit_map[inst_id] = share_info->reformer_id;
            if (inst_id != g_dms.inst_id) {
                dms_reform_list_add(&share_info->list_rollback, inst_id);
            }
        }
    }
}

#ifdef OPENGAUSS
/* DEBUG version only, check for DRC reform correctness */
void dms_reform_judgement_drc_validate(bool8 set_inaccess)
{
#ifndef NDEBUG
    share_info_t *share_info = DMS_SHARE_INFO;
    LOG_DEBUG_INF("Add step dms_validate_drc for reform:%d, DEBUG only", share_info->reform_type);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_INACCESS);

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_VALIDATE);

    if (set_inaccess) {
        return;
    } else {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DRC_ACCESS);

        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_PAGE_ACCESS);
    }
#endif
}
#endif

void dms_reform_judgement_sync_node_lfn(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_NODE_LFN);
}