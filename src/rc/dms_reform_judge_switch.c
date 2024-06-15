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
 * dms_reform_judge_switch.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_switch.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_judge_switch.h"
#include "dms_reform.h"
#include "dms_process.h"

void dms_reform_judgement_az_demote_phase1(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE1);
    share_info->demote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_demote_approve(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_APPROVE);
    share_info->demote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_demote_phase2(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE2);
    share_info->demote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_promote_phase1(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE1);
    share_info->promote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_promote_phase2(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE2);
    share_info->promote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_failover_promote_phase1(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE1);
    share_info->promote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_failover_promote_resetlog(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_RESETLOG);
    share_info->promote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_failover_promote_phase2(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE2);
    share_info->promote_id = (uint8)g_dms.inst_id;
}

void dms_reform_judgement_az_switchover_info_reset(void)
{
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;

    cm_spin_lock(&switchover_info->lock, NULL);
    switchover_info->switch_start = CM_FALSE;
    switchover_info->inst_id = CM_INVALID_ID8;
    switchover_info->sess_id = CM_INVALID_ID16;
    switchover_info->switch_req = CM_FALSE;
    switchover_info->switch_type = AZ_IDLE;
    cm_spin_unlock(&switchover_info->lock);
}

bool32 dms_reform_judgement_az_switchover_check(instance_list_t *inst_lists)
{
#ifdef OPENGAUSS
    return CM_FALSE;
#endif

    share_info_t *share_info = DMS_SHARE_INFO;
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;

    // if there are restart/remove/new add instances, ignore switchover request at current judgement
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_judgement_az_switchover_info_reset();
        g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, ERRNO_DMS_REFORM_FAIL);
        return CM_FALSE;
    }

    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    // if the standby node(which has request switchover) is not exist in bitmap_online. clear this request
    if (!bitmap64_exist(&share_info->bitmap_online, switchover_info->inst_id)) {
        switchover_info->switch_req = CM_FALSE;
        switchover_info->inst_id = CM_INVALID_ID8;
        switchover_info->sess_id = CM_INVALID_ID16;
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    if (switchover_info->switch_type != AZ_SWITCHOVER) {
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    unsigned int db_role;
    g_dms.callback.get_db_role(g_dms.reform_ctx.handle_judge, &db_role);

    share_info->reform_type = db_role != (unsigned int)DMS_DB_ROLE_PRIMARY ?
        DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE : DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE;
    share_info->promote_id = switchover_info->inst_id;
    share_info->switch_version.inst_id = switchover_info->inst_id;
    share_info->switch_version.start_time = switchover_info->start_time;
    cm_spin_unlock(&switchover_info->lock);
    return CM_TRUE;
}

bool32 dms_reform_judgement_az_failover_check(instance_list_t *inst_lists)
{
#ifdef OPENGAUSS
    return CM_FALSE;
#endif

    share_info_t *share_info = DMS_SHARE_INFO;
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;

    // if there are restart/remove/new add instances, ignore switchover request at current judgement
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_judgement_az_switchover_info_reset();
        g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, ERRNO_DMS_REFORM_FAIL);
        return CM_FALSE;
    }

    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    // if the standby node(which has request switchover) is not exist in bitmap_online. clear this request
    if (!bitmap64_exist(&share_info->bitmap_online, switchover_info->inst_id)) {
        switchover_info->switch_req = CM_FALSE;
        switchover_info->inst_id = CM_INVALID_ID8;
        switchover_info->sess_id = CM_INVALID_ID16;
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    if (switchover_info->switch_type != AZ_FAILOVER) {
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    share_info->reform_type = DMS_REFORM_TYPE_FOR_AZ_FAILOVER;
    share_info->promote_id = switchover_info->inst_id;
    share_info->switch_version.inst_id = switchover_info->inst_id;
    share_info->switch_version.start_time = switchover_info->start_time;
    cm_spin_unlock(&switchover_info->lock);
    return CM_TRUE;
}

#ifdef OPENGAUSS
bool32 dms_reform_judgement_switchover_opengauss_check(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    health_info_t *health_info = DMS_HEALTH_INFO;

    // if there are restart/remove/new add instances, ignore switchover request at current judgement
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0 ||
        inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        return CM_FALSE;
    }

    cm_spin_lock(&switchover_info->lock, NULL);
    if (!switchover_info->switch_req) {
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    // if the standby node(which has request switchover) is not exist in bitmap_online. clear this request
    // if the standby node restart, also clear
    if (!bitmap64_exist(&share_info->bitmap_online, switchover_info->inst_id) ||
        (health_info->online_times[switchover_info->inst_id] != switchover_info->start_time)) {
        switchover_info->switch_req = CM_FALSE;
        switchover_info->inst_id = CM_INVALID_ID8;
        switchover_info->sess_id = CM_INVALID_ID16;
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    share_info->reform_type = DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS;
    share_info->promote_id = switchover_info->inst_id;
    share_info->switch_version.inst_id = switchover_info->inst_id;
    share_info->switch_version.start_time = switchover_info->start_time;
    cm_spin_unlock(&switchover_info->lock);
    return CM_TRUE;
}

bool32 dms_reform_judgement_failover_opengauss_check(instance_list_t *inst_lists)
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
    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->promote_id = (uint8)g_dms.inst_id;
    return CM_TRUE;
}
#endif