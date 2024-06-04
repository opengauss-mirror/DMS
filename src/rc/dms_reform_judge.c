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
 * dms_reform_judge.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_judge.h"
#include "dms_reform_msg.h"
#include "dms_error.h"
#include "dms_msg_protocol.h"
#include "cm_timer.h"
#include "dms_reform_judge_stat.h"
#include "dms_reform_judge_switch.h"

extern dms_reform_proc_t g_dms_reform_procs[DMS_REFORM_STEP_COUNT];

#ifndef OPENGAUSS
static void dms_reform_list_remove(instance_list_t *list, int index)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(index < list->inst_id_count);

    list->inst_id_count--;
    for (int i = index; i < list->inst_id_count; i++) {
        list->inst_id_list[i] = list->inst_id_list[i + 1];
    }
}
#endif

static void dms_reform_list_init(instance_list_t *list)
{
    list->inst_id_count = 0;
}

static void dms_reform_list_add(instance_list_t *list_dst, uint8 inst_id)
{
    CM_ASSERT(list_dst != NULL);
    list_dst->inst_id_list[list_dst->inst_id_count++] = inst_id;
}

static void dms_reform_list_add_all(instance_list_t *list_dst)
{
    CM_ASSERT(list_dst != NULL);
    for (uint8 i = 0; i < g_dms.inst_cnt; i++) {
        list_dst->inst_id_list[list_dst->inst_id_count++] = i;
    }
}

static void dms_reform_list_cancat(instance_list_t *list_dst, instance_list_t *list_src)
{
    CM_ASSERT(list_dst != NULL);
    CM_ASSERT(list_src != NULL);

    for (uint8 i = 0; i < list_src->inst_id_count; i++) {
        list_dst->inst_id_list[list_dst->inst_id_count++] = list_src->inst_id_list[i];
    }
}

static void dms_reform_list_minus(instance_list_t *list_dst, instance_list_t *list_src)
{
    CM_ASSERT(list_dst != NULL);
    CM_ASSERT(list_src != NULL);

    instance_list_t list_result;
    dms_reform_list_init(&list_result);
    for (uint8 i = 0; i < list_dst->inst_id_count; i++) {
        if (!dms_reform_list_exist(list_src, list_dst->inst_id_list[i])) {
            dms_reform_list_add(&list_result, list_dst->inst_id_list[i]);
        }
    }
    *list_dst = list_result;
}

// get online offline unknown list from CMS
int dms_reform_get_list_from_cm(instance_list_t *list_online, instance_list_t *list_offline, uint64 *online_version)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    instance_list_t list_unknown;
    int ret = DMS_SUCCESS;

    dms_reform_list_init(list_online);
    dms_reform_list_init(list_offline);
    dms_reform_list_init(&list_unknown);

    if(reform_info->rst_recover) {
        dms_reform_list_add(list_online, (uint8)g_dms.inst_id);
        return DMS_SUCCESS;
    }

    if (!reform_info->build_complete) {
        dms_reform_list_add(list_online, DMS_REFORMER_ID_FOR_BUILD);
        return DMS_SUCCESS;
    }

    if (reform_info->maintain) {
        dms_reform_list_add(list_online, (uint8)g_dms.inst_id);
        return DMS_SUCCESS;
    }

    ret = dms_reform_cm_res_get_inst_stat(list_online, list_offline, &list_unknown, online_version);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    // if there is unknown instance, finish current judgement
    if (list_unknown.inst_id_count != 0) {
        LOG_DEBUG_WAR("[DMS REFORM]dms_reform_get_list_online, unknown inst count: %d", list_unknown.inst_id_count);
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "there is unknown instance");
        return ERRNO_DMS_REFORM_FAIL;
    }

    if (!dms_reform_list_exist(list_online, (uint8)g_dms.inst_id)) {
        LOG_DEBUG_WAR("[DMS REFORM]dms_reform_get_list_online, instance(%u) not in list_online", g_dms.inst_id);
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "current instance is not in online list");
        return ERRNO_DMS_REFORM_FAIL;
    }

    return DMS_SUCCESS;
}

void dms_reform_update_reformer_version(uint64 start_time, uint8 inst_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    cm_spin_lock(&reform_info->version_lock, NULL);
    reform_info->reformer_version.start_time = start_time;
    reform_info->reformer_version.inst_id = inst_id;
    cm_spin_unlock(&reform_info->version_lock);
}

static int dms_reform_get_online_status_l(uint8 *online_status, uint64 *online_times,
    uint8 *online_rw_status, uint8 dst_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 status = (uint8)g_dms.callback.get_dms_status(g_dms.reform_ctx.handle_judge);
    CM_ASSERT(status <= DMS_STATUS_IN);
    online_status[dst_id] = status;
    online_times[dst_id] = reform_info->start_time;
#ifdef OPENGAUSS
    online_rw_status[dst_id] = 1;
#else
    online_rw_status[dst_id] = (uint8)g_dms.callback.check_db_readwrite(g_dms.reform_ctx.handle_judge);
#endif
    dms_reform_update_reformer_version(reform_info->start_time, dst_id);
    return DMS_SUCCESS;
}

// don't retry while wait overtime, finish current judgement and get online list again
static int dms_reform_get_online_status_r(uint8 *online_status, uint64 *online_times, uint8 *online_rw_status,
    uint8 dst_id, uint32 sess_id)
{
    dms_reform_req_partner_status_t req;

    dms_reform_init_req_dms_status(&req, dst_id, sess_id);
    int ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_get_online_status_r SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_dms_status_wait(online_status, online_times, online_rw_status, dst_id, req.head.ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_get_online_status_r WAIT error: %d, dst_id: %d", ret, dst_id);
    }

    return ret;
}

static void dms_update_rw_bitmap(uint64 *rw_bitmap, uint8 *online_rw_status, instance_list_t *list_online)
{
    dms_reform_list_to_bitmap(rw_bitmap, list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (!bitmap64_exist(rw_bitmap, i)) {
            continue;
        }
        if (!online_rw_status[i]) {
            bitmap64_clear(rw_bitmap, i);
        }
    }
}

void dms_set_driver_ping_info(uint64 online_version, uint8 *online_rw_status, instance_list_t *list_online)
{
    uint64 rw_bitmap = 0ULL;
    dms_update_rw_bitmap(&rw_bitmap, online_rw_status, list_online);
    cm_spin_lock(&g_dms.dms_driver_ping_info.lock, NULL);
    g_dms.dms_driver_ping_info.driver_ping_info.rw_bitmap = rw_bitmap;
    g_dms.dms_driver_ping_info.driver_ping_info.major_version = online_version;
    g_dms.dms_driver_ping_info.driver_ping_info.minor_version = (uint64)g_timer()->now;
    cm_spin_unlock(&g_dms.dms_driver_ping_info.lock);
}

// 1. req to online list and get status
int dms_reform_get_online_status(instance_list_t *list_online, uint8 *online_status, uint64* online_times,
    uint8 *online_rw_status, uint32 sess_id)
{
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            ret = dms_reform_get_online_status_l(online_status, online_times, online_rw_status, dst_id);
        } else {
            ret = dms_reform_get_online_status_r(online_status, online_times, online_rw_status, dst_id, sess_id);
        }
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    return DMS_SUCCESS;
}

static void dms_reform_modify_list(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

#ifdef OPENGAUSS
    if (!DMS_FIRST_REFORM_FINISH && share_info->list_stable.inst_id_count == 0) {
        dms_reform_list_init(&share_info->list_online);
        dms_reform_list_init(&share_info->list_offline);
        dms_reform_list_add(&share_info->list_online, (uint8)g_dms.inst_id);
    }
#else
    // in CENTRALIZED, if node is offline and not stable, just ignore the node make cluster usable in time
    // if the node is online later, reform is lightweight, recovery&migrate is not included
    instance_list_t *list_offline = &share_info->list_offline;
    uint64 bitmap_stable = share_info->bitmap_stable;

    if (g_dms.reform_ctx.catalog_centralized) {
        int index = 0;
        while (index < list_offline->inst_id_count) {
            uint8 inst_id = list_offline->inst_id_list[index];
            if (!bitmap64_exist(&bitmap_stable, inst_id)) {
                dms_reform_list_remove(list_offline, index);
                continue;
            }
            index++;
        }
    }
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (reform_info->rst_recover) {
        // To update the rcy point and lrp point of other nodes
        for (uint32 inst_id = 0; inst_id < g_dms.inst_cnt; inst_id++) {
            if (inst_id != g_dms.inst_id) {
                dms_reform_list_add(&share_info->list_stable, (uint8)inst_id);
            }
        }
        dms_reform_list_to_bitmap(&share_info->bitmap_stable, &share_info->list_stable);
    }
#endif
}

void dms_reform_bitmap_to_list(instance_list_t *list, uint64 bitmap)
{
    dms_reform_list_init(list);

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&bitmap, i)) {
            dms_reform_list_add(list, i);
        }
    }
}

#ifndef OPENGAUSS
static int dms_reform_connect(instance_list_t *list_online)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    instance_list_t list_reconnect;
    uint64 bitmap_online = 0;
    int ret = DMS_SUCCESS;

    dms_reform_list_to_bitmap(&bitmap_online, list_online);
    bitmap64_minus(&bitmap_online, reform_info->bitmap_mes);
    dms_reform_bitmap_to_list(&list_reconnect, bitmap_online);

    cm_spin_lock(&reform_info->mes_lock, NULL);
    ret = mfc_add_instance_batch(list_reconnect.inst_id_list, list_reconnect.inst_id_count, CM_FALSE);
    if (ret != DMS_SUCCESS) {
        cm_spin_unlock(&reform_info->mes_lock);
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    bitmap64_union(&reform_info->bitmap_mes, bitmap_online);
    cm_spin_unlock(&reform_info->mes_lock);

    return DMS_SUCCESS;
}
#endif

static int dms_reform_get_list_stable(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint64 bitmap_stable = 0;
    uint8 reformer_id = 0;
    int ret = DMS_SUCCESS;

    ret = g_dms.callback.get_list_stable(g_dms.reform_ctx.handle_judge, &bitmap_stable, &reformer_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    share_info->bitmap_stable = bitmap_stable;
    share_info->last_reformer = reformer_id;
    dms_reform_bitmap_to_list(&share_info->list_stable, bitmap_stable);
    return DMS_SUCCESS;
}

static void dms_reform_inst_list_add(instance_list_t *inst_lists, uint8 list_index, uint8 inst_id)
{
    instance_list_t *inst_list = &inst_lists[list_index];
    inst_list->inst_id_list[inst_list->inst_id_count++] = inst_id;
}

static int dms_reform_check_remote_inner(uint8 dst_id)
{
    dms_reform_req_prepare_t req;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    bool8 last_fail = CM_FALSE;
    int in_reform = CM_FALSE;
    bool8 has_ddl_2phase = CM_FALSE;

    dms_reform_init_req_prepare(&req, dst_id);
    
    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_remote_inner SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_prepare_wait(&last_fail, &in_reform, &has_ddl_2phase, req.head.ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_remote_inner WAIT error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    if (in_reform) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_remote_inner in reform, dst_id: %d", dst_id);
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    if (last_fail) {
        share_info->full_clean = CM_TRUE;
    }

    if (has_ddl_2phase) {
        reform_info->has_ddl_2phase = CM_TRUE;
    }

    return DMS_SUCCESS;
}

static int dms_reform_check_remote(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    if (reform_info->last_fail) {
        share_info->full_clean = CM_TRUE;
    }

#ifndef OPENGAUSS
    reform_info->has_ddl_2phase = (bool8)g_dms.callback.reform_is_need_ddl_2phase_rcy(g_dms.reform_ctx.handle_proc);
#endif

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            continue;
        }
        ret = dms_reform_check_remote_inner(dst_id);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        reformer_ctrl->instance_fail[i] = 0;
        reformer_ctrl->instance_step[i] = 0;
    }

    LOG_DEBUG_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_sync_cluster_version_inner(uint8 dst_id, bool8 *local_updated, bool8 pushing)
{
    dms_reform_req_gcv_sync_t req;
    int ret = DMS_SUCCESS;

    dms_reform_init_req_gcv_sync(&req, dst_id, pushing);
    
    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM][GCV SYNC]dms_reform_sync_cluster_version_inner "
            "SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_gcv_sync_wait(local_updated, pushing, req.head.ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM][GCV SYNC]dms_reform_sync_cluster_version_inner "
            "WAIT error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    return DMS_SUCCESS;
}

/*
 * calc and sync appropriate cluster version before any reform msg passed around
 */
int dms_reform_sync_cluster_version(bool8 pushing)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;
    bool8 local_updated = CM_FALSE; /* whether reformer had to update */

    LOG_DEBUG_INF("[DMS REFORM][GCV %s]dms_reform_sync_cluster_version 1st round",
        pushing ? "PUSH" : "SYNC");
    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            continue;
        }
        ret = dms_reform_sync_cluster_version_inner(dst_id, &local_updated, pushing);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }
    cm_panic_log(!(pushing && local_updated), "[DMS REFORM][GCV SYNC]fatal: reformer gcv < partner:%u",
        DMS_GLOBAL_CLUSTER_VER);

    /* sync again when some partner has the biggest GCV that reformer has just learnt */
    while (local_updated && !pushing) {
        local_updated = CM_FALSE;
        LOG_DEBUG_INF("[DMS REFORM][GCV SYNC]dms_reform_sync_cluster_version 2nd round");
        for (uint8 i = 0; i < list_online->inst_id_count; i++) {
            dst_id = list_online->inst_id_list[i];
            if (dms_dst_id_is_self(dst_id)) {
                continue;
            }
            ret = dms_reform_sync_cluster_version_inner(dst_id, &local_updated, pushing);
            if (ret != DMS_SUCCESS) {
                return ret;
            }
        }
        if (local_updated) {
            LOG_DEBUG_ERR("[DMS REFORM][GCV SYNC]fatal: reformer local updated again, GCV:%u",
                DMS_GLOBAL_CLUSTER_VER);
        }
    }

    LOG_DEBUG_INF("[DMS REFORM][GCV %s]dms_reform_sync_cluster_version success, gcv=%u",
        pushing ? "PUSH" : "SYNC", DMS_GLOBAL_CLUSTER_VER);

    LOG_DEBUG_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static void dms_reform_judgement_prepare(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->reform_step_count = 0;
    share_info->reform_phase_count = 0;
    share_info->judge_time = g_timer()->now;
    dms_reform_add_step(DMS_REFORM_STEP_PREPARE);
}

static void dms_reform_judgement_start(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_START);
}

static void dms_reform_judgement_disconnect(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_disconnect);
    if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_disconnect, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_list_to_bitmap(&share_info->bitmap_disconnect, &share_info->list_disconnect);
        dms_reform_add_step(DMS_REFORM_STEP_DISCONNECT);
    }
}

static void dms_reform_judgement_reconnect(instance_list_t *inst_lists)
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
static void dms_reform_judgement_drc_clean(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->full_clean) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_FULL_CLEAN);
        return;
    }

    // if reform_type is fail-over, all DRC has lost, no need to do drc_clean
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
        return;
    }

    dms_reform_list_init(&share_info->list_clean);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_clean, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_clean, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_list_to_bitmap(&share_info->bitmap_clean, &share_info->list_clean);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DRC_CLEAN);
    }
}

static void dms_reform_part_copy(void)
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

static void dms_reform_part_recalc_for_distribute(instance_list_t *inst_lists)
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

static void dms_reform_part_recalc_for_centralized(instance_list_t *inst_lists)
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

static void dms_reform_part_recalc(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    if (share_info->catalog_centralized) {
        dms_reform_part_recalc_for_centralized(inst_lists);
    } else {
        dms_reform_part_recalc_for_distribute(inst_lists);
    }
}

static void dms_reform_part_collect_inner(drc_inst_part_t *inst_part, uint16 *parts, uint8 *part_num)
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

static void dms_reform_part_collect(uint16 *parts, uint8 *part_num)
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

static void dms_reform_part_assign_inner(drc_inst_part_t *inst_part, uint8 inst_id, uint16 *parts, uint8 *part_num)
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

static void dms_reform_part_assign(uint16 *parts, uint8 part_num)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_inst_part_t *inst_part = NULL;

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        inst_part = &remaster_info->inst_part_tbl[i];
        dms_reform_part_assign_inner(inst_part, i, parts, &part_num);
    }
    CM_ASSERT(part_num == 0);
}

static void dms_reform_judgement_remaster(instance_list_t *inst_lists)
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

static void dms_reform_judgement_switch_lock(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCH_LOCK);
}

static void dms_reform_judgement_switchover_demote(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_DEMOTE);
    share_info->demote_id = (uint8)g_dms.inst_id;
}

static void dms_reform_judgement_switchover_promote(void)
{
#ifndef OPENGAUSS
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        return;
    }
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_PROMOTE);
#endif
}

static void dms_reform_judgement_switchover_promote_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS);
}

static void dms_reform_judgement_failover_promote_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS);
}

static void dms_reform_migrate_task_inner(uint8 part_id, drc_part_t *part_now, drc_part_t *part_remaster,
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

static void dms_reform_migrate_task(void)
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

static void dms_reform_judgement_migrate(instance_list_t *inst_lists)
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
static void dms_reform_judgement_rebuild(instance_list_t *inst_lists)
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

// Notice: REPAIR and FLUSH_COPY must be used in pairs
static void dms_reform_judgement_repair(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->full_clean) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REPAIR);
        return;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REPAIR);
    }
}

// Notice: REPAIR and FLUSH_COPY must be used in pairs
static void dms_reform_judgement_flush_copy(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FLUSH_COPY);
}

static void dms_reform_judgement_recovery_analyse(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_recovery);
    dms_reform_list_add_all(&share_info->list_recovery);
    // if instance is IN, ignore redo log, because all dirty pages in data_buffer
    dms_reform_list_minus(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_IN]);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_ANALYSE);
}

static void dms_reform_judgement_set_curr_point(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SET_CURRENT_POINT);
}

static void dms_reform_judgement_recovery(instance_list_t *inst_lists)
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
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_VALIDATE_LSN);
    }
    dms_reform_add_step(DMS_REFORM_STEP_DRC_RCY_CLEAN);
    dms_reform_add_step(DMS_REFORM_STEP_CTL_RCY_CLEAN);
}

// Notice: must be used before DRC_ACCESS
static void dms_reform_judgement_dw_recovery(instance_list_t *inst_lists)
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

static void dms_reform_judgement_df_recovery()
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DF_RECOVERY);
}

static void dms_reform_judgement_space_reload()
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SPACE_RELOAD);
}

static void dms_reform_judgement_recovery_opengauss(instance_list_t *inst_lists)
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
    }
}

static void dms_reform_judgement_rollback_for_az_standby(instance_list_t *inst_lists)
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

static void dms_reform_judgement_rollback_prepare(instance_list_t *inst_lists)
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

static void dms_reform_judgement_reload_txn(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RELOAD_TXN);
}

static void dms_reform_judgement_rollback_start(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->list_rollback.inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK_START);
    }
}


static void dms_reform_judgement_ddl_2phase_rcy()
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (reform_info->has_ddl_2phase) {
        dms_reform_add_step(DMS_REFORM_STEP_DDL_2PHASE_RCY);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_DRC_LOCK_ALL_ACCESS);
    }
}

static void dms_reform_judgement_txn_deposit(instance_list_t *inst_lists)
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
static void dms_reform_judgement_drc_inaccess(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_INACCESS);
}

// Notice: DRC_INACCESS must be used before
static void dms_reform_judgement_page_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_PAGE_ACCESS);
}

static void dms_reform_judgement_reset_user(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RESET_USER);
}

// Notice: DRC_INACCESS must be used before
static void dms_reform_judgement_drc_access(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);

    if (reform_info->has_ddl_2phase) {
        dms_reform_add_step(DMS_REFORM_STEP_DDL_2PHASE_DRC_ACCESS);
    } else {
        dms_reform_add_step(DMS_REFORM_STEP_DRC_ACCESS);
    }
}

/* DEBUG version only, check for DRC reform correctness */
static void dms_reform_judgement_drc_validate(bool set_inaccess)
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

/* sync between lock-push, to prevent internode gcv diff followed by upper level endless loop */
static void dms_reform_judgement_lock_instance(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_LOCK_INSTANCE);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_PUSH_GCV_AND_UNLOCK);
}

static void dms_reform_judgement_set_remove_point(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_to_bitmap(&share_info->bitmap_remove, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_SET_REMOVE_POINT);
    }
}

static void dms_reform_judgement_success(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SUCCESS);
}

static void dms_reform_judgement_done(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_DONE);
    dms_reform_add_step(DMS_REFORM_STEP_DONE_CHECK);
}

static void dms_refrom_judgement_startup_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STARTUP_OPENGAUSS);
}

char *dms_reform_get_type_desc(uint32 reform_type)
{
    switch (reform_type) {
        case DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS:
            return "OPENGAUSS_NORMAL";

        case DMS_REFORM_TYPE_FOR_NORMAL:
            return "NORMAL";

        case DMS_REFORM_TYPE_FOR_SWITCHOVER:
            return "SWITCHOVER";
        
        case DMS_REFORM_TYPE_FOR_RST_RECOVER:
            return "FOR RESTORE RECOVER";

        case DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS:
            return "FAILOVER_OPENGAUSS";

        case DMS_REFORM_TYPE_FOR_BUILD:
            return "CREATE DATABASE";

        case DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS:
            return "SWITCHOVER FOR OPENGAUSS";

        case DMS_REFORM_TYPE_FOR_FULL_CLEAN:
            return "FULL_CLEAN";

        case DMS_REFORM_TYPE_FOR_MAINTAIN:
            return "FOR MAINTAIN";

        case DMS_REFORM_TYPE_FOR_NEW_JOIN:
            return "NEW JOIN";

        case DMS_REFORM_TYPE_FOR_OLD_REMOVE:
            return "OLD REMOVE";

        case DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY:
            return "SHUTDOWN CONSISTENCY";

        case DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN:
            return "FOR STANDBY MAINTAIN";

        case DMS_REFORM_TYPE_FOR_NORMAL_STANDBY:
            return "STANDBY NORMAL";

        case DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE:
            return "AZ SWITCHOVER DEMOTE";

	case DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE:
	     return "AZ SWITCHOVER PROMOTE";

        case DMS_REFORM_TYPE_FOR_AZ_FAILOVER:
            return "AZ FAILOVER";

        case DMS_REFORM_TYPE_COUNT:
        default:
            return "UNKNOWN TYPE";
    }
}

void dms_reform_judgement_step_log(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 step = (uint8)share_info->reform_step[0];
    char desc[DMS_INFO_DESC_LEN] = { 0 };
    errno_t err;

    err = strcat_s(desc, DMS_INFO_DESC_LEN, g_dms_reform_procs[step].desc);
    DMS_SECUREC_CHECK(err);

    for (uint8 i = 1; i < share_info->reform_step_count; i++) {
        err = strcat_s(desc, DMS_INFO_DESC_LEN, "-");
        DMS_SECUREC_CHECK(err);
        step = (uint8)share_info->reform_step[i];
        err = strcat_s(desc, DMS_INFO_DESC_LEN, g_dms_reform_procs[step].desc);
        DMS_SECUREC_CHECK(err);
    }

    char *role = DMS_IS_REFORMER ? "reformer" : "partner";
    char *catalog = share_info->catalog_centralized ? "centralized" : "distributed";
    char *reform_type = dms_reform_get_type_desc((uint32)share_info->reform_type);

    LOG_RUN_INF("[DMS REFORM]inst_id:%u, role:%s, catalog:%s, reform_type:%s, full_clean:%d, ddl_2phase:%d, step:%s",
        g_dms.inst_id, role, catalog, reform_type, share_info->full_clean, reform_info->has_ddl_2phase, desc);
}

static void dms_reform_instance_list_log(instance_list_t *inst_list, const char *list_name, char *desc)
{
    char temp_desc[DMS_TEMP_DESC_LEN] = { 0 };
    uint64 bitmap = 0;
    errno_t err;

    dms_reform_list_to_bitmap(&bitmap, inst_list);
    err = sprintf_s(temp_desc, DMS_TEMP_DESC_LEN, "[DMS REFORM]list_name: %-30s, bitmap: %llu\n", list_name, bitmap);
    DMS_SECUREC_CHECK_SS(err);
    err = strcat_s(desc, DMS_INFO_DESC_LEN, temp_desc);
    DMS_SECUREC_CHECK(err);
}

static void dms_reform_instance_lists_log(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    char desc[DMS_INFO_DESC_LEN] = { 0 };

    dms_reform_instance_list_log(&inst_lists[INST_LIST_OLD_OUT], "old out", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_OLD_JOIN], "old join", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_OLD_REFORM], "old reform", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_OLD_IN], "old in", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_OLD_REMOVE], "old remove", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_NEW_OUT], "new out", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_NEW_JOIN], "new join", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_NEW_REFORM], "new reform", desc);
    dms_reform_instance_list_log(&inst_lists[INST_LIST_NEW_IN], "new in", desc);
    dms_reform_instance_list_log(&share_info->list_stable, "share list stable", desc);
    dms_reform_instance_list_log(&share_info->list_online, "share list online", desc);
    dms_reform_instance_list_log(&share_info->list_offline, "share list offline", desc);
    dms_reform_instance_list_log(&share_info->list_reconnect, "share list reconnect", desc);
    dms_reform_instance_list_log(&share_info->list_disconnect, "share list disconnect", desc);
    dms_reform_instance_list_log(&share_info->list_clean, "share list clean", desc);
    dms_reform_instance_list_log(&share_info->list_rebuild, "share list rebuild", desc);
    dms_reform_instance_list_log(&share_info->list_recovery, "share list recovery", desc);
    dms_reform_instance_list_log(&share_info->list_withdraw, "share list withdraw", desc);
    dms_reform_instance_list_log(&share_info->list_rollback, "share list rollback", desc);

    LOG_RUN_INF("[DMS REFORM]instance lists info:\n%s", desc);
}

static void dms_reform_judgement_list_collect(instance_list_t *inst_lists, uint8 *online_status)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    bool32 in_list_online = CM_FALSE;
    bool32 in_list_stable = CM_FALSE;

    dms_reform_list_to_bitmap(&share_info->bitmap_online, &share_info->list_online);

    // collect instance status
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_online = bitmap64_exist(&share_info->bitmap_online, i);
        in_list_stable = bitmap64_exist(&share_info->bitmap_stable, i);
        if (in_list_online && in_list_stable) {
            dms_reform_inst_list_add(inst_lists, (uint8)(INST_LIST_OLD_BASE + online_status[i]), i);
        } else if (in_list_online && !in_list_stable) {
            dms_reform_inst_list_add(inst_lists, (uint8)(INST_LIST_NEW_BASE + online_status[i]), i);
        } else if (!in_list_online && in_list_stable) {
            dms_reform_inst_list_add(inst_lists, INST_LIST_OLD_REMOVE, i);
        }
    }

    // bitmap_in is not only used in the connect scenario,
    // but also used in ss_cb_save_list_stable to unblock rcy for old_join nodes and new_join nodes.
    dms_reform_list_to_bitmap(&share_info->bitmap_in, &inst_lists[INST_LIST_OLD_IN]);

    for (int i = 0; i < INST_LIST_TYPE_COUNT; i++) {
        dms_reform_list_to_bitmap(&share_info->inst_bitmap[i], &inst_lists[i]);
    }
}

static void dms_reform_judgement_set_phase(reform_phase_t reform_phase)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SET_PHASE);
    dms_reform_add_step(DMS_REFORM_STEP_WAIT_DB);
    share_info->reform_phase[share_info->reform_phase_count++] = reform_phase;
}

static void dms_reform_judgement_file_blocked(instance_list_t *inst_lists)
{
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_FILE_BLOCKED);
    }
}

static void dms_reform_judgement_update_scn(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_UPDATE_SCN);
}

static void dms_reform_judgement_wait_ckpt(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_WAIT_CKPT);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
}

static void dms_reform_judgement_file_unblocked(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_FILE_UNBLOCKED);
}

static void dms_reform_judgement_collect_xaowners(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_COLLECT_XA_OWNER);
}

static void dms_reform_judgement_merge_xaowners(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_MERGE_XA_OWNERS);
}

static void dms_reform_judgement_recovery_xa(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_XA);
}

static void dms_reform_judgement_xa_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_XA_DRC_ACCESS);
}

static void dms_reform_judgement_validate_lock_mode(instance_list_t *inst_lists)
{
    // if there is no old_join or old remove, DRC has not been traversed before. So no need to validate lock mode
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0) {
        return;
    }

    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_VALIDATE_LOCK_MODE);
}

static void dms_reform_judgement_standby_sync(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_UPDATE_REMOVE_NODE_CTRL);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_STOP_THREAD);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_RELOAD_NODE_CTRL);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_STANDBY_SET_ONLINE_LIST);
}

static void dms_reform_judgement_start_lrpl(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_START_LRPL);
}

static void dms_reform_judgement_stop_lrpl(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STOP_LRPL);
}

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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_recovery_analyse(inst_lists);
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_reset_user();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_space_reload();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_set_remove_point(inst_lists);
    dms_reform_judgement_done();
}

static void dms_reform_judgement_new_join(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_set_curr_point();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_space_reload();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_file_unblocked();
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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_recovery_analyse(inst_lists);
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_df_recovery();
    dms_reform_judgement_reset_user();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_space_reload();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_ddl_2phase_rcy();
    dms_reform_judgement_file_unblocked();
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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_flush_copy();
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
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_dw_recovery(inst_lists);
    dms_reform_judgement_reset_user();
    dms_reform_judgement_validate_lock_mode(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_standby_sync();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_DRC_ACCESS);
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_stop_lrpl();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_RECOVERY);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_space_reload();
    dms_reform_judgement_set_phase(DMS_PHASE_AFTER_TXN_DEPOSIT);
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_success();
    dms_reform_judgement_set_phase(DMS_PHASE_END);
    dms_reform_judgement_rollback_start(inst_lists);
    dms_reform_judgement_wait_ckpt();
    dms_reform_judgement_start_lrpl();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_switchover(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_switchover_demote(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_reset_user();
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_switch_lock();
    dms_reform_judgement_collect_xaowners();
    dms_reform_judgement_merge_xaowners();
    dms_reform_judgement_recovery_xa();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_switchover_promote();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_drc_validate(true); /* maintain drc inaccess as failover not finished */
    dms_reform_judgement_drc_access();
    dms_reform_judgement_failover_promote_opengauss();
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_flush_copy();
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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_drc_access();
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_recovery_opengauss(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_drc_validate(false);
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_build(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
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
    dms_reform_judgement_repair(inst_lists);
#ifndef OPENGAUSS
    dms_reform_judgement_reset_user();
#endif
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_xa_access();
    dms_reform_judgement_switchover_promote();
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
    dms_reform_judgement_file_unblocked();
    dms_reform_judgement_switchover_promote();
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
    dms_reform_judgement_file_unblocked();
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
    dms_reform_judgement_az_demote_approve(inst_lists);
    dms_reform_judgement_az_demote_phase2(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_lock_instance();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_standby_sync();
    dms_reform_judgement_page_access();
    dms_reform_judgement_recovery(inst_lists);
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    // txn_deposit must before dc_init, otherwise, dc_init may be hung due to transactions accessing the deleted node.
    dms_reform_judgement_rollback_prepare(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_file_unblocked();
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
    dms_reform_judgement_az_promote();
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    dms_reform_judgement_reload_txn();
    dms_reform_judgement_txn_deposit(inst_lists);
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
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_drc_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_az_failover_promote_phase1();
    dms_reform_judgement_az_failover_promote_resetlog();
    dms_reform_judgement_az_failover_promote_phase2();
    dms_reform_judgement_file_blocked(inst_lists);
    dms_reform_judgement_update_scn();
    dms_reform_judgement_reload_txn();
    dms_reform_judgement_txn_deposit(inst_lists);
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

#ifndef OPENGAUSS
static void dms_reform_judgement_refresh_reform_info(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    bool32 build_complete = CM_FALSE;
    g_dms.callback.check_if_build_complete(g_dms.reform_ctx.handle_judge, &build_complete);
    reform_info->build_complete = (bool8)build_complete;
    bool32 rst_recover = CM_FALSE;
    g_dms.callback.check_if_restore_recover(g_dms.reform_ctx.handle_judge, &rst_recover);
    reform_info->rst_recover = (bool8)rst_recover;
}
#endif

#ifdef OPENGAUSS
static bool32 dms_reform_list_cmp(instance_list_t *list1, instance_list_t *list2)
{
    if (list1->inst_id_count != list2->inst_id_count) {
        return CM_FALSE;
    }

    // instance id in list must be in order, so we can compare instance id one by one
    for (uint8 i = 0; i < list1->inst_id_count; i++) {
        if (list1->inst_id_list[i] != list2->inst_id_list[i]) {
            return CM_FALSE;
        }
    }

    return CM_TRUE;
}

static void dms_reform_judgement_reform_type(instance_list_t *list)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint32 primary_id;

    // treat full_clean as priority
    if (dms_reform_list_cmp(&share_info->list_online, &share_info->list_stable) &&
        dms_reform_list_cmp(&share_info->list_online, &list[INST_LIST_OLD_IN]) &&
        share_info->full_clean) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_FULL_CLEAN;
        return;
    }

    g_dms.callback.get_db_primary_id(g_dms.reform_ctx.handle_judge, &primary_id);

    // if reformer(current node) is not primary, old reformer&primary has been removed from cluster
    if (!dms_dst_id_is_self((uint8)primary_id) && primary_id != -1) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS;
        share_info->last_reformer = (uint8)primary_id;
        return;
    }

    share_info->reform_type = DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS;
}
#else
static bool8 dms_reform_judgement_reform_type_optimize(instance_list_t *list)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;

    // there is only new_join and there is old_in
    if (list[INST_LIST_OLD_IN].inst_id_count != 0 &&
        list[INST_LIST_NEW_JOIN].inst_id_count != 0 &&
        list[INST_LIST_OLD_JOIN].inst_id_count == 0 &&
        list[INST_LIST_OLD_REMOVE].inst_id_count == 0) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_NEW_JOIN;
        return CM_TRUE;
    }

    // there is only old_remove and there is old_in
    if (list[INST_LIST_OLD_IN].inst_id_count != 0 &&
        list[INST_LIST_NEW_JOIN].inst_id_count == 0 &&
        list[INST_LIST_OLD_JOIN].inst_id_count == 0 &&
        list[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        if (g_dms.callback.check_shutdown_consistency(reform_ctx->handle_judge, &list[INST_LIST_OLD_REMOVE])) {
            share_info->reform_type = DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY;
        } else {
            share_info->reform_type = DMS_REFORM_TYPE_FOR_OLD_REMOVE;
        }
        return CM_TRUE;
    }

    return CM_FALSE;
}

static void dms_reform_judgement_reform_type(instance_list_t *list)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    // database recover for restore, should before build database
    if (reform_info->rst_recover) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_RST_RECOVER;
        return;
    }

    // database has not been created
    if (!reform_info->build_complete) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_BUILD;
        return;
    }
    unsigned int db_role;
    g_dms.callback.get_db_role(g_dms.reform_ctx.handle_judge, &db_role);

    // database started for maintain
    if (reform_info->maintain) {
        if (db_role != (unsigned int)DMS_DB_ROLE_PRIMARY) {
            share_info->reform_type = DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN;
            return;
        }
        share_info->reform_type = DMS_REFORM_TYPE_FOR_MAINTAIN;
        return;
    }

    if (db_role != (unsigned int)DMS_DB_ROLE_PRIMARY) {
        az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
        if (switchover_info->switch_type == AZ_FAILOVER) {
            share_info->reform_type = DMS_REFORM_TYPE_FOR_AZ_FAILOVER;
            return;
        }
        share_info->reform_type = DMS_REFORM_TYPE_FOR_NORMAL_STANDBY;
        return;
    }

    if (dms_reform_judgement_reform_type_optimize(list)) {
        return;
    }

    // switchover & fail over are not allowed at multi_write
    share_info->reform_type = DMS_REFORM_TYPE_FOR_NORMAL;
}
#endif

static dms_reform_judgement_proc_t g_reform_judgement_proc[DMS_REFORM_TYPE_COUNT] = {
    [DMS_REFORM_TYPE_FOR_NORMAL] = {
    dms_reform_judgement_normal_check,
    dms_reform_judgement_normal },

    [DMS_REFORM_TYPE_FOR_SWITCHOVER] = {
    dms_reform_judgement_switchover_check,
    dms_reform_judgement_switchover },

    [DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS] = {
    dms_reform_judgement_normal_opengauss_check,
    dms_reform_judgement_normal_opengauss },

    [DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS] = {
    dms_reform_judgement_failover_opengauss_check,
    dms_reform_judgement_failover_opengauss },

    [DMS_REFORM_TYPE_FOR_BUILD] = {
    dms_reform_judgement_build_check,
    dms_reform_judgement_build },

    [DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS] = {
    dms_reform_judgement_switchover_opengauss_check,
    dms_reform_judgement_switchover_opengauss },

    [DMS_REFORM_TYPE_FOR_FULL_CLEAN] = {
    dms_reform_judgement_full_clean_check,
    dms_reform_judgement_full_clean },

    [DMS_REFORM_TYPE_FOR_MAINTAIN] = {
    dms_reform_judgement_maintain_check,
    dms_reform_judgement_maintain },

    [DMS_REFORM_TYPE_FOR_RST_RECOVER] = {
    dms_reform_judgement_rst_recover_check,
    dms_reform_judgement_rst_recover },

    [DMS_REFORM_TYPE_FOR_NEW_JOIN] = {
    dms_reform_judgement_new_join_check,
    dms_reform_judgement_new_join },

    [DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN] = {
    dms_reform_judgement_standby_maintain_check,
    dms_reform_judgement_standby_maintain },

    [DMS_REFORM_TYPE_FOR_NORMAL_STANDBY] = {
    dms_reform_judgement_normal_check,
    dms_reform_judgement_normal_standby },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE] = {
    dms_reform_judgement_az_switchover_check,
    dms_reform_judgement_az_switchover_demote },

    [DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE] = {
    dms_reform_judgement_az_switchover_check,
    dms_reform_judgement_az_switchover_to_promote },

    [DMS_REFORM_TYPE_FOR_AZ_FAILOVER] = {
    dms_reform_judgement_az_failover_check,
    dms_reform_judgement_az_failover },

    [DMS_REFORM_TYPE_FOR_OLD_REMOVE] = {
    dms_reform_judgement_old_remove_check,
    dms_reform_judgement_old_remove },

    [DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY] = {
    dms_reform_judgement_shutdown_consistency_check,
    dms_reform_judgement_shutdown_consistency },
};

static int dms_reform_sync_share_info_r(uint8 dst_id)
{
    dms_reform_req_sync_share_info_t req;

    int ret = dms_reform_init_req_sync_share_info(&req, dst_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_share_info_r SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_sync_share_info_wait(req.head.ruid);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_share_info_r WAIT error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    return DMS_SUCCESS;
}

static int dms_reform_sync_share_info(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            continue;
        }
        ret = dms_reform_sync_share_info_r(dst_id);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    LOG_DEBUG_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_refresh_map_info(uint8 *online_status, instance_list_t *inst_lists)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    // reformer status is IN, part info and txn deposit map is valid
    if (online_status[g_dms.inst_id] == (uint8)DMS_STATUS_IN) {
        reform_info->use_default_map = CM_FALSE;
        return DMS_SUCCESS;
    }

    // no instance is IN, use the default value
    if (inst_lists[INST_LIST_OLD_IN].inst_id_count == 0) {
        reform_info->use_default_map = CM_TRUE;
        return DMS_SUCCESS;
    }

    reform_info->use_default_map = CM_FALSE;
    // get part info and txn deposit map from instance which status is IN
    dms_message_head_t head;
    dms_reform_init_map_info_req(&head, inst_lists[INST_LIST_OLD_IN].inst_id_list[0]);
    
    int ret = mfc_send_data(&head);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return dms_reform_map_info_req_wait(head.ruid);
}

#ifdef OPENGAUSS
static void dms_reform_adjust(instance_list_t *inst_lists, uint8 *online_status)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    if (share_info->reform_type == DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS) {
        uint32 primary_id;
        g_dms.callback.get_db_primary_id(g_dms.reform_ctx.handle_judge, &primary_id);
        if (bitmap64_exist(&share_info->bitmap_online, (uint8)primary_id)) {
            uint8 inst_tmp[1] = {(uint8)primary_id};
            uint64 bitmap_tmp = bitmap64_create(inst_tmp, 1);
            bitmap64_minus(&share_info->bitmap_online, bitmap_tmp);
            dms_reform_bitmap_to_list(&share_info->list_online, share_info->bitmap_online);
            uint32 len = (uint32)(sizeof(instance_list_t) * INST_LIST_TYPE_COUNT);
            memset_s(inst_lists, len, 0, len);
            dms_reform_judgement_list_collect(inst_lists, online_status);
        }
    }
}
#endif

static void dms_reform_judgement_record_start_times(void)
{
    share_info_t* share_info = DMS_SHARE_INFO;
    health_info_t* health_info = DMS_HEALTH_INFO;

    for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
        share_info->start_times[i] = health_info->online_times[i];
    }
}

static void dms_reform_judgement_set_catalog(void)
{
    reform_context_t * reform_context = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;
#ifndef OPENGAUSS
    if (share_info->reform_type == DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN ||
        share_info->reform_type == DMS_REFORM_TYPE_FOR_NORMAL_STANDBY ||
        share_info->reform_type == DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE) {
        share_info->catalog_centralized = CM_TRUE;
    } else {
        share_info->catalog_centralized = reform_context->catalog_centralized;
    }
#else
    share_info->catalog_centralized = reform_context->catalog_centralized;
#endif
}

static void dms_reform_judgement_before_proc(instance_list_t *inst_lists)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    switch (share_info->reform_type) {
        case DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE:
        case DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE:
        case DMS_REFORM_TYPE_FOR_AZ_FAILOVER:
        case DMS_REFORM_TYPE_FOR_NEW_JOIN:
            reform_info->has_ddl_2phase = CM_FALSE;
            break;

        case DMS_REFORM_TYPE_FOR_NORMAL:
        case DMS_REFORM_TYPE_FOR_OLD_REMOVE:
            share_info->full_clean = CM_TRUE;
            break;

        case DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY:
            reform_info->has_ddl_2phase = CM_FALSE;
            share_info->full_clean = CM_TRUE;
            break;

        default:
            break;
    }
}

static bool32 dms_reform_judgement(uint8 *online_status)
{
    instance_list_t inst_lists[INST_LIST_TYPE_COUNT];
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    dms_reform_judgement_proc_t reform_judgement_proc;
    uint32 len = (uint32)(sizeof(instance_list_t) * INST_LIST_TYPE_COUNT);

    share_info->proto_version = dms_get_send_proto_version_by_cmd(MSG_REQ_SYNC_SHARE_INFO, CM_INVALID_ID8);
    if (share_info->list_offline.inst_id_count != 0) {
        dms_reform_judgement_stat_desc("offline exists");
        return CM_FALSE;
    }

    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_CHECK_REMOTE);
    if (dms_reform_check_remote() != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to check remote");
        return CM_FALSE;
    }

    int ret = memset_s(inst_lists, len, 0, len);
    if (ret != EOK) {
        dms_reform_judgement_stat_desc("fail to memset");
        return CM_FALSE;
    }

    share_info->reformer_version.inst_id = (uint8)g_dms.inst_id;
    share_info->reformer_version.start_time = reform_info->start_time;
    dms_reform_judgement_list_collect(inst_lists, online_status);
#ifndef OPENGAUSS
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_REFRESH_REFORM_INFO);
    dms_reform_judgement_refresh_reform_info();
#endif
    dms_reform_judgement_reform_type(inst_lists);

    reform_judgement_proc = g_reform_judgement_proc[share_info->reform_type];
    if (!reform_judgement_proc.check_proc(inst_lists)) {
        dms_reform_judgement_stat_desc("fail to check");
        return CM_FALSE;
    }

    dms_reform_judgement_set_catalog();

    /* this check must be first in judgement reform */
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_SYNC_GCV);
    if (dms_reform_sync_cluster_version(CM_FALSE) != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to sync gcv");
        return CM_FALSE;
    }

    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_REFRESH_MAP_INFO);
    if (dms_reform_refresh_map_info(online_status, inst_lists) != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to refresh map info");
        return CM_FALSE;
    }

#ifdef OPENGAUSS
    dms_reform_adjust(inst_lists, online_status);
#endif
    cm_spin_lock(&reform_context->share_info_lock, NULL);
    share_info->version_num++;
    cm_spin_unlock(&reform_context->share_info_lock);

    // build reform step. check_proc may change reform_type, so reset judgement_proc
    reform_judgement_proc = g_reform_judgement_proc[share_info->reform_type];
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_PROC);
    dms_reform_judgement_before_proc(inst_lists); // must before judgement proc
    reform_judgement_proc.judgement_proc(inst_lists);

    dms_reform_judgement_record_start_times();

    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_SYNC_SHARE_INFO);
    if (dms_reform_sync_share_info() != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to sync share info");
        return CM_FALSE;
    }

    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
    dms_reform_judgement_stat_desc("success");
    return CM_TRUE;
}

#ifndef OPENGAUSS
static bool8 dms_reform_kick_reboot_inst_online_list()
{
    share_info_t *share_info = DMS_SHARE_INFO;
    health_info_t *health_info = DMS_HEALTH_INFO;
    uint64 bitmap_kick_out = 0;
    uint64 bitmap_status_in = 0;
    for (uint8 i = 0; i < share_info->list_online.inst_id_count; ++i) {
        uint8 inst_id = share_info->list_online.inst_id_list[i];
        if ((health_info->online_status[inst_id] == DMS_STATUS_JOIN ||
            health_info->online_status[inst_id] == DMS_STATUS_OUT) &&
            bitmap64_exist(&share_info->bitmap_stable, inst_id)) {
            bitmap64_set(&bitmap_kick_out, inst_id);
        }
        if (health_info->online_status[inst_id] == DMS_STATUS_IN) {
            bitmap64_set(&bitmap_status_in, inst_id);
        }
    }
    if (bitmap_status_in == 0 || bitmap_kick_out == 0) {
        return CM_TRUE;
    }

    LOG_RUN_INF("[DMS REFORM] bitmap_status_in is %llu, bitmap_kick_out is %llu", bitmap_status_in, bitmap_kick_out);

    if (bitmap64_exist(&bitmap_kick_out, (uint8)g_dms.inst_id)) {
        LOG_RUN_INF("[DMS REFORM] reformer inst %u should be kicked out", g_dms.inst_id);
        uint8 new_reformer_id = bitmap64_get_bit_is_one(bitmap_status_in);
        LOG_RUN_INF("[DMS REFORM] new reformer is inst %u", new_reformer_id);
        dms_reform_cm_res_trans_lock(new_reformer_id);
        reform_info_t *reform_info = DMS_REFORM_INFO;
        reform_info->dms_role = DMS_ROLE_PARTNER;
        return CM_FALSE;
    } else {
        dms_reform_list_to_bitmap(&share_info->bitmap_online, &share_info->list_online);
        LOG_RUN_INF("[DMS REFORM] share_info->bitmap_online before kick is %llu", share_info->bitmap_online);
        bitmap64_minus(&share_info->bitmap_online, bitmap_kick_out);
        LOG_RUN_INF("[DMS REFORM] share_info->bitmap_online after kick is %llu", share_info->bitmap_online);
        dms_reform_bitmap_to_list(&share_info->list_online, share_info->bitmap_online);
        return CM_TRUE;
    }
}
#endif

static void dms_reform_judgement_reformer(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;
    health_info_t *health_info = DMS_HEALTH_INFO;

    if (dms_reform_in_process()) {
        dms_reform_judgement_stat_cancel();
        return;
    }

    uint64 online_version = 0ULL;
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_GET_LIST_ONLINE);
    if (dms_reform_get_list_from_cm(&share_info->list_online, &share_info->list_offline, &online_version)
        != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to get online list");
        return;
    }

#ifdef UT_TEST
    return;
#endif
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_GET_LIST_STABLE);
    if (dms_reform_get_list_stable() != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to get stable list");
        return;
    }

    dms_reform_modify_list();

    // mes_channel_entry has been created in mes_init, add mes_channel_entry dynamically is not allowed in openGauss
#ifndef OPENGAUSS
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_CONNECT);
    if (dms_reform_connect(&share_info->list_online) != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to connect");
        return;
    }
#endif
    dms_reform_judgement_stat_step(DMS_REFORM_JUDGE_GET_ONLINE_STATUS);
    if (dms_reform_get_online_status(&share_info->list_online, health_info->online_status, health_info->online_times,
        health_info->online_rw_status, reform_ctx->sess_judge) != DMS_SUCCESS) {
        dms_reform_judgement_stat_desc("fail to get online status");
        return;
    }
    share_info->reformer_id = (uint8)g_dms.inst_id;
#ifndef OPENGAUSS
    if (!dms_reform_kick_reboot_inst_online_list()) {
        return;
    }
#endif
    dms_set_driver_ping_info(online_version, health_info->online_rw_status, &share_info->list_online);

    if (!dms_reform_judgement(health_info->online_status)) {
        return;
    }

    dms_reform_set_start();
}

static void dms_reform_judgement_partner(void)
{
    instance_list_t list_online;
    instance_list_t list_offline;
    uint64 online_version = 0ULL;

    if (dms_reform_get_list_from_cm(&list_online, &list_offline, &online_version) != DMS_SUCCESS) {
        return;
    }

#ifdef UT_TEST
    return;
#endif

    // mes_channel_entry has been created in mes_init, add mes_channel_entry dynamically is not allowed in openGauss
#ifndef OPENGAUSS
    if (dms_reform_connect(&list_online) != DMS_SUCCESS) {
        return;
    }
#endif
}

static void dms_reform_judgement_mes_init(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    reform_info->bitmap_mes = 0;
    GS_INIT_SPIN_LOCK(reform_info->mes_lock);
    if (!reform_context->mes_has_init) {
        return;
    }

    for (uint32 i = 0; i < g_dms.inst_cnt; i++) {
        bitmap64_set(&reform_info->bitmap_mes, (uint8)i);
    }
}

void dms_reform_judgement_thread(thread_t *thread)
{
    cm_set_thread_name("reform_judgement");
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    LOG_RUN_INF("[DMS REFORM]dms_reform_judgement thread started");
    dms_reform_judgement_mes_init();
    dms_reform_judgement_stat_init();
    while (!thread->closed) {
        if (DMS_IS_REFORMER) {
            dms_reform_judgement_stat_start();
            dms_reform_judgement_reformer();
            dms_reform_judgement_stat_end();
        } else if (DMS_IS_PARTNER) {
            dms_reform_judgement_partner();
        }
        DMS_REFORM_LONG_SLEEP;
    }
}
