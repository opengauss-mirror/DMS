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
#include "dms_errno.h"

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

// get online offline unknown list from CMS
static int dms_reform_get_list_from_cm(instance_list_t *list_online, instance_list_t *list_offline)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    instance_list_t list_unknown;
    int ret = DMS_SUCCESS;

    dms_reform_list_init(list_online);
    dms_reform_list_init(list_offline);
    dms_reform_list_init(&list_unknown);
    if (!reform_info->build_complete) {
        dms_reform_list_add(list_online, DMS_REFORMER_ID_FOR_BUILD);
        return DMS_SUCCESS;
    }

    if (reform_info->maintain) {
        dms_reform_list_add(list_online, (uint8)g_dms.inst_id);
        return DMS_SUCCESS;
    }

    ret = dms_reform_cm_res_get_inst_stat(list_online, list_offline, &list_unknown);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    // if there is unknown instance, finish current judgement
    if (list_unknown.inst_id_count != 0) {
        LOG_DEBUG_WAR("[DMS REFORM]dms_reform_get_list_online, unknown inst count: %d", list_unknown.inst_id_count);
        return ERRNO_DMS_REFORM_FAIL;
    }

    if (!dms_reform_list_exist(list_online, (uint8)g_dms.inst_id)) {
        LOG_DEBUG_WAR("[DMS REFORM]dms_reform_get_list_online, instance(%u) not in list_online", g_dms.inst_id);
        return ERRNO_DMS_REFORM_FAIL;
    }

    return DMS_SUCCESS;
}

// if there is instance in online list before and not in online list now, set reform fail
static void dms_reform_cmp_list_online(instance_list_t *list_online)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    bool32 in_list_current = CM_FALSE;
    bool32 in_list_cache = CM_FALSE;
    uint64 bitmap_online_current = 0;

    dms_reform_list_to_bitmap(&bitmap_online_current, list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_current = bitmap64_exist(&bitmap_online_current, i);
        in_list_cache = bitmap64_exist(&share_info->bitmap_online, i);
        if (in_list_cache && !in_list_current) {
            dms_reform_set_fail();
            LOG_RUN_INF("[DMS REFORM]dms_reform_cmp_list_online error, inst(%d) offline, cache: %llu, current: %llu",
                i, share_info->bitmap_online, bitmap_online_current);
            return;
        }
    }
}

void dms_reform_update_reformer_version(uint64 start_time, uint8 inst_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    cm_spin_lock(&reform_info->version_lock, NULL);
    reform_info->reformer_version.start_time = start_time;
    reform_info->reformer_version.inst_id = inst_id;
    cm_spin_unlock(&reform_info->version_lock);
}

static int dms_reform_get_online_status_l(uint8 *online_status, uint8 dst_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 status = (uint8)g_dms.callback.get_dms_status(g_dms.reform_ctx.handle_judge);
    CM_ASSERT(status <= DMS_STATUS_IN);
    online_status[dst_id] = status;
    dms_reform_update_reformer_version(reform_info->start_time, dst_id);
    return DMS_SUCCESS;
}

// don't retry while wait overtime, finish current judgement and get online list again
static int dms_reform_get_online_status_r(uint8 *online_status, uint8 dst_id)
{
    dms_reform_req_partner_status_t req;

    dms_reform_init_req_dms_status(&req, dst_id);
    int ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_get_online_status_r SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_dms_status_wait(online_status, dst_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_get_online_status_r WAIT error: %d, dst_id: %d", ret, dst_id);
    }

    return ret;
}

// 1. req to online list and get status
static int dms_reform_get_online_status(instance_list_t *list_online, uint8 *online_status)
{
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            ret = dms_reform_get_online_status_l(online_status, dst_id);
        } else {
            ret = dms_reform_get_online_status_r(online_status, dst_id);
        }
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    return DMS_SUCCESS;
}

// if there is instance status before less than now
// it means the instance restart in the period of reform, set reform fail
static void dms_reform_cmp_online_status(uint8 *online_status, uint8 *online_status_cache)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint64 list_online_cache = 0;
    bool32 in_list_cache = CM_FALSE;

    dms_reform_list_to_bitmap(&list_online_cache, &share_info->list_online);
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        in_list_cache = bitmap64_exist(&list_online_cache, i);
        if (!in_list_cache) {
            continue;
        }
        if (online_status_cache[i] > online_status[i]) {
            dms_reform_set_fail();
            LOG_RUN_INF("[DMS REFORM]dms_reform_cmp_online_status error, inst(%d), cache: %d, current: %d",
                i, online_status_cache[i], online_status[i]);
            return;
        } else {
            online_status_cache[i] = online_status[i];
        }
    }
}

// in the period of reform, some errors may occur
static void dms_reform_check_abnormal(uint8 *online_status_cache)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 online_status[DMS_MAX_INSTANCES] = { 0 };
    instance_list_t list_online;
    instance_list_t list_offline;

    if (!reform_info->build_complete) {
        return;
    }

    if (reform_info->maintain) {
        return;
    }

    if (reform_info->reform_fail) {
        return;
    }

    if (dms_reform_get_list_from_cm(&list_online, &list_offline) != DMS_SUCCESS) {
        return;
    }

    dms_reform_cmp_list_online(&list_online);
    if (reform_info->reform_fail) {
        return;
    }

    if (dms_reform_get_online_status(&share_info->list_online, online_status) != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_check_abnormal skip, fail to get online status");
        return;
    }
    dms_reform_cmp_online_status(online_status, online_status_cache);
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

    if (DMS_CATALOG_IS_CENTRALIZED) {
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
#endif
}

static void dms_reform_bitmap_to_list(instance_list_t *list, uint64 bitmap)
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
    ret = mes_connect_batch_no_wait(list_reconnect.inst_id_list, list_reconnect.inst_id_count);
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
    int ret = DMS_SUCCESS;
    bool8 last_fail = CM_FALSE;

    dms_reform_init_req_prepare(&req, dst_id);
    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_remote_inner SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_prepare_wait(&last_fail);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_check_remote_inner WAIT error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    if (last_fail) {
        share_info->full_clean = CM_TRUE;
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

static void dms_reform_add_step(reform_step_t step)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    // BUILD and UNSHARED no need to SYNC_WAIT, there is only one instance
    if ((dms_reform_type_is(DMS_REFORM_TYPE_FOR_BUILD) || dms_reform_type_is(DMS_REFORM_TYPE_FOR_MAINTAIN)) &&
        step == DMS_REFORM_STEP_SYNC_WAIT) {
        return;
    }

    share_info->reform_step[share_info->reform_step_count++] = step;
    CM_ASSERT(share_info->reform_step_count < DMS_REFORM_STEP_TOTAL_COUNT);
}

static void dms_reform_judgement_prepare(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->reform_step_count = 0;
    dms_reform_add_step(DMS_REFORM_STEP_PREPARE);
}

static void dms_reform_judgement_start(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_START);
}

static void dms_reform_judgement_msg_sync(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_MSG_SYNC);
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
        dms_reform_add_step(DMS_REFORM_STEP_DRC_CLEAN);
        return;
    }

    // if reform_type is fail-over, all DRC has lost, no need to do drc_clean
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
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
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;

    uint32 size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
    errno_t err = memcpy_s(remaster_info->inst_part_tbl, size, part_mngr->inst_part_tbl, size);
    DMS_SECUREC_CHECK(err);

    size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
    err = memcpy_s(remaster_info->part_map, size, part_mngr->part_map, size);
    DMS_SECUREC_CHECK(err);
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
    if (DMS_CATALOG_IS_CENTRALIZED) {
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
        CM_ASSERT(part_id < DRC_MAX_PART_NUM);
        part_map = &remaster_info->part_map[part_id];
        inst_part->first = part_map->next;
        inst_part->count--;
        parts[(*part_num)++] = part_id;
    }
}

static void dms_reform_part_collect(uint16 *parts, uint8 *part_num)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_inst_part_t *inst_part = NULL;

    // reformer has not finished the first reform, all parts should be assigned
    if (!DMS_FIRST_REFORM_FINISH) {
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
    CM_ASSERT(*part_num > 0);
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

static void dms_reform_part_remaster(instance_list_t *inst_lists)
{
    uint16 parts[DRC_MAX_PART_NUM];
    uint8 part_num = 0;

    dms_reform_part_copy();
    dms_reform_part_recalc(inst_lists);
    dms_reform_part_collect(parts, &part_num);
    dms_reform_part_assign(parts, part_num);
}

static void dms_reform_judgement_remaster(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    // all drc assign to reformer
    if (DMS_CATALOG_IS_CENTRALIZED) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REMASTER);
        dms_reform_part_remaster(inst_lists);
        return;
    }

    // online instance changed, should recalc part info and assign
    if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0 ||
        share_info->full_clean || !DMS_FIRST_REFORM_FINISH) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REMASTER);
        dms_reform_part_remaster(inst_lists);
        return;
    }

    // old join, part info is empty, should copy from reformer
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REMASTER);
        dms_reform_part_copy();
        return;
    }
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
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_SWITCHOVER_PROMOTE);
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
    migrate_task_t migrate_task;

    if (part_now->inst_id == part_remaster->inst_id) {
        return;
    }

    if (!bitmap64_exist(&bitmap_online, part_now->inst_id)) {
        return;
    }

    // part_remaster->inst_id must be in list_online
    // if part_now->inst_id is in list_online too
    // should migrate part info from part_now->inst_id to part_remaster->inst_id;
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
    share_info_t *share_info = DMS_SHARE_INFO;

    if (share_info->full_clean) {
        return;
    }

    if (DMS_CATALOG_IS_CENTRALIZED) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_MIGRATE);
        dms_reform_migrate_task();
        return;
    }

    if (inst_lists[INST_LIST_NEW_JOIN].inst_id_count > inst_lists[INST_LIST_OLD_REMOVE].inst_id_count) {
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_MIGRATE);
        dms_reform_migrate_task();
        return;
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

    // if reform_type is standby, standby node does not manage DRC, no need to do rebuild
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY)) {
        return;
    }

    dms_reform_list_init(&share_info->list_rebuild);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_rebuild, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_REBUILD);
    }
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

static void dms_reform_judgement_recovery_parallel(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_recovery);
    dms_reform_list_init(&share_info->list_remove);
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count != 0 || inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
        dms_reform_list_cancat(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_JOIN]);
        dms_reform_list_cancat(&share_info->list_recovery, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_list_cancat(&share_info->list_remove, &inst_lists[INST_LIST_OLD_REMOVE]);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_PARALLEL);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN);
    }
}

static void dms_reform_judgement_recovery_failover(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_recovery);
    dms_reform_list_init(&share_info->list_remove);
    dms_reform_list_add_all(&share_info->list_recovery);
    dms_reform_list_cancat(&share_info->list_remove, &inst_lists[INST_LIST_OLD_REMOVE]);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_FAILOVER);
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN);
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
        dms_reform_add_step(DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN);
    }
}

static void dms_reform_judgement_refresh_point(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_REFRESH_POINT);
}

static void dms_reform_judgement_rollback(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_rollback);

    // in multi_write, reformer rollback transaction of removed instances
    // if there are some instances restart, they rollback transaction by themselves
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL)) {
        if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0) {
            dms_reform_list_cancat(&share_info->list_rollback, &inst_lists[INST_LIST_OLD_REMOVE]);
            dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
            dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK);
        }
        return;
    }

    // in primary_standby, reformer rollback transaction of all instances. partner is also standby, it is read only
    // in partner, it may remain unfinished transaction and redo. reformer should traverse undo segment of all inst
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER)) {
        dms_reform_list_add_all(&share_info->list_rollback);
        dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
        dms_reform_add_step(DMS_REFORM_STEP_ROLLBACK);
        return;
    }
}

static void dms_reform_judgement_txn_deposit(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_list_init(&share_info->list_withdraw);
    dms_reform_list_init(&share_info->list_deposit);

    // reformer withdraw own txn
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_SWITCHOVER)) {
        dms_reform_list_add(&share_info->list_withdraw, share_info->promote_id);
        dms_reform_add_step(DMS_REFORM_STEP_TXN_DEPOSIT);
        return;
    }

    // reformer withdraw own txn and deposit others
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER)) {
        dms_reform_list_add_all(&share_info->list_deposit);
        dms_reform_add_step(DMS_REFORM_STEP_TXN_DEPOSIT);
        return;
    }

    // reformer deposit new standby
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY)) {
        if (inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
            dms_reform_list_cancat(&share_info->list_deposit, &inst_lists[INST_LIST_NEW_JOIN]);
            dms_reform_add_step(DMS_REFORM_STEP_TXN_DEPOSIT);
        }
        return;
    }

    // new instances withdraw own txn, reformer deposit remove instances
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL)) {
        if (inst_lists[INST_LIST_OLD_REMOVE].inst_id_count != 0 || inst_lists[INST_LIST_NEW_JOIN].inst_id_count != 0) {
            dms_reform_list_cancat(&share_info->list_withdraw, &inst_lists[INST_LIST_NEW_JOIN]);
            dms_reform_list_cancat(&share_info->list_deposit, &inst_lists[INST_LIST_OLD_REMOVE]);
            dms_reform_add_step(DMS_REFORM_STEP_TXN_DEPOSIT);
        }
        return;
    }
}

// Notice1: LOCK_ACCESS must be used after
// Notice2: PAGE_ACCESS must be used after
static void dms_reform_judgement_drc_inaccess(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_DRC_INACCESS);
    dms_reform_judgement_msg_sync();
}

// Notice: DRC_INACCESS must be used before
static void dms_reform_judgement_page_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_PAGE_ACCESS);
}

// Notice: DRC_INACCESS must be used before
static void dms_reform_judgement_lock_access(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_SYNC_WAIT);
    dms_reform_add_step(DMS_REFORM_STEP_LOCK_ACCESS);
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

static void dms_reform_judgement_load_tablespace(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_LOAD_TABLESPACE);
}

static void dms_refrom_judgement_startup_opengauss(void)
{
    dms_reform_add_step(DMS_REFORM_STEP_STARTUP_OPENGAUSS);
}

static char reform_step_desc[DMS_REFORM_STEP_COUNT][DMS_REFORM_STEP_DESC_STR_LEN] = {
    [DMS_REFORM_STEP_DONE] = "DONE",
    [DMS_REFORM_STEP_PREPARE] = "PREPARE",
    [DMS_REFORM_STEP_START] = "START",
    [DMS_REFORM_STEP_MSG_SYNC] = "MSG_SYNC",
    [DMS_REFORM_STEP_DISCONNECT] = "DISCONNECT",
    [DMS_REFORM_STEP_RECONNECT] = "RECONNECT",
    [DMS_REFORM_STEP_DRC_CLEAN] = "DRC_CLEAN",
    [DMS_REFORM_STEP_MIGRATE] = "MIGRATE",
    [DMS_REFORM_STEP_REBUILD] = "REBUILD",
    [DMS_REFORM_STEP_REMASTER] = "REMASTER",
    [DMS_REFORM_STEP_REPAIR] = "REPAIR",
    [DMS_REFORM_STEP_SWITCH_LOCK] = "SWITCH_LOCK",
    [DMS_REFORM_STEP_SWITCHOVER_DEMOTE] = "SWITCHOVER_DEMOTE",
    [DMS_REFORM_STEP_SWITCHOVER_PROMOTE] = "SWITCHOVER_PROMOTE",
    [DMS_REFORM_STEP_RECOVERY_FAILOVER] = "RECOVERY_FAILOVER",
    [DMS_REFORM_STEP_RECOVERY_PARALLEL] = "RECOVERY_PARALLEL",
    [DMS_REFORM_STEP_RECOVERY_OPENGAUSS] = "RECOVERY_OPENGAUSS",
    [DMS_REFORM_STEP_RECOVERY_FLAG_CLEAN] = "RECOVERY_FLAG_CLEAN",
    [DMS_REFORM_STEP_TXN_DEPOSIT] = "TXN_DEPOSIT",
    [DMS_REFORM_STEP_ROLLBACK] = "ROLLBACK",
    [DMS_REFORM_STEP_SUCCESS] = "SUCCESS",
    [DMS_REFORM_STEP_SELF_FAIL] = "SELF_FAIL",
    [DMS_REFORM_STEP_REFORM_FAIL] = "REFORM_FAIL",
    [DMS_REFORM_STEP_SYNC_WAIT] = "SYNC_WAIT",
    [DMS_REFORM_STEP_LOCK_ACCESS] = "LOCK_ACCESS",
    [DMS_REFORM_STEP_PAGE_ACCESS] = "PAGE_ACCESS",
    [DMS_REFORM_STEP_DRC_INACCESS] = "DRC_INACCESS",
    [DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS] = "SWITCHOVER_PROMOTE_OPENGAUSS",
    [DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS] = "FAILOVER_PROMOTE_OPENGAUSS",
    [DMS_REFORM_STEP_LOAD_TABLESPACE] = "LOAD_TABLESPACE",
    [DMS_REFORM_STEP_STARTUP_OPENGAUSS] = "STARTUP_OPENGAUSS",
    [DMS_REFORM_STEP_FLUSH_COPY] = "FLUSH_COPY",
    [DMS_REFORM_STEP_REFRESH_POINT] = "REFRESH_POINT",
    [DMS_REFORM_STEP_DONE_CHECK] = "DONE_CHECK",
};

static char *dms_reform_get_type_desc(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    switch (share_info->reform_type) {
        case DMS_REFORM_TYPE_FOR_OPENGAUSS:
            return "OPENGAUSS_NORMAL";

        case DMS_REFORM_TYPE_FOR_NORMAL:
            return "NORMAL";

        case DMS_REFORM_TYPE_FOR_SWITCHOVER:
            return "SWITCHOVER";

        case DMS_REFORM_TYPE_FOR_FAILOVER:
            return "FAILOVER";

        case DMS_REFORM_TYPE_FOR_STANDBY:
            return "FOR STANDBY";

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

        case DMS_REFORM_TYPE_COUNT:
        default:
            return "UNKNOWN TYPE";
    }
}

void dms_reform_judgement_step_log(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 step = (uint8)share_info->reform_step[0];
    char desc[DMS_INFO_DESC_LEN] = { 0 };
    errno_t err;

    err = strcat_s(desc, DMS_INFO_DESC_LEN, reform_step_desc[step]);
    DMS_SECUREC_CHECK(err);

    for (uint8 i = 1; i < share_info->reform_step_count; i++) {
        err = strcat_s(desc, DMS_INFO_DESC_LEN, "-");
        DMS_SECUREC_CHECK(err);
        step = (uint8)share_info->reform_step[i];
        err = strcat_s(desc, DMS_INFO_DESC_LEN, reform_step_desc[step]);
        DMS_SECUREC_CHECK(err);
    }

    char *role = DMS_IS_REFORMER ? "reformer" : "partner";
    char *catalog = DMS_CATALOG_IS_CENTRALIZED ? "centralized" : "distributed";
    char *reform_type = dms_reform_get_type_desc();

    LOG_RUN_INF("[DMS REFORM]inst_id:%u, role:%s, catalog:%s, reform_type:%s, full_clean:%d, dms_reform_step:%s",
        g_dms.inst_id, role, catalog, reform_type, share_info->full_clean, desc);
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
    dms_reform_instance_list_log(&share_info->list_deposit, "share list deposit", desc);
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
}

static void dms_reform_judgement_normal(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_load_tablespace();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_recovery_parallel(inst_lists);
    dms_reform_judgement_refresh_point();
    dms_reform_judgement_rollback(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_switchover(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_switchover_demote(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_switch_lock();
    dms_reform_judgement_switchover_promote();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_switchover_opengauss(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_switchover_demote(inst_lists);
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_migrate(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_switch_lock();
    dms_reform_judgement_switchover_promote_opengauss();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_failover(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_load_tablespace();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_recovery_failover(inst_lists);
    dms_reform_judgement_refresh_point();
    dms_reform_judgement_rollback(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_switchover_promote();
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
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_failover_promote_opengauss();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_recovery_opengauss(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_opengauss(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_refrom_judgement_startup_opengauss();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_recovery_opengauss(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_standby(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_disconnect(inst_lists);
    dms_reform_judgement_reconnect(inst_lists);
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_load_tablespace();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_refresh_point();
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_build(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_load_tablespace();
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_full_clean(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_drc_clean(inst_lists);
    dms_reform_judgement_rebuild(inst_lists);
    dms_reform_judgement_remaster(inst_lists);
    dms_reform_judgement_repair(inst_lists);
    dms_reform_judgement_lock_access();
    dms_reform_judgement_flush_copy();
    dms_reform_judgement_page_access();
    dms_reform_judgement_success();
    dms_reform_judgement_done();
}

static void dms_reform_judgement_maintain(instance_list_t *inst_lists)
{
    dms_reform_judgement_prepare();
    dms_reform_judgement_start();
    dms_reform_judgement_drc_inaccess();
    dms_reform_judgement_load_tablespace();
    dms_reform_judgement_recovery_failover(inst_lists);
    dms_reform_judgement_refresh_point();
    dms_reform_judgement_rollback(inst_lists);
    dms_reform_judgement_txn_deposit(inst_lists);
    dms_reform_judgement_page_access();
    dms_reform_judgement_switchover_promote();
    dms_reform_judgement_success();
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

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 &&
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, old_remove: 0, new_join: 0");
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool32 dms_reform_judgement_switchover_check(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;

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
    if (!bitmap64_exist(&share_info->bitmap_online, switchover_info->inst_id)) {
        switchover_info->switch_req = CM_FALSE;
        switchover_info->inst_id = CM_INVALID_ID8;
        switchover_info->sess_id = CM_INVALID_ID16;
        cm_spin_unlock(&switchover_info->lock);
        return CM_FALSE;
    }

    share_info->reform_type = DMS_REFORM_TYPE_FOR_SWITCHOVER;
    share_info->promote_id = switchover_info->inst_id;
    share_info->switch_version.inst_id = switchover_info->inst_id;
    share_info->switch_version.start_time = switchover_info->start_time;
    cm_spin_unlock(&switchover_info->lock);
    return CM_TRUE;
}

static bool32 dms_reform_judgement_switchover_opengauss_check(instance_list_t *inst_lists)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;

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
    if (!bitmap64_exist(&share_info->bitmap_online, switchover_info->inst_id)) {
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

static bool32 dms_reform_judgement_standby_check(instance_list_t *inst_lists)
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

    if (dms_reform_judgement_switchover_check(inst_lists)) {
        return CM_TRUE;
    }

    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 &&
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, old_remove: 0, new_join: 0");
        return CM_FALSE;
    }

    return CM_TRUE;
}

static bool32 dms_reform_judgement_failover_check(instance_list_t *inst_lists)
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

    // prevent inexplicable switch dms_reform_lock
    if (inst_lists[INST_LIST_OLD_JOIN].inst_id_count == 0 && inst_lists[INST_LIST_OLD_REMOVE].inst_id_count == 0 &&
        inst_lists[INST_LIST_NEW_JOIN].inst_id_count == 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, old_join: 0, old_remove: 0, new_join: 0");
        return CM_FALSE;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->promote_id = (uint8)g_dms.inst_id;
    return CM_TRUE;
}

static bool32 dms_reform_judgement_failover_check_opengauss(instance_list_t *inst_lists)
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

static bool32 dms_reform_judgement_build_check(instance_list_t *inst_lists)
{
    if (DMS_FIRST_REFORM_FINISH) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, first reform has finished");
        return CM_FALSE;
    }
    return CM_TRUE;
}

static bool32 dms_reform_judgement_opengauss_check(instance_list_t *inst_lists)
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
        return CM_FALSE;
    }

    share_info_t *share_info = DMS_SHARE_INFO;
    share_info->promote_id = (uint8)g_dms.inst_id;
    return CM_TRUE;
}

static void dms_reform_judgement_normal_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_switchover_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_failover_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_opengauss_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_failover_print_opengauss(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_standby_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_build_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_full_clean_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

static void dms_reform_judgement_maintain_print(instance_list_t *inst_lists)
{
    dms_reform_instance_lists_log(inst_lists);
    dms_reform_judgement_step_log();
}

#ifdef OPENGAUSS
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

    share_info->reform_type = DMS_REFORM_TYPE_FOR_OPENGAUSS;
}
#else
static void dms_reform_judgement_reform_type(instance_list_t *list)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    // treat full_clean as priority
    if (dms_reform_list_cmp(&share_info->list_online, &share_info->list_stable) &&
        dms_reform_list_cmp(&share_info->list_online, &list[INST_LIST_OLD_IN]) &&
        share_info->full_clean) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_FULL_CLEAN;
        return;
    }

    // database has not been created
    if (!reform_info->build_complete) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_BUILD;
        return;
    }

    // database started for maintain
    if (reform_info->maintain) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_MAINTAIN;
        return;
    }

    // switchover & fail over are not allowed at multi_write
    if (!DMS_CATALOG_IS_PRIMARY_STANDBY) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_NORMAL;
        return;
    }

    // db restart with reformer lock, treat as fail over
    if (!DMS_FIRST_REFORM_FINISH) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_FAILOVER;
        return;
    }

    // db is primary & reformer, it is normal situation, check if should reform for standby
    // if all nodes are normal, then check if there is switchover request
    if (g_dms.callback.db_is_primary(g_dms.reform_ctx.handle_judge)) {
        share_info->reform_type = DMS_REFORM_TYPE_FOR_STANDBY;
        return;
    }

    // db is not primary but reformer, it seems that original reformer is abnormal
    share_info->reform_type = DMS_REFORM_TYPE_FOR_FAILOVER;
}
#endif

static dms_reform_judgement_proc_t g_reform_judgement_proc[DMS_REFORM_TYPE_COUNT] = {
    [DMS_REFORM_TYPE_FOR_NORMAL] = {
    dms_reform_judgement_normal_check,
    dms_reform_judgement_normal,
    dms_reform_judgement_normal_print },

    [DMS_REFORM_TYPE_FOR_SWITCHOVER] = {
    dms_reform_judgement_switchover_check,
    dms_reform_judgement_switchover,
    dms_reform_judgement_switchover_print },

    [DMS_REFORM_TYPE_FOR_FAILOVER] = {
    dms_reform_judgement_failover_check,
    dms_reform_judgement_failover,
    dms_reform_judgement_failover_print },

    [DMS_REFORM_TYPE_FOR_OPENGAUSS] = {
    dms_reform_judgement_opengauss_check,
    dms_reform_judgement_opengauss,
    dms_reform_judgement_opengauss_print },

    [DMS_REFORM_TYPE_FOR_STANDBY] = {
    dms_reform_judgement_standby_check,
    dms_reform_judgement_standby,
    dms_reform_judgement_standby_print },

    [DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS] = {
    dms_reform_judgement_failover_check_opengauss,
    dms_reform_judgement_failover_opengauss,
    dms_reform_judgement_failover_print_opengauss },

    [DMS_REFORM_TYPE_FOR_BUILD] = {
    dms_reform_judgement_build_check,
    dms_reform_judgement_build,
    dms_reform_judgement_build_print },

    [DMS_REFORM_TYPE_FOR_SWITCHOVER_OPENGAUSS] = {
    dms_reform_judgement_switchover_opengauss_check,
    dms_reform_judgement_switchover_opengauss,
    dms_reform_judgement_switchover_print },

    [DMS_REFORM_TYPE_FOR_FULL_CLEAN] = {
    dms_reform_judgement_full_clean_check,
    dms_reform_judgement_full_clean,
    dms_reform_judgement_full_clean_print },

    [DMS_REFORM_TYPE_FOR_MAINTAIN] = {
    dms_reform_judgement_maintain_check,
    dms_reform_judgement_maintain,
    dms_reform_judgement_maintain_print },
};

static int dms_reform_sync_share_info_r(uint8 dst_id)
{
    dms_reform_req_sync_share_info_t req;
    int ret = DMS_SUCCESS;

    dms_reform_init_req_sync_share_info(&req, dst_id);
    ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_share_info_r SEND error: %d, dst_id: %d", ret, dst_id);
        return ret;
    }

    ret = dms_reform_req_sync_share_info_wait();
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

    share_info->reformer_id = (uint8)g_dms.inst_id;
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

static bool32 dms_reform_judgement(uint8 *online_status)
{
    instance_list_t inst_lists[INST_LIST_TYPE_COUNT];
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    dms_reform_judgement_proc_t reform_judgement_proc;
    uint32 len = (uint32)(sizeof(instance_list_t) * INST_LIST_TYPE_COUNT);

    if (share_info->list_offline.inst_id_count != 0) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, offline inst count: %d",
            share_info->list_offline.inst_id_count);
        return CM_FALSE;
    }

    int ret = memset_s(inst_lists, len, 0, len);
    if (ret != EOK) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, Secure C lib has thrown an error %d", ret);
        return CM_FALSE;
    }

    share_info->reformer_version.inst_id = (uint8)g_dms.inst_id;
    share_info->reformer_version.start_time = reform_info->start_time;
    dms_reform_judgement_list_collect(inst_lists, online_status);
    dms_reform_judgement_reform_type(inst_lists);

    reform_judgement_proc = g_reform_judgement_proc[share_info->reform_type];
    if (!reform_judgement_proc.check_proc(inst_lists)) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No need to reform");
        return CM_FALSE;
    }

    if (dms_reform_check_remote() != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, fail to check remote");
        return CM_FALSE;
    }

    cm_spin_lock(&reform_context->share_info_lock, NULL);
    share_info->version_num++;
    cm_spin_unlock(&reform_context->share_info_lock);

    // build reform step. check_proc may change reform_type, so reset judgement_proc
    reform_judgement_proc = g_reform_judgement_proc[share_info->reform_type];
    reform_judgement_proc.judgement_proc(inst_lists);

    if (dms_reform_sync_share_info() != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, fail to sync share info");
        return CM_FALSE;
    }

    LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: Yes");
    reform_judgement_proc.print_proc(inst_lists);
    return CM_TRUE;
}

static void dms_reform_judgement_reformer(uint8 *online_status)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    if (dms_reform_in_process()) {
        dms_reform_check_abnormal(online_status);
        return;
    }
    if (dms_reform_get_list_from_cm(&share_info->list_online, &share_info->list_offline) != DMS_SUCCESS) {
        return;
    }

#ifdef UT_TEST
    return;
#endif
    if (dms_reform_get_list_stable() != DMS_SUCCESS) {
        return;
    }

    dms_reform_modify_list();

    // mes_channel_entry has been created in mes_init, add mes_channel_entry dynamically is not allowed in openGauss
#ifndef OPENGAUSS
    if (dms_reform_connect(&share_info->list_online) != DMS_SUCCESS) {
        return;
    }
#endif
    if (dms_reform_get_online_status(&share_info->list_online, online_status) != DMS_SUCCESS) {
        LOG_DEBUG_INF("[DMS REFORM]dms_reform_judgement, result: No, fail to get online status");
        return;
    }

    if (!dms_reform_judgement(online_status)) {
        return;
    }

    dms_reform_set_start();
}

static void dms_reform_judgement_partner(void)
{
    instance_list_t list_online;
    instance_list_t list_offline;

    if (dms_reform_get_list_from_cm(&list_online, &list_offline) != DMS_SUCCESS) {
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
    uint8 online_status[DMS_MAX_INSTANCES] = { 0 };
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    LOG_RUN_INF("[DMS REFORM]dms_reform_judgement thread started");
    dms_reform_judgement_mes_init();
    while (!thread->closed) {
        if (DMS_IS_REFORMER) {
            dms_reform_judgement_reformer(online_status);
        } else if (DMS_IS_PARTNER) {
            dms_reform_judgement_partner();
        }
        DMS_REFORM_LONG_SLEEP;
    }
}
