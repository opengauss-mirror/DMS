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
 * dms_reform_cm_res.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_cm_res.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_cm_res.h"
#include "dms_reform.h"
#include "dms_process.h"
#include "dms_errno.h"
#ifdef DMS_TEST
#include "cm_num.h"
#endif

#ifdef DMS_TEST
uint8 g_reformer_id = 0;

static void dms_reform_get_reformer_id(void)
{
    char *reformer_id_str = getenv("DMS_REFORMER_ID");
    uint32 reformer_id;

    if (reformer_id_str == NULL) {
        return;
    }

    if (cm_str2uint32(reformer_id_str, &reformer_id) != CM_SUCCESS) {
        return;
    }

    if (reformer_id >= g_dms.inst_cnt) {
        return;
    }

    g_reformer_id = (uint8)reformer_id;
}

int dms_reform_cm_res_init(void)
{
#ifdef UT_TEST
    reform_info_t *reform_info = DMS_REFORM_INFO;

    reform_info->first_reform_finish = CM_TRUE;
    reform_info->page_accessible = CM_TRUE;
    reform_info->lock_accessible = CM_TRUE;
    printf("DMS FOR UT TEST.\n");
    LOG_RUN_INF("[DMS REFORM]cm_res_init success(FOR UT TEST)");
#else
    printf("DMS FOR DB TEST.\n");
    LOG_RUN_INF("[DMS REFORM]cm_res_init success(FOR DB TEST)");
    dms_reform_get_reformer_id();
#endif
    return DMS_SUCCESS;
}

static bool8 dms_reform_get_online_list(instance_list_t *list_online)
{
    char *online_bitmap_str = getenv("DMS_ONLINE_BITMAP");
    uint64 online_bitmap = 0;

    if (online_bitmap_str == NULL) {
        return CM_FALSE;
    }

    if (cm_str2uint64(online_bitmap_str, &online_bitmap) != CM_SUCCESS) {
        return CM_FALSE;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&online_bitmap, i)) {
            list_online->inst_id_list[list_online->inst_id_count++] = i;
        }
    }

    return CM_TRUE;
}

int dms_reform_cm_res_get_inst_stat(instance_list_t *list_online, instance_list_t *list_offline,
    instance_list_t *list_unknown)
{
    if (dms_reform_get_online_list(list_online)) {
        return DMS_SUCCESS;
    }

    for (uint32 i = 0; i < g_dms.inst_cnt; i++) {
        list_online->inst_id_list[list_online->inst_id_count++] = (uint8)i;
    }
    return DMS_SUCCESS;
}

void dms_reform_cm_res_lock(void)
{
    return;
}

void dms_reform_cm_res_unlock(void)
{
    return;
}

int dms_reform_cm_res_get_lock_owner(uint8 *owner_id)
{
    *owner_id = g_reformer_id;
    return DMS_SUCCESS;
}

void dms_reform_cm_res_trans_lock(uint8 inst_id)
{
    g_reformer_id = inst_id;
    return;
}

#else

int dms_reform_cm_res_init(void)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    int ret = DMS_SUCCESS;

    ret = cm_res_mgr_init(DMS_LIBCLIENT_PATH, cm_res_mgr, NULL);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]cm_res_mgr_init, error: %d", ret);
        return ret;
    }

    ret = cm_res_init(cm_res_mgr, g_dms.inst_id + DMS_RESOURCE_ID_BASE, DMS_CM_RES_NAME, NULL);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]cm_res_init, error: %d", ret);
        return ret;
    }

    LOG_RUN_INF("[DMS REFORM]cm_res_init success");
    return DMS_SUCCESS;
}

int dms_reform_cm_res_get_inst_stat(instance_list_t *list_online, instance_list_t *list_offline,
    instance_list_t *list_unknown)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    cm_res_stat_ptr_t res_stat = cm_res_get_stat(cm_res_mgr);
    if (res_stat == NULL) {
        return ERRNO_DMS_FAIL_GET_STAT_LIST;
    }

    int res_count = cm_res_get_instance_count(cm_res_mgr, res_stat);
    for (uint32 i = 0; i < (uint32)res_count; i++) {
        const cm_res_inst_info_ptr_t inst_info = cm_res_get_instance_info(cm_res_mgr, res_stat, i);
        CM_ASSERT(inst_info != NULL);

        int inst_id = cm_res_get_inst_instance_id(cm_res_mgr, inst_info);
        inst_id -= DMS_RESOURCE_ID_BASE;
        CM_ASSERT(inst_id >= 0 && inst_id < DMS_MAX_INSTANCES);

        int is_work_member = cm_res_get_inst_is_work_member(cm_res_mgr, inst_info);
        if (!is_work_member) {
            continue;
        }

        int stat = cm_res_get_inst_stat(cm_res_mgr, inst_info);
        CM_ASSERT(stat < INST_STAT_COUNT);

        if (stat == INST_STAT_ONLINE) {
            list_online->inst_id_list[list_online->inst_id_count++] = (uint8)inst_id;
        } else if (stat == INST_STAT_OFFLINE) {
            list_offline->inst_id_list[list_offline->inst_id_count++] = (uint8)inst_id;
        } else if (stat == INST_STAT_UNKNOWN) {
            list_unknown->inst_id_list[list_unknown->inst_id_count++] = (uint8)inst_id;
        }
    }
    cm_res_free_stat(cm_res_mgr, res_stat);

    return DMS_SUCCESS;
}

void dms_reform_cm_res_lock(void)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    (void)cm_res_lock(cm_res_mgr, DMS_REFORMER_LOCK);
}

void dms_reform_cm_res_unlock(void)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    (void)cm_res_unlock(cm_res_mgr, DMS_REFORMER_LOCK);
}

int dms_reform_cm_res_get_lock_owner(uint8 *owner_id)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    uint32 temp_id;
    int ret = DMS_SUCCESS;

    ret = cm_res_get_lock_owner(cm_res_mgr, DMS_REFORMER_LOCK, &temp_id);
    if (ret == CM_RES_TIMEOUT) {
        return ERRNO_DMS_RECV_MSG_FAILED;
    } else if (ret == CM_RES_SUCCESS) {
        *owner_id = (uint8)(temp_id - DMS_RESOURCE_ID_BASE);
    } else {
        *owner_id = CM_INVALID_ID8;
    }
    return DMS_SUCCESS;
}

void dms_reform_cm_res_trans_lock(uint8 inst_id)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    uint32 res_inst_id = inst_id + DMS_RESOURCE_ID_BASE;

    int ret = cm_res_trans_lock(cm_res_mgr, DMS_REFORMER_LOCK, res_inst_id);
    if (ret == DMS_SUCCESS) {
        LOG_RUN_INF("[DMS REFORM]success to trans reformer lock to %d", inst_id);
    }
}
#endif