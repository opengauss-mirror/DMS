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
#include "dms_error.h"
#ifdef DMS_TEST
#include "cm_num.h"
#endif

#ifdef DMS_TEST

cm_simulation_t g_cm_simulation;

static config_item_t g_cm_params[] = {
    { CM_REFORMER_ID, CM_TRUE, CM_FALSE, "0", NULL, NULL, "-", "[0, 63]", "INTEGER", NULL, CM_PARAM_REFORMER_ID,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { CM_BITMAP_ONLINE, CM_TRUE, CM_FALSE, "3", NULL, NULL, "-", "-", "BIG INTEGER", NULL, CM_PARAM_BITMAP_ONLINE,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
    { CM_VERSION_ONLINE, CM_TRUE, CM_FALSE, "0", NULL, NULL, "-", "-", "BIG INTEGER", NULL, CM_PARAM_VERSION_ONLINE,
        EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL },
};

static void dms_reform_cm_simulation_init()
{
    g_cm_simulation.params.reformer_id = CM_INVALID_ID32;
    g_cm_simulation.params.bitmap_online = 0;
    g_cm_simulation.params.online_version = 0;
}

static void dms_reform_cm_simulation_refresh(void)
{
    char *value = cm_get_config_value(&g_cm_simulation.config, CM_REFORMER_ID);
    if (cm_str2uint32(value, &g_cm_simulation.params.reformer_id) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to get REFORMER_ID");
    }

    value = cm_get_config_value(&g_cm_simulation.config, CM_BITMAP_ONLINE);
    if (cm_str2uint64(value, &g_cm_simulation.params.bitmap_online) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to get BITMAP_ONLINE");
    }

    value = cm_get_config_value(&g_cm_simulation.config, CM_VERSION_ONLINE);
    if (cm_str2uint64(value, &g_cm_simulation.params.online_version) != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to get VERSION_ONLINE");
    }
}

static void dms_reform_cm_simulation_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif

    char *cm_config_path = getenv(CM_CONFIG_PATH);
    char cm_config_realpath[CM_MAX_PATH_LEN];
    if (cm_config_path == NULL) {
        LOG_RUN_ERR("[DMS REFORM][cm_simulation]fail to get CM_CONFIG_PATH");
        return;
    }

    int status = realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]invalid cfg dir");
        return;
    }

    cm_set_thread_name("cm_simulation");
    LOG_RUN_INF("[DMS REFORM][cm_simulation]dms_reform_cm_simulation thread started");
    dms_reform_cm_simulation_init();

    while (!thread->closed) {
        cm_spin_lock(&g_cm_simulation.lock, NULL);
        status = cm_load_config(g_cm_params, CM_PARAM_COUNT, cm_config_realpath, &g_cm_simulation.config, CM_FALSE);
        if (status != CM_SUCCESS) {
            cm_spin_unlock(&g_cm_simulation.lock);
            LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to load cm simulation");
            cm_sleep(DMS_REFORM_LONG_TIMEOUT);
            continue;
        }
        dms_reform_cm_simulation_refresh();
        cm_spin_unlock(&g_cm_simulation.lock);
        cm_sleep(DMS_REFORM_LONG_TIMEOUT);
    }
}

static void dms_reform_cm_simulation(void)
{
    char *cm_config_path = getenv(CM_CONFIG_PATH);
    char cm_config_realpath[CM_MAX_PATH_LEN];
    if (cm_config_path == NULL) {
        LOG_RUN_ERR("[DMS REFORM][cm_simulation]fail to get CM_CONFIG_PATH");
        return;
    }

    int status = realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]invalid cfg dir");
        return;
    }

    int ret = cm_create_thread(dms_reform_cm_simulation_thread, 0, NULL, &g_cm_simulation.thread);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM][cm_simulation]fail to create dms_reform_cm_simulation_thread");
    }
}

int dms_reform_cm_res_init(void)
{
#ifdef UT_TEST
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    reform_info->first_reform_finish = CM_TRUE;
    ctx->global_buf_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_lock_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_xa_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    printf("DMS FOR UT TEST.\n");
    LOG_RUN_INF("[DMS REFORM]cm_res_init success(FOR UT TEST)");
#else
    printf("DMS FOR DB TEST.\n");
    dms_reform_cm_simulation();
    LOG_RUN_INF("[DMS REFORM]cm_res_init success(FOR DB TEST)");
#endif
    return DMS_SUCCESS;
}

void dms_reform_cm_simulation_uninit(void)
{
    cm_close_thread(&g_cm_simulation.thread);
}

int dms_cm_res_get_online_version(unsigned long long *online_version)
{
    *online_version = g_cm_simulation.params.online_version;
    return DMS_SUCCESS;
}

static void dms_reform_get_online_list(instance_list_t *list_online)
{
    char *cm_config_path = getenv(CM_CONFIG_PATH);
    char cm_config_realpath[CM_MAX_PATH_LEN];
    if (cm_config_path == NULL) {
        for (uint8 i = 0; i < g_dms.inst_cnt; i++) {
            list_online->inst_id_list[list_online->inst_id_count++] = i;
        }
        return;
    }

    int status = realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]invalid cfg dir");
        return;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&g_cm_simulation.params.bitmap_online, i)) {
            list_online->inst_id_list[list_online->inst_id_count++] = i;
        }
    }
}

int dms_reform_cm_res_get_inst_stat(instance_list_t *list_online, instance_list_t *list_offline,
    instance_list_t *list_unknown, unsigned long long *online_version)
{
    dms_reform_get_online_list(list_online);
    dms_cm_res_get_online_version(online_version);
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
    *owner_id = (uint8)g_cm_simulation.params.reformer_id;
    return DMS_SUCCESS;
}

void dms_reform_cm_res_trans_lock(uint8 inst_id)
{
    int status = CM_SUCCESS;
    char buf[CM_BUFLEN_32];
    char cm_config_realpath[CM_MAX_PATH_LEN];

    char *cm_config_path = getenv(CM_CONFIG_PATH);
    if (cm_config_path == NULL) {
        g_cm_simulation.params.reformer_id = inst_id;
        return;
    }

    status = realpath_file(cm_config_path, cm_config_realpath, CM_MAX_PATH_LEN);
    if (status != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]invalid cfg dir");
        return;
    }

    int ret = sprintf_s(buf, CM_BUFLEN_32, "%d", (int)inst_id);
    if (ret == -1) {
        return;
    }

    if (DMS_IS_SHARE_REFORMER) {
        cm_spin_lock(&g_cm_simulation.lock, NULL);
        status = cm_alter_config(&g_cm_simulation.config, CM_REFORMER_ID, buf, CONFIG_SCOPE_BOTH, CM_TRUE);
        if (status != CM_SUCCESS) {
            cm_spin_unlock(&g_cm_simulation.lock);
            LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to modify REFORMER_ID");
            return;
        }
        cm_spin_unlock(&g_cm_simulation.lock);
    }

    cm_spin_lock(&g_cm_simulation.lock, NULL);
    status = cm_load_config(g_cm_params, CM_PARAM_COUNT, cm_config_realpath, &g_cm_simulation.config, CM_FALSE);
    if (status != CM_SUCCESS) {
        cm_spin_unlock(&g_cm_simulation.lock);
        LOG_DEBUG_ERR("[DMS REFORM][cm_simulation]fail to load cm simulation");
    }
    dms_reform_cm_simulation_refresh();
    cm_spin_unlock(&g_cm_simulation.lock);
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
    instance_list_t *list_unknown, uint64 *online_version)
{
    cm_res_mgr_t *cm_res_mgr = &g_dms.cm_res_mgr;
    cm_res_mem_ctx_t res_mem_ctx;
    if (cm_res_init_memctx(&res_mem_ctx) != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST);
        return ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST;
    }

    cm_res_stat_ptr_t res_stat = cm_res_get_stat(cm_res_mgr, &res_mem_ctx);
    if (res_stat == NULL) {
        cm_res_uninit_memctx(&res_mem_ctx);
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST);
        return ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST;
    }

    uint32 inst_count = 0;
    if (cm_res_get_instance_count(&inst_count, cm_res_mgr, res_stat) != CM_SUCCESS
        || cm_res_get_cm_version(online_version, cm_res_mgr, res_stat) != CM_SUCCESS) {
        cm_res_free_stat(cm_res_mgr, res_stat);
        cm_res_uninit_memctx(&res_mem_ctx);
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST);
        return ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST;
    }
    for (uint32 i = 0; i < inst_count; i++) {
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
    cm_res_uninit_memctx(&res_mem_ctx);

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
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_GET_LOCK_FAILED);
        return ERRNO_DMS_REFORM_GET_LOCK_FAILED;
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