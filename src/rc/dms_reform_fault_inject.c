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
 * dms_reform_fault_inject.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_fault_inject.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_fault_inject.h"
#include "dms_reform_proc.h"
#include "cm_num.h"

typedef enum en_rfi_param {
    PARAM_FAULT_INJECT_TYPE = 0,
    PARAM_FAULT_INJECT_STEP = 1,
    PARAM_FAULT_INJECT_SLEEP_TIME = 2,

    PARAM_COUNT
} rfi_param_t;

#define FAULT_INJECT_DEFAULT_SLEEP_TIME 30

static config_item_t g_rfi_params[] = {
    { "FAULT_INJECT_TYPE", CM_TRUE, CM_FALSE, "NONE", NULL, NULL, "-", "-", "STRING", NULL,
        PARAM_FAULT_INJECT_TYPE, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, FLAG_NONE, "NONE", CM_FALSE, CM_FALSE },
    { "FAULT_INJECT_STEP", CM_TRUE, CM_FALSE, "NONE", NULL, NULL, "-", "-", "STRING", NULL,
        PARAM_FAULT_INJECT_STEP, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, FLAG_NONE, "NONE", CM_FALSE, CM_FALSE },
    { "FAULT_INJECT_SLEEP_TIME", CM_TRUE, CM_FALSE, "30", NULL, NULL, "-", "-", "INT", NULL,
        PARAM_FAULT_INJECT_SLEEP_TIME, EFFECT_REBOOT, CFG_INS, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, FLAG_NONE, "NONE", CM_FALSE, CM_FALSE },
};

typedef struct st_rfi_context {
    thread_t            thread;
    config_t            config;
    char                fault_step[CM_BUFLEN_64];
    char                fault_type[CM_BUFLEN_64];
    uint32              sleep_time;
} rfi_context_t;

rfi_context_t g_rfi_context;

static void dms_reform_fault_inject_ini_create(char *ini_path)
{
    int32 file_handle = CM_INVALID_HANDLE;
    if (cm_create_file(ini_path, O_CREAT | O_RDWR, &file_handle) != CM_SUCCESS) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "[DMS FAULT INJECT]fail to create %s", ini_path);
        return;
    }
    cm_close_file(file_handle);
}

static void dms_reform_fault_inject_load_params(char *ini_path)
{
    if (cm_load_config(g_rfi_params, PARAM_COUNT, ini_path, &g_rfi_context.config, CM_FALSE) != CM_SUCCESS) {
        LOG_RUN_ERR_INHIBIT(LOG_INHIBIT_LEVEL4, "[DMS FAULT INJECT]fail to load parameter");
        return;
    }

    char *value = cm_get_config_value(&g_rfi_context.config, "FAULT_INJECT_TYPE");
    MEMS_RETVOID_IFERR(strcpy_s(g_rfi_context.fault_type, CM_BUFLEN_64, value));

    value = cm_get_config_value(&g_rfi_context.config, "FAULT_INJECT_STEP");
    MEMS_RETVOID_IFERR(strcpy_s(g_rfi_context.fault_step, CM_BUFLEN_64, value));

    value = cm_get_config_value(&g_rfi_context.config, "FAULT_INJECT_SLEEP_TIME");
    if (cm_str2uint32(value, &g_rfi_context.sleep_time) != CM_SUCCESS) {
        g_rfi_context.sleep_time = FAULT_INJECT_DEFAULT_SLEEP_TIME;
    }
}

static void dms_reform_fault_inject_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    char *gsdb_home = thread->argument;
    char ini_path[CM_FILE_NAME_BUFFER_SIZE];

#ifdef OPENGAUSS
    PRTS_RETVOID_IFERR(sprintf_s(ini_path, CM_MAX_FILE_NAME_LEN, "%s/dms_rfi.ini", gsdb_home));
#else
    PRTS_RETVOID_IFERR(sprintf_s(ini_path, CM_MAX_FILE_NAME_LEN, "%s/cfg/dms_rfi.ini", gsdb_home));
#endif

    cm_set_thread_name(DMS_REFORM_FI_THRD_NAME);
    LOG_RUN_INF("[DMS FAULT INJECT]dms_reform_fault_inject_thread start");

    while (!thread->closed) {
        if (!cm_file_exist(ini_path)) {
            dms_reform_fault_inject_ini_create(ini_path);
        }
        dms_reform_fault_inject_load_params(ini_path);
        cm_sleep(DMS_REFORM_SHORT_TIMEOUT);
    }

    LOG_RUN_INF("[DMS FAULT INJECT]dms_reform_fault_inject_thread close");
}

void dms_reform_fault_inject_init(char *gsdb_home)
{
    if (cm_create_thread(dms_reform_fault_inject_thread, 0, gsdb_home, &g_rfi_context.thread) != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS FAULT INJECT]fail to create dms_reform_fault_inject_thread");
    }
}

void dms_reform_fault_inject_deinit(void)
{
    cm_close_thread(&g_rfi_context.thread);
}

void dms_reform_fault_inject_before_step(dms_reform_proc_t *reform_proc)
{
    if (strlen(g_rfi_context.fault_step) == 0 || strlen(g_rfi_context.fault_type) == 0) {
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_step, reform_proc->desc) != 0) {
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_type, "ABORT_BEFORE_STEP") == 0) {
        LOG_RUN_WAR("[DMS FAULT INJECT]before %s, abort", reform_proc->desc);
        cm_exit(0);
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_type, "SLEEP_BEFORE_STEP") == 0) {
        LOG_RUN_WAR("[DMS FAULT INJECT]before %s, sleep %us", reform_proc->desc, g_rfi_context.sleep_time);
        cm_sleep(g_rfi_context.sleep_time * MILLISECS_PER_SECOND);
        return;
    }
}

void dms_reform_fault_inject_after_step(dms_reform_proc_t *reform_proc)
{
    if (strlen(g_rfi_context.fault_step) == 0 || strlen(g_rfi_context.fault_type) == 0) {
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_step, reform_proc->desc) != 0) {
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_type, "ABORT_AFTER_STEP") == 0) {
        LOG_RUN_WAR("[DMS FAULT INJECT]after %s, abort", reform_proc->desc);
        cm_exit(0);
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_type, "SLEEP_AFTER_STEP") == 0) {
        LOG_RUN_WAR("[DMS FAULT INJECT]after %s, sleep %us", reform_proc->desc, g_rfi_context.sleep_time);
        cm_sleep(g_rfi_context.sleep_time * MILLISECS_PER_SECOND);
        return;
    }

    if (cm_strcmpi(g_rfi_context.fault_type, "FAIL_AFTER_STEP") == 0) {
        LOG_RUN_WAR("[DMS FAULT INJECT]after %s, set reform fail", reform_proc->desc);
        reform_info_t *reform_info = DMS_REFORM_INFO;
        reform_info->reform_fail = CM_TRUE;
        return;
    }
}