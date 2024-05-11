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
 * dms_reform_cm_res.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_cm_res.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_CM_RES_H__
#define __DMS_REFORM_CM_RES_H__

#include "dms.h"
#include "cm_config.h"
#include "cm_res_mgr.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_LIBCLIENT_PATH      "libclient.so"
#define DMS_CM_RES_NAME         "dms_res"
#define DMS_REFORMER_LOCK       "dms_reformer_lock"
#define DMS_RESOURCE_ID_BASE    6001

typedef enum en_inst_stat {
    INST_STAT_UNKNOWN = 0,
    INST_STAT_ONLINE  = 1,
    INST_STAT_OFFLINE = 2,

    INST_STAT_COUNT
} inst_stat_t;

typedef enum {
    CM_RES_SUCCESS = 0,
    CM_RES_CANNOT_DO = 1,
    CM_RES_DDB_FAILED = 2,
    CM_RES_VERSION_WRONG = 3,
    CM_RES_CONNECT_ERROR = 4,
    CM_RES_TIMEOUT = 5,
    CM_RES_NO_LOCK_OWNER = 6,
} cm_err_code;

int dms_reform_cm_res_init(void);
int dms_reform_cm_res_get_inst_stat(instance_list_t *list_online, instance_list_t *list_offline,
    instance_list_t *list_unknown, uint64 *online_version);
int dms_reform_cm_res_get_lock_owner(uint8 *owner_id);
void dms_reform_cm_res_lock(void);
void dms_reform_cm_res_unlock(void);
void dms_reform_cm_res_trans_lock(uint8 inst_id);

#ifdef DMS_TEST
#define CM_CONFIG_PATH        "CM_CONFIG_PATH"
#define CM_REFORMER_ID        "REFORMER_ID"
#define CM_BITMAP_ONLINE      "BITMAP_ONLINE"
#define CM_VERSION_ONLINE     "VERSION_ONLINE"

typedef enum en_cm_params {
    CM_PARAM_REFORMER_ID,
    CM_PARAM_BITMAP_ONLINE,
    CM_PARAM_VERSION_ONLINE,

    /* add above here */
    CM_PARAM_COUNT
} cm_params_e;

typedef struct st_cm_params {
    uint64          bitmap_online;
    uint32          reformer_id;
    uint64          online_version;
} cm_params_t;

typedef struct st_cm_simulation {
    thread_t        thread;
    spinlock_t      lock;
    config_t        config;
    cm_params_t     params;
} cm_simulation_t;

void dms_reform_cm_simulation_uninit(void);
#endif

#ifdef __cplusplus
}
#endif
#endif