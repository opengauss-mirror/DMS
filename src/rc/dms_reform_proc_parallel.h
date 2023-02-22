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
 * dms_reform_proc_parallel.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc_parallel.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_PROC_PARALLEL_H__
#define __DMS_REFORM_PROC_PARALLEL_H__

#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

int dms_reform_reconnect_parallel(void);
int dms_reform_drc_clean_parallel(void);
int dms_reform_migrate_parallel(void);
int dms_reform_repair_parallel(void);
int dms_reform_rcy_clean_parallel(void);
int dms_reform_flush_copy_parallel(void);
int dms_reform_rebuild_parallel(void);

int dms_reform_parallel_thread_init(dms_profile_t *dms_profile);
void dms_reform_parallel_thread_deinit(void);

typedef enum en_dms_reform_parallel {
    DMS_REFORM_PARALLEL_RECONNECT = 0,
    DMS_REFORM_PARALLEL_DRC_CLEAN,
    DMS_REFORM_PARALLEL_MIGRATE,
    DMS_REFORM_PARALLEL_REPAIR,
    DMS_REFORM_PARALLEL_RCY_CLEAN,
    DMS_REFORM_PARALLEL_FLUSH_COPY,
    DMS_REFORM_PARALLEL_REBUILD,

    /* add new items above here */
    DMS_REFORM_PARALLEL_COUNT,
} dms_reform_parallel_e;

typedef void(*dms_reform_parallel_assign_proc)(void);
typedef int(*dms_reform_parallel_proc)(resource_id_t *res_id, parallel_thread_t *parallel);

typedef struct st_dms_reform_parallel {
    char                                desc[CM_MAX_NAME_LEN];
    dms_reform_parallel_assign_proc     assign_proc;
    dms_reform_parallel_proc            proc;
} dms_reform_parallel_t;

#ifdef __cplusplus
}
#endif
#endif