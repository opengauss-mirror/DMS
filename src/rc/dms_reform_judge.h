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
 * dms_reform_judge.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_JUDGE_H__
#define __DMS_REFORM_JUDGE_H__

#include "cm_thread.h"
#include "dms.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_judgement_thread(thread_t *thread);
void dms_reform_update_reformer_version(uint64 start_time, uint8 inst_id);
int dms_reform_get_list_from_cm(instance_list_t *list_online, instance_list_t *list_offline);
int dms_reform_get_online_status(uint8 *online_status, uint64 *online_times, uint32 sess_id);
int dms_reform_sync_cluster_version(bool8 pushing);
char *dms_reform_get_type_desc(uint32 reform_type);
void dms_reform_bitmap_to_list(instance_list_t *list, uint64 bitmap);

typedef bool32(*dms_reform_judgement_check_proc)(instance_list_t *list);
typedef void(*dms_reform_judgement_proc)(instance_list_t *list);
typedef void(*dms_reform_judgement_print_proc)(instance_list_t *list);

typedef struct st_dms_reform_judgement_proc {
    dms_reform_judgement_check_proc     check_proc;
    dms_reform_judgement_proc           judgement_proc;
    dms_reform_judgement_print_proc     print_proc;
} dms_reform_judgement_proc_t;

#ifdef __cplusplus
}
#endif
#endif