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
 * dms_reform_judge_switch.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_judge_switch.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_JUDGE_SWITCH_H__
#define __DMS_REFORM_JUDGE_SWITCH_H__

#include "dms.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_judgement_az_demote_phase1(instance_list_t *inst_lists);
void dms_reform_judgement_az_demote_change_role(instance_list_t *inst_lists);
void dms_reform_judgement_az_demote_approve(instance_list_t *inst_lists);
void dms_reform_judgement_az_demote_phase2(instance_list_t *inst_lists);
void dms_reform_judgement_az_promote_phase1(void);
void dms_reform_judgement_az_promote_phase2(void);
void dms_reform_judgement_az_failover_promote_phase1(void);
void dms_reform_judgement_az_failover_promote_resetlog(void);
void dms_reform_judgement_az_failover_promote_phase2(void);
void dms_reform_judgement_az_switchover_info_reset(void);
bool32 dms_reform_judgement_az_switchover_check(instance_list_t *inst_lists);
bool32 dms_reform_judgement_az_failover_check(instance_list_t *inst_lists);
bool32 dms_reform_judgement_switchover_opengauss_check(instance_list_t *inst_lists);
bool32 dms_reform_judgement_failover_opengauss_check(instance_list_t *inst_lists);

#ifdef __cplusplus
}
#endif
#endif