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
 * dms_reform_health.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_health.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_HEALTH_H__
#define __DMS_REFORM_HEALTH_H__

#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_reform_health_thread(thread_t *thread);
void dms_reform_health_set_running(void);
void dms_reform_health_set_pause(void);
#ifdef OPENGAUSS
void dms_reform_handle_fail_in_special_scenario(void);
#endif

#define DMS_REFORM_HEALTH_TRIGGER_DYN       60

#ifdef __cplusplus
}
#endif
#endif