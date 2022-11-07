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
 * dms_reform_preempt.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_preempt.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_PREEMPT_H__
#define __DMS_REFORM_PREEMPT_H__

#include "cm_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_MAX_FAIL_TIME_WITH_CM     30       // if DMS fail to get lock owner from CM for 30s, exit(0)

void dms_reformer_preempt_thread(thread_t *thread);

#ifdef __cplusplus
}
#endif
#endif