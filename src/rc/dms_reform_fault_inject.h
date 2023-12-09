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
 * dms_reform_fault_inject.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_fault_inject.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_REFORM_FAULT_INJECT_H__
#define __DMS_REFORM_FAULT_INJECT_H__

#include "dms_reform.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DEBUG
void dms_reform_fault_inject_init(char *gsdb_home);
void dms_reform_fault_inject_deinit(void);
void dms_reform_fault_inject_before_step(dms_reform_proc_t *reform_proc);
void dms_reform_fault_inject_after_step(dms_reform_proc_t *reform_proc);

#define DMS_RFI_INIT(gsdb_home)             dms_reform_fault_inject_init(gsdb_home)
#define DMS_RFI_DEINIT                      dms_reform_fault_inject_deinit()
#define DMS_RFI_BEFORE_STEP(reform_proc)    dms_reform_fault_inject_before_step(reform_proc)
#define DMS_RFI_AFTER_STEP(reform_proc)     dms_reform_fault_inject_after_step(reform_proc)
#else
#define DMS_RFI_INIT(gsdb_home)
#define DMS_RFI_DEINIT
#define DMS_RFI_BEFORE_STEP(reform_proc)
#define DMS_RFI_AFTER_STEP(reform_proc)
#endif

#ifdef __cplusplus
}
#endif
#endif