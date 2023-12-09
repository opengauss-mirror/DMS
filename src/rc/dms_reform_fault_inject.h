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


#ifdef __cplusplus
extern "C" {
#endif

#ifdef _DEBUG
void dms_reform_fault_inject_init(char *gsdb_home);
void dms_reform_fault_inject_deinit(void);
void dms_reform_fault_inject_before_step(void);
void dms_reform_fault_inject_after_step(void);

#define DMS_RFI_INIT(gsdb_home)         dms_reform_fault_inject_init(gsdb_home)
#define DMS_RFI_DEINIT                  dms_reform_fault_inject_deinit()
#define DMS_RFI_BEFORE_STEP             dms_reform_fault_inject_before_step()
#define DMS_RFI_AFTER_STEP              dms_reform_fault_inject_after_step()
#else
#define DMS_RFI_INIT(gsdb_home)
#define DMS_RFI_DEINIT
#define DMS_RFI_BEFORE_STEP
#define DMS_RFI_AFTER_STEP
#endif

#ifdef __cplusplus
}
#endif
#endif