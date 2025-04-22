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
 * cmpt_reform_proc.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_reform_proc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_REFORM_PROC_H__
#define __CMPT_REFORM_PROC_H__

#include "cmpt_msg_version.h"

#ifdef __cplusplus
extern "C" {
#endif

extern dms_reform_judgement_proc_t *g_reform_judgement_proc_map[DMS_PROTO_VER_NUMS];

#ifdef __cplusplus
}
#endif

#endif // __CMPT_REFORM_PROC_H__