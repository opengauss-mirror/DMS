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
 * dms_reform_alock.h
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_alock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_REFORM_ALOCK_H__
#define __DMS_REFORM_ALOCK_H__

#include "dms_reform.h"
#include "dms_reform_msg.h"

#ifdef __cplusplus
extern "C" {
#endif
// rebuild
int dms_reform_rebuild_alock(void *handle, uint8 thread_index, uint8 thread_num);
void dms_reform_proc_req_alock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg);

// validate
int dms_reform_validate_alock(void *handle, uint8 thread_index, uint8 thread_num);
void dms_reform_proc_req_alock_validate(dms_process_context_t *ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif
#endif