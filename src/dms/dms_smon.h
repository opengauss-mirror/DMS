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
 * dms_smon.h
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_smon.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_SMON_H__
#define __DMS_SMON_H__

#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

void dms_smon_entry(thread_t *thread);
bool32 dms_the_same_drc_req(drc_request_info_t *req1, drc_request_info_t *req2);

#ifdef __cplusplus
}
#endif

#endif /* __DMS_SMON_H__ */
