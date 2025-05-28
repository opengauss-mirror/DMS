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
 * dcs_dc.h
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_dc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DCS_DC_H__
#define __DCS_DC_H__

#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_THROW_AND_RETURN_IF_BCAST_ERROR(error_no, ...)                                  \
    do {                                                                                    \
        if (error_no == ERRNO_DMS_DCS_BROADCAST_FAILED) {                                   \
            cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no,     \
                dms_get_error_desc(error_no), ##__VA_ARGS__);                               \
            return ERRNO_DMS_DCS_BROADCAST_FAILED;                                          \
        }                                                                                   \
    } while (CM_FALSE)                                                                      \

void dcs_proc_broadcast_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg);
void dcs_proc_boc(dms_process_context_t *process_ctx, dms_message_t *receive_msg);

#ifdef __cplusplus
}
#endif

#endif /* __DCS_DC_H__ */
