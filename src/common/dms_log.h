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
 * dms_log.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_log.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_LOG_H__
#define __DMS_LOG_H__

#include "dms_errno.h"
#include "cm_types.h"
#include "cm_log.h"
#include "cm_error.h"
#include "cm_hash_pool.h"
#ifdef __cplusplus
extern "C" {
#endif

#define DMS_DESC_HASH_BUCKET_NUM 4096
#define DMS_DESC_MAX_ENTRY_NUM   100000
#define DMS_ERROR_DESC_POOL_NAME_SIZE 64
#define DMS_ERROR_DESC_SIZE      256
#define DMS_ONE_BYTE_SIZE      1

typedef struct st_dms_error_desc {
    uint32 code; /* dms error code */
    char *desc;  /* dms error describe msg */
} dms_error_desc_t;

void dms_uninit_error_desc(void);
void  dms_get_error_desc(uint32 code, char *errmsg);
status_t dms_init_error_desc(void);

#define DMS_THROW_ERROR(error_no, ...)                                                                  \
    do {                                                                                                \
        char tmp[DMS_ERROR_DESC_SIZE];                                                                  \
        dms_get_error_desc(error_no, tmp);                                                              \
        if (tmp[0] != '\0') {                                                                           \
            cm_reset_error();                                                                           \
            cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no, tmp, ##__VA_ARGS__); \
        } else {                                                                                        \
            LOG_RUN_ERR("g_dms_error_desc is NULL, errno num = %d\n", (errno_t)error_no);                \
        }                                                                                               \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* __DMS_LOG_H__ */
