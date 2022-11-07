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
 * dms_cm.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_cm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_CM_H__
#define __DMS_CM_H__

#include "cm_types.h"
#include "dms.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __TO_STR(x) #x
#define __AS_STR(x) __TO_STR(x)
#define __STR_LINE__ __AS_STR(__LINE__)

#define DRC_MAX_PART_NUM (128)
#define SSL_CERT_CHK_WHICH_TIME (2)   // check the ssl certificate at 2 o'clock every day
#define SSL_CERT_CHK_FIRST (1)        // must be ensured that the inspection is only conducted once an hour
#define SSL_CERT_CHK_NOT_FIRST (2)

#define DMS_RETURN_IF_ERROR(ret)      \
    do {                              \
        int _status_ = (ret);         \
        if (_status_ != CM_SUCCESS) { \
            return _status_;          \
        }                             \
    } while (0)

#define DMS_SECUREC_CHECK(err)                                            \
    {                                                                     \
        if (SECUREC_UNLIKELY(EOK != (err))) {                             \
            LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));    \
            cm_fync_logfile();                                            \
            cm_panic(0);                                                  \
        }                                                                 \
    }

    /* Used in sprintf_s or scanf_s cluster function */
#define DMS_SECUREC_CHECK_SS(err)                                         \
    {                                                                     \
        if (SECUREC_UNLIKELY((err) == -1)) {                              \
            LOG_RUN_ERR("Secure C lib has thrown an error %d", (err));    \
            cm_fync_logfile();                                            \
            cm_panic(0);                                                 \
        }                                                                 \
    }

// break the loop if ret is not GS_SUCCESS
#define DMS_BREAK_IF_ERROR(ret)         \
    {                                   \
        if ((ret) != CM_SUCCESS) {      \
            break;                      \
        }                               \
    }

char *cm_display_pageid(char pageid[DMS_PAGEID_SIZE]);
char *cm_display_xid(char xid[DMS_XID_SIZE]);
char *cm_display_rowid(char rowid[DMS_ROWID_SIZE]);
void dms_ssl_ca_cert_expire(void);
char *cm_display_lockid(dms_drid_t *lockid);
char *cm_display_resid(char *resid, uint8 res_type);

typedef struct st_dms_worker_info {
    uint8 inst_id;
    uint32 sess_id;
} dms_worker_info_t;

#ifdef __cplusplus
}
#endif

#endif /* __DMS_CM_H__ */
