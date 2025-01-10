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
#include "cm_error.h"
#include "dms_stat.h"

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
#define DMS_IS_INST_SEND(bits, id) (((bits) >> (id)) & 0x1)

#define DMS_TICKS_PER_MILLISEC (uint32)20 /* 1s ~ 20000ticks on 2.6GHz 56u */

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

// break the loop if con is true
#define DMS_BREAK_IF(con) \
    {                     \
        if (con) {        \
            break;        \
        }                 \
    }

#define DMS_CONTINUE_IF(con) \
    {                        \
        if (con) {           \
            continue;        \
        }                    \
    }


char *cm_display_pageid(char pageid[DMS_PAGEID_SIZE]);
char *cm_display_xid(char xid[DMS_XID_SIZE]);
char *cm_display_rowid(char rowid[DMS_ROWID_SIZE]);
void dms_ssl_ca_cert_expire(void);
char *cm_display_lockid(dms_drid_t *lockid);
char *cm_display_alockid(alockid_t *lockid);
char *cm_display_resid(char *resid, uint8 res_type);

typedef struct st_dms_worker_info {
    uint8 inst_id;
    uint32 sess_id;
} dms_worker_info_t;

const char *dms_get_error_desc(int code);

#define DMS_THROW_ERROR(error_no, ...)                                                                      \
    do {                                                                                                    \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no,                         \
            dms_get_error_desc(error_no), ##__VA_ARGS__);                                                   \
    } while (CM_FALSE)

#ifdef __cplusplus
}
#endif

#endif /* __DMS_CM_H__ */
