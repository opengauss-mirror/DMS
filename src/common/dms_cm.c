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
 * dms_cm.c
 *
 *
 * IDENTIFICATION
 *    src/common/dms_cm.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_cm.h"
#include "securec.h"
#include "dms_process.h"
#include "cm_date_to_text.h"
#include "cm_date.h"
#include "mes_metadata.h"

#ifdef __cplusplus
extern "C" {
#endif

// Displaying a hexadecimal byte requires two digits and one space, the end-of-string character need one byte
#define DMS_DISPLAY_SIZE 512 // > MAX(DMS_PAGEID_SIZE, DMS_XID_SIZE, DMS_ROWID_SIZE) * 3 + 1

#ifdef WIN32
    __declspec(thread) char g_display_buf[DMS_DISPLAY_SIZE];
#else
    __thread char g_display_buf[DMS_DISPLAY_SIZE];
#endif

static uint8 g_chk_ssl_first = 1;

char *cm_display_pageid(char pageid[DMS_PAGEID_SIZE])
{
    return g_dms.callback.display_pageid(g_display_buf, DMS_DISPLAY_SIZE, pageid);
}

char *cm_display_lockid(dms_drid_t *lockid)
{
    int ret = sprintf_s(g_display_buf, DMS_DISPLAY_SIZE, "%u/%u/%u/%u/%u",
        (uint32)lockid->type, (uint32)lockid->uid, lockid->oid, lockid->index, lockid->part);
    if (ret < 0) {
        g_display_buf[0] = '\0';
    }
    return g_display_buf;
}

char *cm_display_global_xid(drc_global_xid_t *global_xid)
{
    text_t gtrid, bqual;
    cm_str2text_safe(global_xid->gtrid, global_xid->gtrid_len, &gtrid);
    cm_str2text_safe(global_xid->bqual, global_xid->bqual_len, &bqual);
    int ret = sprintf_s(g_display_buf, DMS_DISPLAY_SIZE, "%llu.%s.", global_xid->fmt_id, T2S(&gtrid));
    if (ret < 0) {
        g_display_buf[0] = '\0';
        return g_display_buf;
    }

    unsigned int str_len = strlen(g_display_buf);
    if (bqual.len > 0) {
        ret = memcpy_sp(g_display_buf + str_len, DMS_DISPLAY_SIZE - str_len, bqual.str, bqual.len);
        if (ret != EOK) {
            g_display_buf[0] = '\0';
            return g_display_buf;
        }
    }

    g_display_buf[str_len + bqual.len] = '\0';
    return g_display_buf;
}

char *cm_display_resid(char *resid, uint8 res_type)
{
    if (res_type == DRC_RES_PAGE_TYPE) {
        return cm_display_pageid(resid);
    }

    if (res_type == DRC_RES_GLOBAL_XA_TYPE) {
        return cm_display_global_xid((drc_global_xid_t *)resid);
    }
    return cm_display_lockid((dms_drid_t *)resid);
}

char *cm_display_xid(char xid[DMS_XID_SIZE])
{
    return g_dms.callback.display_xid(g_display_buf, DMS_DISPLAY_SIZE, xid);
}

char *cm_display_rowid(char rowid[DMS_ROWID_SIZE])
{
    return g_dms.callback.display_rowid(g_display_buf, DMS_DISPLAY_SIZE, rowid);
}

void dms_ssl_ca_cert_expire(void)
{
    date_detail_t detail;
    cm_now_detail(&detail);
    if ((detail.hour == (uint8)SSL_CERT_CHK_WHICH_TIME) && (g_chk_ssl_first == (uint8)SSL_CERT_CHK_FIRST)) {
        g_chk_ssl_first = (uint8)SSL_CERT_CHK_NOT_FIRST;
        (void)mes_chk_ssl_cert_expire();
    } else if (detail.hour != (uint8)SSL_CERT_CHK_WHICH_TIME) {
        g_chk_ssl_first = (uint8)SSL_CERT_CHK_FIRST;
    }
}

#ifdef __cplusplus
}
#endif