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
 * dms_info.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_info.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_cm.h"
#include "dms_process.h"
#include "dms_reform_proc.h"
#include "dms_reform_judge.h"
#include "cm_timer.h"

static int dms_info_append_start(char *buf, unsigned int len)
{
    buf[0] = 0;
    MEMS_RETURN_IFERR(strcat_s(buf, len, "{"));
    return DMS_SUCCESS;
}

static void dms_info_append_end(char *buf, unsigned int len)
{
    uint32 str_len = (uint32)strlen(buf);
    if (str_len > 0) {
        buf[str_len - 1] = '}';
    }
}

static int dms_info_append_string(char *buf, unsigned int len, const char *key, const char *value)
{
    MEMS_RETURN_IFERR(strcat_s(buf, len, "\""));
    MEMS_RETURN_IFERR(strcat_s(buf, len, key));
    MEMS_RETURN_IFERR(strcat_s(buf, len, "\":\""));
    MEMS_RETURN_IFERR(strcat_s(buf, len, value));
    MEMS_RETURN_IFERR(strcat_s(buf, len, "\""));
    MEMS_RETURN_IFERR(strcat_s(buf, len, ","));
    return DMS_SUCCESS;
}

static int dms_info_append_uint64(char *buf, unsigned int len, const char *key, uint64 value)
{
    char tmp[CM_BUFLEN_32];

    PRTS_RETURN_IFERR(sprintf_s(tmp, CM_BUFLEN_32, "%llu", value));
    return dms_info_append_string(buf, len, key, tmp);
}

static int dms_info_append_bool(char *buf, unsigned int len, const char *key, bool32 value,
    const char *desc1, const char *desc2)
{
    if (value) {
        return dms_info_append_string(buf, len, key, desc1);
    } else {
        return dms_info_append_string(buf, len, key, desc2);
    }
}

typedef char *(get_desc_func_t)(uint32 value);

static int dms_info_append_enum(char *buf, unsigned int len, const char *key, uint32 value, get_desc_func_t get_desc)
{
    return dms_info_append_string(buf, len, key, get_desc(value));
}

static int dms_info_append_instance_list(char *buf, unsigned int len, const char *key, instance_list_t *list)
{
    uint64 bitmap = 0;
    dms_reform_list_to_bitmap(&bitmap, list);
    return dms_info_append_uint64(buf, len, key, bitmap);
}

static int dms_info_append_date(char *buf, unsigned int len, const char *key, date_t date)
{
    date_detail_t detail;
    char date_buf[CM_BUFLEN_128];

    cm_decode_date(date, &detail);
    PRTS_RETURN_IFERR(sprintf_s(date_buf, CM_BUFLEN_128, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        detail.year, detail.mon, detail.day, detail.hour, detail.min, detail.sec, detail.millisec));

    return dms_info_append_string(buf, len, key, date_buf);
}

static int dms_info_reform(reform_info_t *reform_info, share_info_t *share_info, char *buf, uint32 len, bool32 curr)
{
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "INSTANCE_ID", (uint64)g_dms.inst_id));
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "DMS_ROLE", reform_info->dms_role == DMS_ROLE_REFORMER,
        "REFORMER", "PARTNER"));
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "PROC_STATUS", (bool32)dms_reform_in_process(),
        "RUNNING", "FINISHED"));
    if (reform_info->reform_done && curr) {
        return dms_info_append_string(buf, len, "REFORM_STATUS", "FINISHED");
    }
    if (reform_info->reform_step_index == 0) {
        return dms_info_append_string(buf, len, "REFORM_STATUS", "WAITING");
    }
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "REFORM_STATUS", curr, "RUNNING", "FINISHED"));
    DMS_RETURN_IF_ERROR(dms_info_append_date(buf, len, "START_TIME", share_info->judge_time));
    DMS_RETURN_IF_ERROR(dms_info_append_enum(buf, len, "REFORM_TYPE", (uint32)share_info->reform_type,
        dms_reform_get_type_desc));
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "FULL_CLEAN", share_info->full_clean, "TRUE", "FALSE"));
    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "PROMOTE_ID", (uint64)share_info->promote_id));
        DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "DEMOTE_ID", (uint64)share_info->demote_id));
    }
    DMS_RETURN_IF_ERROR(dms_info_append_enum(buf, len, "LAST_STEP", (uint32)reform_info->last_step,
        dms_reform_get_step_desc));
    DMS_RETURN_IF_ERROR(dms_info_append_enum(buf, len, "CURR_STEP", (uint32)reform_info->current_step,
        dms_reform_get_step_desc));
    if (reform_info->current_step == DMS_REFORM_STEP_DONE_CHECK) {
        DMS_RETURN_IF_ERROR(dms_info_append_string(buf, len, "NEXT_STEP", "N/A"));
    } else {
        DMS_RETURN_IF_ERROR(dms_info_append_enum(buf, len, "NEXT_STEP", (uint32)reform_info->next_step,
            dms_reform_get_step_desc));
    }
    if (curr) {
        DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "CURR_STEP_ELASPED(us)",
            (uint64)g_timer()->now - reform_info->proc_time));
    }
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "DDL_ENABLE", reform_info->ddl_unable, "FALSE", "TRUE"));
    DMS_RETURN_IF_ERROR(dms_info_append_bool(buf, len, "FILE_ENABLE", reform_info->file_unable, "FALSE", "TRUE"));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_MES", reform_info->bitmap_mes));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_CONNECT", reform_info->bitmap_connect));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_STABLE", share_info->bitmap_stable));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_ONLINE", share_info->bitmap_online));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_RECONNECT", share_info->bitmap_reconnect));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_DISCONNECT", share_info->bitmap_disconnect));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_CLEAN", share_info->bitmap_clean));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_RECOVERY", share_info->bitmap_recovery));
    DMS_RETURN_IF_ERROR(dms_info_append_uint64(buf, len, "BITMAP_IN", share_info->bitmap_in));
    DMS_RETURN_IF_ERROR(dms_info_append_instance_list(buf, len, "BITMAP_REBUILD", &share_info->list_rebuild));
    DMS_RETURN_IF_ERROR(dms_info_append_instance_list(buf, len, "BITMAP_WITHDRAW", &share_info->list_withdraw));
    DMS_RETURN_IF_ERROR(dms_info_append_instance_list(buf, len, "BITMAP_ROLLBACK", &share_info->list_rollback));

    return DMS_SUCCESS;
}

static int dms_info_reform_current(char *buf, uint32 len)
{
    reform_info_t reform_info = g_dms.reform_ctx.reform_info;
    share_info_t share_info = g_dms.reform_ctx.share_info;

    DMS_RETURN_IF_ERROR(dms_info_append_start(buf, len));
    DMS_RETURN_IF_ERROR(dms_info_reform(&reform_info, &share_info, buf, len, CM_TRUE));
    dms_info_append_end(buf, len);

    return DMS_SUCCESS;
}

static int dms_info_reform_last(char *buf, uint32 len)
{
    reform_info_t reform_info = g_dms.reform_ctx.last_reform_info;
    share_info_t share_info = g_dms.reform_ctx.last_share_info;

    DMS_RETURN_IF_ERROR(dms_info_append_start(buf, len));
    DMS_RETURN_IF_ERROR(dms_info_reform(&reform_info, &share_info, buf, len, CM_FALSE));
    dms_info_append_end(buf, len);

    return DMS_SUCCESS;
}

int dms_info(char *buf, unsigned int len, dms_info_id_e id)
{
    buf[0] = 0;
    switch (id) {
        case DMS_INFO_REFORM_CURRENT:
            return dms_info_reform_current(buf, len);
        case DMS_INFO_REFORM_LAST:
            return dms_info_reform_last(buf, len);
        default:
            return DMS_SUCCESS;
    }
}