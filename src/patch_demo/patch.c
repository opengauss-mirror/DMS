/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * patch.c
 *
 * -------------------------------------------------------------------------
 */
#include "drc_page.h"
#include "cm_log.h"
#include "drc.h"
#include "drc_res_mgr.h"
#include "dms_cm.h"
#include "dms_error.h"
#include "dms_msg.h"
#include "dcs_page.h"
#include "dms_reform_proc.h"
#include "dms_reform_msg.h"
#include "dcs_dc.h"
#include "dms_msg.h"
int32 dms_request_res_internal(dms_context_t *dms_ctx, void *res, dms_lock_mode_t curr_mode, dms_lock_mode_t req_mode)
{
    LOG_RUN_INF("[HOTPATCH]hotpatch for dms");
    uint8 master_id;
    int32 ret = drc_get_master_id(dms_ctx->resid, dms_ctx->type, &master_id);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return (-1);
}
