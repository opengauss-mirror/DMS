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
 * dms_reform_drc_clean.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_clean.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc.h"

int dms_reform_full_clean(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    LOG_RUN_FUNC_ENTER;
    drc_res_pool_reinit(&ctx->lock_item_pool);
    dms_global_res_reinit(&ctx->global_buf_res);
    dms_global_res_reinit(&ctx->global_lock_res);
    dms_global_res_reinit(&ctx->global_alock_res);
#ifndef OPENGAUSS
    dms_global_res_reinit(&ctx->global_xa_res);
#endif

    // For rolling upgrade compatibility. We should update old part map before rebuild
    // Other, during rebuild step, it may be erroneously discovered that there is an old master
    dms_reform_remaster_inner();
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}