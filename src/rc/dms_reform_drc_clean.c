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
#include "dms_reform_msg.h"
#include "drc_res_mgr.h"
#include "dms_error.h"
#include "drc_page.h"
#include "dms_reform_judge.h"
#include "dcs_page.h"
#include "dms_reform_health.h"
#include "cm_timer.h"
#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_xa.h"
#include "dms_reform_fault_inject.h"

void dms_reform_full_clean_init_assist(full_clean_assist_t *assist)
{
    cm_bilist_init(&assist->temp_convert_q);
    cm_bilist_init(&assist->temp_page);
    cm_bilist_init(&assist->temp_lock);
    cm_bilist_init(&assist->temp_alock);
    cm_bilist_init(&assist->temp_xa);
}

void dms_reform_full_clean_reinit(uint8 thread_index, uint8 thread_num, full_clean_assist_t *assist)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_reinit(&ctx->lock_item_pool, thread_index, thread_num, &assist->temp_convert_q);
    dms_global_res_reinit(&ctx->global_buf_res, thread_index, thread_num, &assist->temp_page);
    dms_global_res_reinit(&ctx->global_lock_res, thread_index, thread_num, &assist->temp_lock);
    dms_global_res_reinit(&ctx->global_alock_res, thread_index, thread_num, &assist->temp_alock);
#ifndef OPENGAUSS
    dms_global_res_reinit(&ctx->global_xa_res, thread_index, thread_num, &assist->temp_xa);
#endif
}

void dms_reform_full_clean_concat_free_list(full_clean_assist_t *assist)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_bilist_concat(&ctx->lock_item_pool.free_list, &assist->temp_convert_q);
    LOG_DEBUG_INF("[FULL_CLEAN]convert_q free_list:%u", ctx->lock_item_pool.free_list.count);
    cm_bilist_concat(&ctx->global_buf_res.res_map.res_pool.free_list, &assist->temp_page);
    LOG_DEBUG_INF("[FULL_CLEAN]page drc free_list:%u", ctx->global_buf_res.res_map.res_pool.free_list.count);
    cm_bilist_concat(&ctx->global_lock_res.res_map.res_pool.free_list, &assist->temp_lock);
    LOG_DEBUG_INF("[FULL_CLEAN]lock drc free_list:%u", ctx->global_lock_res.res_map.res_pool.free_list.count);
    cm_bilist_concat(&ctx->global_alock_res.res_map.res_pool.free_list, &assist->temp_alock);
    LOG_DEBUG_INF("[FULL_CLEAN]alock drc free_list:%u", ctx->global_alock_res.res_map.res_pool.free_list.count);
#ifndef OPENGAUSS
    cm_bilist_concat(&ctx->global_xa_res.res_map.res_pool.free_list, &assist->temp_xa);
    LOG_DEBUG_INF("[FULL_CLEAN]xa drc free_list:%u", ctx->global_xa_res.res_map.res_pool.free_list.count);
#endif
}

int dms_reform_full_clean(void)
{
    full_clean_assist_t assist;
    LOG_RUN_FUNC_ENTER;
    dms_reform_full_clean_init_assist(&assist);
    dms_reform_full_clean_reinit(0, 1, &assist);
    dms_reform_full_clean_concat_free_list(&assist);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}