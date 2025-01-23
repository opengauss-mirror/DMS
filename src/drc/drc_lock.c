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
 * drc_lock.c
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_lock.c
 *
 * -------------------------------------------------------------------------
 */

#include "drc_lock.h"
#include "drc.h"
#include "drc_res_mgr.h"
#include "dls_msg.h"
#include "cm_debug.h"
#include "dms_error.h"
#include "dms.h"
#include "cm_timer.h"

static drc_local_lock_res_t *drc_create_local_lock_res(drc_res_bucket_t *bucket, const dms_drid_t *lock_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_local_lock_res_t *lock_res = NULL;

    lock_res = (drc_local_lock_res_t *)drc_res_pool_alloc_item(&ctx->local_lock_res.res_pool);
    if (lock_res == NULL) {
        return NULL;
    }

    lock_res->resid = *lock_id;
    lock_res->lock = 0;
    lock_res->latch_stat.lock_mode = DMS_LOCK_NULL;
    lock_res->latch_stat.shared_count = 0;
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    lock_res->latch_stat.sid = 0;
    lock_res->releasing = CM_FALSE;
    lock_res->is_reform_visit = 0;
    lock_res->modify_mode_lock = 0;
    drc_res_map_add_res(bucket, (char *)lock_res);
    return lock_res;
}

drc_local_lock_res_t *drc_get_local_resx(dms_drid_t *lock_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_bucket_t *bucket;
    drc_local_lock_res_t *lock_res;

    bucket = drc_res_map_get_bucket(&ctx->local_lock_res, (char *)lock_id, sizeof(dms_drid_t));

    cm_spin_lock(&bucket->lock, NULL);
    lock_res = (drc_local_lock_res_t *)drc_res_map_lookup(&ctx->local_lock_res,
        bucket, (char *)lock_id, sizeof(dms_drid_t));
    if (lock_res == NULL) {
        lock_res = drc_create_local_lock_res(bucket, lock_id);
        if (lock_res == NULL) {
            cm_spin_unlock(&bucket->lock);
            return NULL;
        }
    }
    cm_spin_unlock(&bucket->lock);
    return lock_res;
}

int drc_confirm_converting(void *db_handle, char* resid, uint8 type, uint8 *lock_mode)
{
    if (type == DRC_RES_LOCK_TYPE) {
        dms_drid_t *drid = (dms_drid_t *)resid;
        if (DMS_DR_IS_TABLE_TYPE(drid->type)) {
            *lock_mode = g_dms.callback.get_tlock_mode(db_handle, resid);
            return DMS_SUCCESS;
        }
        drc_local_lock_res_t *lock_res = drc_get_local_resx(drid);
        cm_spin_lock(&lock_res->modify_mode_lock, NULL);
        lock_res->is_reform_visit = CM_TRUE;
        *lock_mode = lock_res->latch_stat.lock_mode;
        cm_spin_unlock(&lock_res->modify_mode_lock);
        return DMS_SUCCESS;
    } else if (type == DRC_RES_ALOCK_TYPE) {
        *lock_mode = g_dms.callback.get_alock_mode(db_handle, resid);
        return DMS_SUCCESS;
    }
    cm_panic_log(CM_FALSE, "invalid type: %d", type);
    return DMS_SUCCESS;
}