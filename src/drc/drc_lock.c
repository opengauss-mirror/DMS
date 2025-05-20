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

static drc_local_lock_res_t *drc_create_lock_resx(drc_res_bucket_t *bucket, dms_drid_t *drid, uint8 partid)
{
    drc_res_pool_t *pool = &DRC_RES_CTX->local_lock_res.res_pool;
    drc_local_lock_res_t *lock_res = (drc_local_lock_res_t *)drc_res_pool_alloc_item(pool);
    if (lock_res == NULL) {
        return NULL;
    }
    /* !!!Attention: Do not initialize lock_res's lock
     * if is allocated newly, its lock may be initialized by memset, no need to initialize here
     * if is allocated from free list, its lock may be used with others concurrently
     */
    lock_res->partid = partid;
    lock_res->resid  = *drid;
    lock_res->latch_stat.lock_mode = DMS_LOCK_NULL;
    lock_res->latch_stat.shared_count = 0;
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    lock_res->latch_stat.sid = 0;
    lock_res->releasing = CM_FALSE;
    lock_res->is_reform_visit = 0;
    lock_res->modify_mode_lock = 0;
    lock_res->version = (uint64)cm_atomic_inc(&DRC_RES_CTX->version);
    drc_res_map_add_res(bucket, (char *)lock_res);
    lock_resx_add_lru_head(lock_res);
    return lock_res;
}

bool8 drc_get_lock_resx_by_drid(dms_drid_t *drid, drc_local_lock_res_t **lock_res, uint64 *ver)
{
    drc_res_map_t *res_map = &DRC_RES_CTX->local_lock_res;
    uint32 hash_val = res_map->res_hash_func(res_map->res_type, (char *)drid, sizeof(dms_drid_t));
    drc_res_bucket_t *bucket = &res_map->buckets[hash_val % res_map->bucket_num];
    cm_spin_lock(&bucket->lock, NULL);
    *lock_res = (drc_local_lock_res_t *)drc_res_map_lookup(res_map, bucket, (char *)drid, sizeof(dms_drid_t));
    if (*lock_res == NULL) {
        *lock_res = drc_create_lock_resx(bucket, drid, (uint8)(hash_val % DRC_MAX_PART_NUM));
        if (*lock_res == NULL) {
            cm_spin_unlock(&bucket->lock);
            return CM_FALSE;
        }
    }
    *ver = (*lock_res)->version;
    cm_spin_unlock(&bucket->lock);
    return CM_TRUE;
}

int drc_confirm_converting(void *db_handle, char *resid, uint8 type, uint8 *lock_mode)
{
    if (type == DRC_RES_LOCK_TYPE) {
        dms_drid_t *drid = (dms_drid_t *)resid;
        if (DMS_DR_IS_TABLE_TYPE(drid->type)) {
            *lock_mode = g_dms.callback.get_tlock_mode(db_handle, resid);
            return DMS_SUCCESS;
        }
        uint64 ver = 0;
        drc_local_lock_res_t *lock_res = NULL;
        while (CM_TRUE) {
            if (!drc_get_lock_resx_by_drid(drid, &lock_res, &ver)) {
                cm_spin_sleep();
                continue;
            }
            cm_spin_lock(&lock_res->modify_mode_lock, NULL);
            if (lock_res->version == ver) {
                break;
            }
            cm_spin_unlock(&lock_res->modify_mode_lock);
        }
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