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
 * drc_tran.c
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_tran.c
 *
 * -------------------------------------------------------------------------
 */

#include "drc_tran.h"
#include "drc.h"
#include "cm_thread.h"
#include "dms_error.h"

#define TX_WAIT_INTERVAL      5  // in milliseconds

static drc_res_map_t *get_txn_res_map(dms_res_type_e res_type)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    if (res_type == DMS_RES_TYPE_IS_TXN) {
        return &ctx->txn_res_map;
    } else if (res_type == DMS_RES_TYPE_IS_LOCAL_TXN) {
        return &ctx->local_txn_map;
    }

    cm_panic(0);
    return NULL;
}

static void init_txn_res(drc_txn_res_t *txn_res, const uint64 *xid, dms_res_type_e res_type)
{
    txn_res->res_type = res_type;
    txn_res->res_id = *xid;
    txn_res->inst_map = 0;
    /* note: DMS_RES_TYPE_IS_TXN resource doesn't need condition variable to awake someone */
    if (!txn_res->is_cond_inited && (res_type == DMS_RES_TYPE_IS_LOCAL_TXN)) {
        cm_init_cond(&txn_res->cond);
        txn_res->is_cond_inited = CM_TRUE;
    }
}

drc_txn_res_t *drc_create_txn_res(uint64 *xid, dms_res_type_e res_type)
{
    drc_txn_res_t *txn_res = NULL;
    drc_res_bucket_t *bucket = NULL;
    drc_res_map_t *res_map = NULL;

    res_map = get_txn_res_map(res_type);
    CM_ASSERT(res_map != NULL);
    txn_res = (drc_txn_res_t *)drc_res_pool_alloc_item(&res_map->res_pool);
    if (txn_res == NULL) {
        return NULL;
    }
    init_txn_res(txn_res, xid, res_type);

    /* note: bucket lock needs to be held outside this function */
    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    drc_res_map_add_res(bucket, (char *)txn_res);

    return txn_res;
}

void drc_release_txn_res(drc_txn_res_t *txn_res)
{
    drc_res_map_t *res_map = get_txn_res_map(txn_res->res_type);
    CM_ASSERT(res_map != NULL);
    drc_res_pool_free_item(&res_map->res_pool, (char *)txn_res);
}

void drc_enqueue_txn(uint64 *xid, uint8 inst_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->txn_res_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;

    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)xid, sizeof(uint64));
    if (txn_res == NULL) {
        txn_res = drc_create_txn_res(xid, DMS_RES_TYPE_IS_TXN);
        if (txn_res == NULL) {
            cm_spin_unlock(&bucket->lock);
            return;
        }
    }

    bitmap64_set(&txn_res->inst_map, inst_id);
    cm_spin_unlock(&bucket->lock);
}

bool8 drc_local_txn_wait(uint64 *xid)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->local_txn_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;

    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)xid, sizeof(uint64));
    if (txn_res == NULL) {
        txn_res = drc_create_txn_res(xid, DMS_RES_TYPE_IS_LOCAL_TXN);
        if (txn_res == NULL) {
            cm_spin_unlock(&bucket->lock);
            return CM_FALSE;
        }
    }
    cm_spin_unlock(&bucket->lock);

    bool8 ret = (bool8)cm_wait_cond(&txn_res->cond, TX_WAIT_INTERVAL);
    if (ret != CM_TRUE) {
        return CM_FALSE;
    }
    return CM_TRUE;
}

void drc_local_txn_recycle(uint64 *xid)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->local_txn_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;

    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)xid, sizeof(uint64));
    if (txn_res == NULL) {
        cm_spin_unlock(&bucket->lock);
        return;
    }
    drc_res_map_del_res(res_map, bucket, (char *)xid, sizeof(uint64));
    drc_release_txn_res(txn_res);
    cm_spin_unlock(&bucket->lock);
}

void drc_local_txn_awake(uint64 *xid)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->local_txn_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;

    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);
    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)xid, sizeof(uint64));
    if (txn_res == NULL) {
        cm_spin_unlock(&bucket->lock);
        return;
    }
    cm_release_cond(&txn_res->cond);
    cm_spin_unlock(&bucket->lock);
}