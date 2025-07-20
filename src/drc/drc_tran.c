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
#include "dms_reform.h"
#include "dms_process.h"
#include "dcs_tran.h"

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
    txn_res->ref_count = 0;
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

int32 drc_enqueue_txn(void *db_handle, uint64 *xid, uint8 inst_id, dms_txn_info_t *txn_info)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_map_t *res_map = &ctx->txn_res_map;
    drc_res_bucket_t *bucket = NULL;
    drc_txn_res_t *txn_res = NULL;

    bucket = drc_res_map_get_bucket(res_map, (char *)xid, sizeof(uint64));
    cm_spin_lock(&bucket->lock, NULL);

    int32 ret = g_dms.callback.get_txn_info(db_handle, *xid, CM_FALSE, txn_info);
    if (ret != DMS_SUCCESS) {
        cm_spin_unlock(&bucket->lock);
        return ret;
    }

    if (txn_info->status == DMS_XACT_END) {
        cm_spin_unlock(&bucket->lock);
        return DMS_SUCCESS;
    }

    txn_res = (drc_txn_res_t *)drc_res_map_lookup(res_map, bucket, (char *)xid, sizeof(uint64));
    if (txn_res == NULL) {
        txn_res = drc_create_txn_res(xid, DMS_RES_TYPE_IS_TXN);
        if (txn_res == NULL) {
            cm_spin_unlock(&bucket->lock);
            return DMS_SUCCESS;
        }
    }

    bitmap64_set(&txn_res->inst_map, inst_id);
    cm_spin_unlock(&bucket->lock);
    return DMS_SUCCESS;
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
    (void)cm_atomic32_inc(&txn_res->ref_count);
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

    cm_panic_log(txn_res->ref_count > 0, "xid(%llu) ref_count(%d) is invalid", *xid, txn_res->ref_count);
    (void)cm_atomic32_inc(&txn_res->ref_count);
    if (txn_res->ref_count == 0) {
        drc_res_map_del_res(res_map, bucket, (char *)xid, sizeof(uint64));
        drc_release_txn_res(txn_res);
    }
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

static uint16 drc_get_global_xid_partid(drc_global_xid_t *global_xid)
{
    uint8 bytes[sizeof(uint64) + DMS_MAX_XA_BASE16_GTRID_LEN + DMS_MAX_XA_BASE16_BQUAL_LEN] = { 0 };
    *(uint64 *)bytes = global_xid->fmt_id;
    errno_t ret = memcpy_sp(bytes + sizeof(uint64), DMS_MAX_XA_BASE16_GTRID_LEN, global_xid->gtrid,
        global_xid->gtrid_len);
    DMS_SECUREC_CHECK(ret);
    if (global_xid->bqual_len > 0) {
        ret = memcpy_sp(bytes + sizeof(uint64) + global_xid->gtrid_len, DMS_MAX_XA_BASE16_BQUAL_LEN, global_xid->bqual,
            global_xid->bqual_len);
        DMS_SECUREC_CHECK(ret);
    }
    uint32 bytes_size = sizeof(uint64) + global_xid->gtrid_len + global_xid->bqual_len;
    uint32 part_id = cm_hash_bytes(bytes, bytes_size, DRC_MAX_PART_NUM);
    return part_id;
}

int32 drc_get_xa_master_id(drc_global_xid_t *xid, uint8 *master_id)
{
    uint16 part_id = drc_get_global_xid_partid(xid);
    uint8 instance_id = DRC_PART_MASTER_ID(part_id);
    if (instance_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND;
    }

    *master_id = instance_id;
    return CM_SUCCESS;
}

int32 drc_get_xa_remaster_id(drc_global_xid_t *xid, uint8 *master_id)
{
    uint16 part_id = drc_get_global_xid_partid(xid);
    uint8 instance_id = DRC_PART_REMASTER_ID(part_id);
    if (instance_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND;
    }

    *master_id = instance_id;
    return CM_SUCCESS;
}

static void drc_add_xa_part_list(drc_global_xa_res_t *xa_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    xa_res->part_id = drc_get_global_xid_partid(&xa_res->xid);
    drc_part_list_t *part = &ctx->global_xa_res.res_parts[xa_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_add_head(&xa_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

static void drc_del_xa_part_list(drc_global_xa_res_t *xa_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_xa_res.res_parts[xa_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&xa_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

static int32 drc_new_xa_res(drc_global_res_map_t *xa_res_map, drc_global_xid_t *global_xid, uint8 owner_id,
    uint8 undo_set_id)
{
    drc_res_map_t *res_map = &xa_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, (char *)global_xid, sizeof(drc_global_xid_t));
    drc_global_xa_res_t *xa_res = (drc_global_xa_res_t *)drc_res_pool_alloc_item(&xa_res_map->res_map.res_pool);
    if (xa_res == NULL) {
        LOG_DEBUG_ERR("[%s][drc_new_xa_res] drc global xa pool is full",
            cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_POOL_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_XA_POOL_CAPACITY_NOT_ENOUGH;
    }

    LOG_DEBUG_INF("[DRC][%s] global xa res created", cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
    xa_res->node.next = NULL;
    xa_res->node.prev = NULL;
    xa_res->owner_id = owner_id;
    xa_res->undo_set_id = undo_set_id;
    xa_res->in_recovery = CM_FALSE;
    xa_res->part_id = CM_INVALID_ID8;
    xa_res->part_node.next = NULL;
    xa_res->part_node.prev = NULL;
    errno_t ret = memcpy_sp(&xa_res->xid, sizeof(drc_global_xid_t), global_xid, sizeof(drc_global_xid_t));
    if (ret != EOK) {
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }

    cm_bilist_add_head(&xa_res->node, &bucket->bucket_list);
    drc_add_xa_part_list(xa_res);
    return DMS_SUCCESS;
}

static int32 drc_enter_xa_res_precheck(drc_global_xid_t *global_xid, drc_global_res_map_t *xa_res_map,
    bool32 check_xa_drc)
{
    if (check_xa_drc && xa_res_map->drc_accessible_stage == DRC_ACCESS_STAGE_ALL_INACCESS) {
        LOG_DEBUG_ERR("[%s][drc_enter_xa_res_precheck] XA drc is inaccessiable", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    uint8 master_id = 0XFF;
    int32 ret = drc_get_master_id((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[%s][drc_enter_xa_res_precheck] get xa mater failed", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    if (check_xa_drc && !dms_dst_id_is_self(master_id)) {
        LOG_DEBUG_ERR("[%s][drc_enter_xa_res_precheck] master is changed to %u", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE), master_id);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID, cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_INVALID;
    }

    return DMS_SUCCESS;
}

int32 drc_enter_xa_res(drc_global_xid_t *global_xid, drc_global_xa_res_t **xa_res, bool32 check_xa_drc)
{
    drc_global_res_map_t *xa_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);

    if (!cm_latch_timed_s(&xa_res_map->res_latch, 1, CM_FALSE, NULL)) {
        LOG_DEBUG_ERR("[%s][drc_enter_xa_res] failed to latch xa res map in shared mode",
            cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    int32 ret = drc_enter_xa_res_precheck(global_xid, xa_res_map, check_xa_drc);
    if (ret != DMS_SUCCESS) {
        cm_unlatch(&xa_res_map->res_latch, NULL);
        return ret;
    }

    drc_res_map_t *res_map = &xa_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, (char *)global_xid, sizeof(drc_global_xid_t));
    cm_spin_lock(&bucket->lock, NULL);
    drc_global_xa_res_t *xa = (drc_global_xa_res_t *)drc_res_map_lookup(res_map, bucket, (char *)global_xid,
        sizeof(drc_global_xid_t));
    *xa_res = xa;
    return DMS_SUCCESS;
}

void drc_leave_xa_res(drc_global_res_map_t *xa_res_map, drc_res_bucket_t *bucket)
{
    cm_spin_unlock(&bucket->lock);
    cm_unlatch(&xa_res_map->res_latch, NULL);
}

int32 drc_create_xa_res(void *db_handle, uint32 session_id, drc_global_xid_t *global_xid, uint8 owner_id,
    uint8 undo_set_id, bool32 check_xa_drc)
{
    drc_global_xa_res_t *xa_res = NULL;
    drc_global_res_map_t *xa_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_map_t *res_map = &xa_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, (char *)global_xid, sizeof(drc_global_xid_t));

    int32 ret = drc_enter_xa_res(global_xid, &xa_res, check_xa_drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (xa_res == NULL || xa_res->owner_id == CM_INVALID_ID8) {
        ret = drc_new_xa_res(xa_res_map, global_xid, owner_id, undo_set_id);
        if (ret != DMS_SUCCESS) {
            drc_leave_xa_res(xa_res_map, bucket);
            return ret;
        }

        LOG_DEBUG_INF("[DRC][%s][drc_create_xa_res]: create xa res success", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        drc_leave_xa_res(xa_res_map, bucket);
        return DMS_SUCCESS;
    }

    dms_context_t dms_ctx;
    ret = memset_sp(&dms_ctx, sizeof(dms_context_t), 0, sizeof(dms_context_t));
    if (ret != EOK) {
        drc_leave_xa_res(xa_res_map, bucket);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }

    dms_ctx.inst_id = g_dms.inst_id;
    dms_ctx.sess_id = session_id;
    dms_ctx.db_handle = db_handle;
    dms_ctx.sess_type = dms_is_recovery_session(session_id);
    ret = memcpy_sp(&dms_ctx.global_xid, sizeof(drc_global_xid_t), global_xid, sizeof(drc_global_xid_t));
    if (ret != EOK) {
        drc_leave_xa_res(xa_res_map, bucket);
        DMS_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return ret;
    }

    bool8 inuse = CM_FALSE;
    ret = dms_request_xa_inuse(&dms_ctx, xa_res->owner_id, &inuse);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[%s][drc_create_xa_res] ask xa in use or not failed", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        drc_leave_xa_res(xa_res_map, bucket);
        return ret;
    }

    if (inuse) {
        LOG_DEBUG_ERR("[%s][drc_create_xa_res] xa res already exists", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS, cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
            drc_leave_xa_res(xa_res_map, bucket);
        return ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS;
    }

    xa_res->owner_id = owner_id;
    xa_res->undo_set_id = undo_set_id;
    drc_leave_xa_res(xa_res_map, bucket);
    return DMS_SUCCESS;
}

static void drc_release_xa_res_map(drc_res_map_t *res_map, drc_global_xid_t *global_xid, drc_global_xa_res_t *xa_res)
{
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, (char *)global_xid, sizeof(drc_global_xid_t));

    /* remove xa res from part list */
    drc_del_xa_part_list(xa_res);

    /* remove xa res from hash bucket */
    cm_bilist_del(&xa_res->node, &bucket->bucket_list);

    /* free xa res to resource pool, to be reused later */
    drc_res_pool_free_item(&res_map->res_pool, (char *)xa_res);
}

int32 drc_delete_xa_res(drc_global_xid_t *global_xid, bool32 check_xa_drc)
{
    drc_global_xa_res_t *xa_res = NULL;
    drc_global_res_map_t *xa_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_map_t *res_map = &xa_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, (char *)global_xid, sizeof(drc_global_xid_t));

    int32 ret = drc_enter_xa_res(global_xid, &xa_res, check_xa_drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (xa_res == NULL) {
        LOG_DEBUG_ERR("[%s][drc_delete_xa_res] xa res does not exists", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_RES_NOT_EXISTS, cm_display_resid((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE));
        drc_leave_xa_res(xa_res_map, bucket);
        return ERRNO_DMS_DRC_XA_RES_NOT_EXISTS;
    }

    xa_res->owner_id = CM_INVALID_ID8;
    drc_release_xa_res_map(&xa_res_map->res_map, global_xid, xa_res);
    drc_leave_xa_res(xa_res_map, bucket);
    LOG_DEBUG_ERR("[DRC][%s][drc_delete_xa_res]: delete xa res success", cm_display_resid((char *)global_xid,
        DRC_RES_GLOBAL_XA_TYPE));
    return DMS_SUCCESS;
}

void drc_release_xa_by_part(drc_part_list_t *part)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_map_t *res_map = &global_res_map->res_map;
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_res_bucket_t *bucket = NULL;
    drc_global_xa_res_t *xa_res = NULL;

    while (node != NULL) {
        xa_res = DRC_RES_NODE_OF(drc_global_xa_res_t, node, part_node);
        node = BINODE_NEXT(node);
        bucket = drc_res_map_get_bucket(res_map, (char *)&xa_res->xid, sizeof(drc_global_xid_t));
        cm_spin_lock(&bucket->lock, NULL);
        drc_release_xa_res_map(res_map, &xa_res->xid, xa_res);
        cm_spin_unlock(&bucket->lock);
    }
}
