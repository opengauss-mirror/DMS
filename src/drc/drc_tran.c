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
#include "drc_res_mgr.h"
#include "cmpt_msg_tran.h"

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
    (void)cm_atomic32_dec(&txn_res->ref_count);
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

uint16 drc_get_xa_partid(drc_global_xid_t *xid)
{
    uint8 bytes[sizeof(uint64) + DMS_MAX_XA_BASE16_GTRID_LEN + DMS_MAX_XA_BASE16_BQUAL_LEN] = { 0 };
    *(uint64 *)bytes = xid->fmt_id;
    errno_t ret = memcpy_sp(bytes + sizeof(uint64), DMS_MAX_XA_BASE16_GTRID_LEN, xid->gtrid, xid->gtrid_len);
    DMS_SECUREC_CHECK(ret);
    if (xid->bqual_len > 0) {
        ret = memcpy_sp(bytes + sizeof(uint64) + xid->gtrid_len, DMS_MAX_XA_BASE16_BQUAL_LEN, xid->bqual,
            xid->bqual_len);
        DMS_SECUREC_CHECK(ret);
    }
    uint32 bytes_size = sizeof(uint64) + xid->gtrid_len + xid->bqual_len;
    uint32 part_id = cm_hash_bytes(bytes, bytes_size, DRC_MAX_PART_NUM);
    return part_id;
}

int32 drc_get_xa_master_id(drc_global_xid_t *xid, uint8 *master_id)
{
    uint16 part_id = drc_get_xa_partid(xid);
    uint8 instance_id = DRC_PART_MASTER_ID(part_id);
    if (instance_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND;
    }

    *master_id = instance_id;
    return CM_SUCCESS;
}

int32 drc_get_xa_old_master_id(drc_global_xid_t *xid, uint8 *master_id)
{
    uint16 part_id = drc_get_xa_partid(xid);
    uint8 instance_id = DRC_PART_OLD_MASTER_ID(part_id);
    if (instance_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND;
    }

    *master_id = instance_id;
    return CM_SUCCESS;
}

int dms_check_xid_exist_remote(uint32 sess_id, uint8 owner, drc_global_xid_t *xid, bool8 *exist)
{
    dms_ask_xa_inuse_req_t req = { 0 };
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_ASK_XA_IN_USE, 0, g_dms.inst_id, owner, sess_id, CM_INVALID_ID16);
    req.head.size = (uint16)sizeof(dms_ask_xa_inuse_req_t);
    errno_t err = memcpy_sp((char *)&req.xa_xid, DMS_XA_SIZE, (char *)xid, DMS_XA_SIZE);
    if (err != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    LOG_DEBUG_INF("[TXN][%s]check owner:%d", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), owner);
    DDES_FAULT_INJECTION_CALL(DMS_FI_REQ_ASK_XA_IN_USE, MSG_REQ_ASK_XA_IN_USE);
    dms_begin_stat(sess_id, DMS_EVT_DCS_REQ_XA_IN_USE, CM_TRUE);
    int32 ret = mfc_send_data(&req.head);
    if (ret != DMS_SUCCESS) {
        dms_end_stat_ex(sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
        DMS_THROW_ERROR(ERRNO_DMS_SEND_MSG_FAILED, ret, MSG_REQ_ASK_XA_IN_USE, owner);
        return ERRNO_DMS_SEND_MSG_FAILED;
    }

    dms_message_t msg = { 0 };
    ret = mfc_get_response(req.head.ruid, &msg, DMS_WAIT_MAX_TIME);
    dms_end_stat_ex(sess_id, DMS_EVT_DCS_REQ_XA_IN_USE);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[TXN][%s]fail to get response", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_RECV_MSG_FAILED, ret, MSG_REQ_ASK_XA_IN_USE, owner);
        return ERRNO_DMS_RECV_MSG_FAILED;
    }

    if (msg.head->cmd == MSG_ACK_ERROR) {
        cm_print_error_msg_and_throw_error(msg.buffer);
        mfc_release_response(&msg);
        return ERRNO_DMS_COMMON_MSG_ACK;
    }

    CM_CHK_RESPONSE_SIZE(&msg, sizeof(dms_ask_xa_inuse_ack_t), CM_FALSE);
    dms_ask_xa_inuse_ack_t *ack = (dms_ask_xa_inuse_ack_t *)msg.buffer;
    *exist = ack->exist;
    mfc_release_response(&msg);
    return DMS_SUCCESS;
}

int dms_check_xid_exist(void *db_handle, uint32 sess_id, uint8 owner, drc_global_xid_t *xid, bool8 *exist)
{
    if (dms_dst_id_is_self(owner)) {
        *exist = g_dms.callback.xa_inuse(db_handle, (void *)xid);
        return DMS_SUCCESS;
    } else {
        return dms_check_xid_exist_remote(sess_id, owner, xid, exist);
    }
}

int32 drc_xa_create(void *db_handle, dms_session_e sess_type, uint32 sess_id, drc_global_xid_t *xid, uint8 owner_id)
{
    drc_xa_t *drc_xa = NULL;
    uint8 options = drc_build_options(CM_TRUE, sess_type, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter((char *)xid, DMS_XA_SIZE, DRC_RES_GLOBAL_XA_TYPE, options, (drc_head_t **)&drc_xa);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[%s]fail to create xa ret:%d", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), ret);
        return ret;
    }

    if (drc_xa == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH;
    }

    if (drc_xa->head.is_recycling) {
        drc_leave((drc_head_t *)drc_xa, options);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_IS_RECYCLING, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_IS_RECYCLING;
    }

    if (drc_xa->head.owner == CM_INVALID_ID8) {
        LOG_DEBUG_INF("[%s]success to create xa owner:%d",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), owner_id);
        drc_xa->head.owner = owner_id;
        drc_leave((drc_head_t *)drc_xa, options);
        return DMS_SUCCESS;
    }

    bool8 exist = CM_FALSE;
    ret = dms_check_xid_exist(db_handle, sess_id, drc_xa->head.owner, xid, &exist);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[TXN][%s]fail to check xid exist owner:%d",
            cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), drc_xa->head.owner);
        drc_leave((drc_head_t *)drc_xa, options);
        return ret;
    }
    LOG_DEBUG_INF("[TXN][%s]dms_check_xid_exist owner:%d exist:%d",
        cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE), drc_xa->head.owner, exist);

    if (exist) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        drc_leave((drc_head_t *)drc_xa, options);
        return ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS;
    }

    drc_xa->head.owner = owner_id;
    drc_leave((drc_head_t *)drc_xa, options);
    return DMS_SUCCESS;
}

int32 drc_xa_delete(drc_global_xid_t *xid)
{
    drc_xa_t *drc_xa = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);
    int ret = drc_enter((char *)xid, DMS_XA_SIZE, DRC_RES_GLOBAL_XA_TYPE, options, (drc_head_t **)&drc_xa);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (drc_xa == NULL) {
        LOG_DEBUG_ERR("[%s]drc_xa does not exist", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_XA_RES_NOT_EXISTS, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_XA_RES_NOT_EXISTS;
    }

    if (drc_xa->head.is_recycling) {
        drc_leave((drc_head_t *)drc_xa, options);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_IS_RECYCLING, cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ERRNO_DMS_DRC_IS_RECYCLING;
    }

    drc_xa->head.owner = CM_INVALID_ID8;
    drc_shift_to_tail((drc_head_t *)drc_xa);
    drc_leave((drc_head_t *)drc_xa, options);
    LOG_DEBUG_INF("[DRC][%s][drc_delete_xa_res]success", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
    return DMS_SUCCESS;
}
