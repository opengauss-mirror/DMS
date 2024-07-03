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
 * drc_res_mgr.c
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_res_mgr.c
 *
 * -------------------------------------------------------------------------
 */

#include "drc_res_mgr.h"
#include <stdlib.h>
#include "securec.h"
#include "dms_error.h"
#include "dcs_page.h"
#include "drc_page.h"
#include "dms_reform_proc_parallel.h"
/* some global struct definition */
drc_res_ctx_t g_drc_res_ctx;

#ifndef DRC_RES_CTX
#define DRC_RES_CTX (&g_drc_res_ctx)
#endif

void drc_init_deposit_map(void)
{
    drc_res_ctx_t* ctx = DRC_RES_CTX;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        ctx->deposit_map[i] = i;
    }
}

uint8 drc_get_deposit_id(uint8 instance_id)
{
    drc_res_ctx_t* ctx = DRC_RES_CTX;
    return ctx->deposit_map[instance_id];
}

unsigned char dms_get_deposit_id(unsigned char inst_id)
{
    dms_reset_error();
    return drc_get_deposit_id(inst_id);
}

unsigned char dms_get_deposit_id_for_recovery(unsigned char inst_id)
{
    remaster_info_t* remaster_info = DMS_REMASTER_INFO;
    return remaster_info->deposit_map[inst_id];
}

static void drc_init_over2g_buffer(void* dest_addr, int c, size_t dest_size)
{
    size_t remain_size = dest_size;
    void* curr_addr = dest_addr;

    while (CM_TRUE) {
        if (remain_size < SECUREC_MEM_MAX_LEN) {
            if (memset_s(curr_addr, remain_size, c, remain_size) != EOK) {
                cm_panic(0);
            }
            break;
        }

        if (memset_s(curr_addr, SECUREC_MEM_MAX_LEN, c, SECUREC_MEM_MAX_LEN) != EOK) {
            cm_panic(0);
        }
        curr_addr = (char*)curr_addr + SECUREC_MEM_MAX_LEN;
        remain_size -= SECUREC_MEM_MAX_LEN;
    }

    return;
}

static inline void drc_add_items(drc_res_pool_t *pool, char *addr, uint32 res_size, uint32 res_num)
{
    bilist_node_t* curr_node = (bilist_node_t*)(addr);
    for (uint32 i = 0; i < res_num; i++) {
        cm_bilist_add_tail(curr_node, &pool->free_list);
        curr_node = (bilist_node_t*)((char*)curr_node + res_size);
    }
}

int32 drc_res_pool_init(drc_res_pool_t* pool, uint32 max_extend_num, uint32 res_size, uint32 res_num)
{
    uint64 sz;
    status_t ret = memset_s(pool, sizeof(drc_res_pool_t), 0, sizeof(drc_res_pool_t));
    DMS_SECUREC_CHECK(ret);

    if (res_size <= sizeof(bilist_node_t)) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL, res_size);
        return ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL;
    }

    sz = (uint64)res_size * ((uint64)res_num);
    pool->addr[0] = (char *)dms_malloc(sz);
    if (pool->addr[0] == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    drc_init_over2g_buffer(pool->addr[0], 0, sz);
    cm_bilist_init(&pool->free_list);
    pool->item_num = res_num;
    pool->used_num = 0;
    pool->item_size = res_size;
    pool->lock = 0;
    pool->inited = CM_TRUE;
    pool->extend_step = res_num;
    pool->extend_num = 1;
    pool->max_extend_num = max_extend_num;
    ret = memset_s(pool->each_pool_size, sizeof(pool->each_pool_size), 0, sizeof(pool->each_pool_size));
    DMS_SECUREC_CHECK(ret);
    pool->each_pool_size[0] = res_num;

    drc_add_items(pool, pool->addr[0], res_size, res_num);
    return DMS_SUCCESS;
}

void drc_res_pool_reinit(drc_res_pool_t *pool, uint8 thread_index, uint8 thread_num, bilist_t *temp)
{
    if (thread_index == 0) {
        pool->used_num = 0;
        cm_bilist_init(&pool->free_list);
    }
    for (uint32 i = 0; i < pool->extend_num; i++) {
        uint64 total_count = pool->each_pool_size[i];
        uint64 task_num = (total_count + thread_num - 1) / thread_num;
        uint64 task_begin = thread_index * task_num;
        uint64 task_end = MIN(task_begin + task_num, total_count);
        for (uint64 j = task_begin; j < task_end; j++) {
            bilist_node_t *node = (bilist_node_t *)(pool->addr[i] + j * pool->item_size);
            cm_bilist_node_init(node);
            cm_bilist_add_tail(node, temp);
        }
    }
}

/*
 * spin lock is held outside
 */
char *drc_res_pool_try_extend_and_alloc(drc_res_pool_t *pool)
{
    if (pool->extend_num >= pool->max_extend_num) {
        pool->res_depleted = CM_TRUE;
        return NULL;
    }

    cm_panic(pool->addr[pool->extend_num] == NULL);
    uint64 sz = (uint64)pool->extend_step * (uint64)pool->item_size;
    uint32 try_times = 0;
    while (try_times <= DRC_RES_EXTEND_TRY_TIMES && sz > 0) {
        pool->addr[pool->extend_num] = (char *)dms_malloc(sz);
        if (pool->addr[pool->extend_num] == NULL) {
            try_times++;
            continue;
        }
        break;
    }

    if (pool->addr[pool->extend_num] != NULL) {
        drc_init_over2g_buffer(pool->addr[pool->extend_num], 0, sz);
        drc_add_items(pool, pool->addr[pool->extend_num], pool->item_size, pool->extend_step);
        pool->item_num += pool->extend_step;
        pool->each_pool_size[pool->extend_num] = pool->extend_step;
        pool->extend_num++;
    }

    if (cm_bilist_empty(&pool->free_list)) {
        pool->res_depleted = CM_TRUE;
        return NULL;
    }
    char *item_addr = (char *)cm_bilist_pop_first(&pool->free_list);
    pool->used_num++;
    return item_addr;
}

void drc_res_pool_destroy(drc_res_pool_t* pool)
{
    cm_spin_lock(&pool->lock, NULL);

    if (!pool->inited) {
        return;
    }

    for (uint32 i = 0; i < pool->extend_num; i++) {
        if (pool->addr[i] != NULL) {
            DMS_FREE_PROT_PTR(pool->addr[i]);
        }
    }

    cm_bilist_init(&pool->free_list);
    pool->item_num = 0;
    pool->used_num = 0;
    pool->item_size = 0;
    pool->extend_step = 0;
    pool->extend_num = 0;
    pool->inited = CM_FALSE;
    int ret = memset_s(pool->each_pool_size, sizeof(pool->each_pool_size), 0, sizeof(pool->each_pool_size));
    DMS_SECUREC_CHECK(ret);
    cm_spin_unlock(&pool->lock);
}

char* drc_res_pool_alloc_item(drc_res_pool_t* pool)
{
    char* item_addr = NULL;

    cm_spin_lock(&pool->lock, NULL);
    if (cm_bilist_empty(&pool->free_list)) {
        item_addr = drc_res_pool_try_extend_and_alloc(pool);
        cm_spin_unlock(&pool->lock);
        return item_addr;
    }
    item_addr = (char *)cm_bilist_pop_first(&pool->free_list);
    pool->used_num++;
    cm_spin_unlock(&pool->lock);

    return item_addr;
}

void drc_res_pool_free_item(drc_res_pool_t* pool, char* res)
{
    bilist_node_t* list_node = (bilist_node_t*)res;

    cm_spin_lock(&pool->lock, NULL);
    cm_bilist_add_tail(list_node, &pool->free_list);
    pool->used_num--;
    cm_spin_unlock(&pool->lock);

    return;
}

int32 drc_res_map_init(drc_res_map_t* res_map, uint32 max_extend_num, int32 res_type, uint32 item_num,
    uint32 item_size, res_cmp_callback res_cmp, res_hash_callback res_hash)
{
    uint64 bucket_size;
    int32 ret;

    res_map->bucket_num = DMS_RES_MAP_INIT_PARAM * item_num + 1;
    bucket_size = (uint64)(res_map->bucket_num * sizeof(drc_res_bucket_t));
    res_map->buckets = (drc_res_bucket_t*)dms_malloc(bucket_size);
    if (res_map->buckets == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    drc_init_over2g_buffer(res_map->buckets, 0, bucket_size);
    ret = drc_res_pool_init(&res_map->res_pool, max_extend_num, item_size, item_num);
    if (ret != DMS_SUCCESS) {
        DMS_FREE_PROT_PTR(res_map->buckets);
        return ret;
    }

    res_map->res_type = res_type;
    res_map->res_cmp_func = res_cmp;
    res_map->res_hash_func = res_hash;
    res_map->inited = CM_TRUE;

    return DMS_SUCCESS;
}

void drc_res_map_reinit(drc_res_map_t *res_map, uint8 thread_index, uint8 thread_num, bilist_t *temp)
{
    uint64 total_count = res_map->bucket_num;
    uint64 task_num = (total_count + thread_num - 1) / thread_num;
    uint64 task_begin = thread_index * task_num;
    uint64 task_end = MIN(task_begin + task_num, total_count);
    uint64 bucket_size = (task_end - task_begin) * sizeof(drc_res_bucket_t);
    drc_init_over2g_buffer(&res_map->buckets[task_begin], 0, bucket_size);
    drc_res_pool_reinit(&res_map->res_pool, thread_index, thread_num, temp);
}

void drc_res_map_destroy(drc_res_map_t* res_map)
{
    drc_res_pool_destroy(&res_map->res_pool);
    if (res_map->buckets != NULL) {
        DMS_FREE_PROT_PTR(res_map->buckets);
    }

    res_map->buckets = NULL;
    res_map->res_cmp_func = NULL;
    res_map->bucket_num = 0;
    res_map->inited = CM_FALSE;

    return;
}

/*
 * resid is the resource handle address, len is the resource handle length.
 */
drc_res_bucket_t* drc_res_map_get_bucket(drc_res_map_t* res_map, char* resid, uint32 len)
{
    uint32 hash_val = res_map->res_hash_func(res_map->res_type, resid, len);
    return &res_map->buckets[hash_val % res_map->bucket_num];
}

static void init_buf_res(drc_buf_res_t* buf_res, char* resid, uint16 len, uint8 res_type)
{
    GS_INIT_SPIN_LOCK(buf_res->lock);
    cm_bilist_node_init(&buf_res->node);
    cm_bilist_node_init(&buf_res->part_node);
    cm_bilist_node_init(&buf_res->rebuild_node);
    buf_res->claimed_owner = CM_INVALID_ID8;
    buf_res->copy_insts = 0;
    buf_res->lock_mode = DMS_LOCK_NULL;
    buf_res->last_edp = CM_INVALID_ID8;
    buf_res->edp_map = 0;
    buf_res->lsn = 0;
    buf_res->need_recover = CM_FALSE;
    buf_res->copy_promote = DMS_COPY_PROMOTE_NONE;
    buf_res->need_flush = CM_FALSE;
    buf_res->type = res_type;
    buf_res->rebuild_type = (uint8)REFORM_ASSIST_LIST_NONE;
    buf_res->owner_lsn = 0;
    buf_res->len = len;
    buf_res->count = 0;
    buf_res->recycling = CM_FALSE;
    buf_res->is_using = CM_TRUE;
    cm_bilist_init(&buf_res->convert_q);
    init_drc_cvt_item(&buf_res->converting);
    errno_t ret = memcpy_s(buf_res->data, DMS_RESID_SIZE, resid, len);
    DMS_SECUREC_CHECK(ret);
}

static drc_buf_res_t* drc_create_buf_res(drc_res_pool_t *pool, char *resid, uint16 len, uint8 res_type,
    drc_res_bucket_t *bucket)
{
    drc_buf_res_t* buf_res = (drc_buf_res_t *)drc_res_pool_alloc_item(pool);
    if (buf_res == NULL) {
        LOG_DEBUG_WAR("[DRC][%s]buf_res create fail", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return NULL;
    }
    LOG_DEBUG_INF("[DRC][%s]buf_res create successful", cm_display_resid(resid, res_type));

    init_buf_res(buf_res, resid, len, res_type);
    drc_res_map_add_res(bucket, (char *)buf_res);
    if (res_type == DRC_RES_PAGE_TYPE) {
        drc_add_buf_res_in_part_list(buf_res);
    } else {
        drc_add_lock_res_in_part_list(buf_res);
    }
    return buf_res;
}

void drc_buf_res_set_inaccess(drc_global_res_map_t *res_map)
{
    cm_latch_x(&res_map->res_latch, g_dms.reform_ctx.sess_proc, NULL);
    res_map->drc_accessible_stage = DRC_ACCESS_STAGE_ALL_INACCESS;
    cm_unlatch(&res_map->res_latch, NULL);
}

drc_buf_res_t* drc_get_buf_res(char* resid, uint16 len, uint8 res_type, uint8 options)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(res_type);

    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, resid, len);

    cm_spin_lock(&bucket->lock, NULL);
    drc_buf_res_t* buf_res = (drc_buf_res_t *)drc_res_map_lookup(res_map, bucket, resid, len);
    if (buf_res != NULL) {
        drc_inc_buf_res_ref(buf_res);
        cm_spin_unlock(&bucket->lock);
        return buf_res;
    }

    if (!(options & DRC_RES_ALLOC)) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    buf_res = drc_create_buf_res(&res_map->res_pool, resid, len, res_type, bucket);
    if (SECUREC_UNLIKELY(buf_res == NULL)) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    drc_inc_buf_res_ref(buf_res);
    cm_spin_unlock(&bucket->lock);
    return buf_res;
}

static int drc_buf_res_latch(char *resid, uint8 res_type, uint8 options)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);

    uint8 master_id = CM_INVALID_ID8;

    if (!cm_latch_timed_s(&res_map->res_latch, 1, CM_FALSE, NULL)) {
        LOG_DEBUG_WAR("[%s][drc_buf_res_latch]fail to latch s", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    if (options & DRC_RES_CHECK_ACCESS) {
        if (res_map->drc_accessible_stage == DRC_ACCESS_STAGE_ALL_INACCESS) {
            LOG_DEBUG_WAR("[%s][drc_buf_res_latch]drc is inaccessible", cm_display_resid(resid, res_type));
            cm_unlatch(&res_map->res_latch, NULL);
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
            return ERRNO_DMS_REFORM_IN_PROCESS;
        }
        if (res_type == (uint8)DRC_RES_PAGE_TYPE && !(options & DRC_RES_RELEASE) &&
            res_map->drc_accessible_stage == PAGE_ACCESS_STAGE_REALESE_ACCESS) {
            LOG_DEBUG_WAR("[%s][drc_buf_res_latch]data is inaccessible", cm_display_resid(resid, res_type));
            cm_unlatch(&res_map->res_latch, NULL);
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
            return ERRNO_DMS_REFORM_IN_PROCESS;
        }

        if (res_type == DRC_RES_LOCK_TYPE && (options & DRC_CHECK_BIZ_SESSION) &&
            res_map->drc_accessible_stage == LOCK_ACCESS_STAGE_NON_BIZ_SESSION_ACCESS) {
            LOG_DEBUG_WAR("[%s][drc_buf_res_latch]data is inaccessible", cm_display_resid(resid, res_type));
            cm_unlatch(&res_map->res_latch, NULL);
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
            return ERRNO_DMS_REFORM_IN_PROCESS;
        }
    }

    if (options & DRC_RES_CHECK_MASTER) {
        (void)drc_get_master_id(resid, res_type, &master_id);
        if (dms_dst_id_is_self(master_id)) {
            return DMS_SUCCESS;
        }

        LOG_DEBUG_WAR("[%s][drc_buf_res_latch]master is changed to %d", cm_display_resid(resid, res_type), master_id);
        cm_unlatch(&res_map->res_latch, NULL);
        DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID, cm_display_resid(resid, res_type));
        return ERRNO_DMS_DRC_INVALID;
    }

    return DMS_SUCCESS;
}

void drc_buf_res_unlatch(uint8 res_type)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);
    cm_unlatch(&res_map->res_latch, NULL);
}

void drc_enter_buf_res_set_blocked(void)
{
    drc_global_res_map_t *buf_res_map = &g_drc_res_ctx.global_buf_res;
    drc_global_res_map_t *lock_res_map = &g_drc_res_ctx.global_lock_res;
    drc_global_res_map_t *xa_res_map = &g_drc_res_ctx.global_xa_res;

    cm_latch_x(&buf_res_map->res_latch, 0, NULL);
    cm_latch_x(&lock_res_map->res_latch, 0, NULL);
    cm_latch_x(&xa_res_map->res_latch, 0, NULL);
}

void drc_enter_buf_res_set_unblocked(void)
{
    drc_global_res_map_t *buf_res_map = &g_drc_res_ctx.global_buf_res;
    drc_global_res_map_t *lock_res_map = &g_drc_res_ctx.global_lock_res;
    drc_global_res_map_t *xa_res_map = &g_drc_res_ctx.global_xa_res;

    cm_unlatch(&xa_res_map->res_latch, NULL);
    cm_unlatch(&lock_res_map->res_latch, NULL);
    cm_unlatch(&buf_res_map->res_latch, NULL);
}

int drc_enter_buf_res(char *resid, uint16 len, uint8 res_type, uint8 options, drc_buf_res_t **buf_res)
{
    int ret = drc_buf_res_latch(resid, res_type, options);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    drc_buf_res_t *tmp_res = drc_get_buf_res(resid, len, res_type, options);
    if (tmp_res == NULL) {
        drc_buf_res_unlatch(res_type);
        *buf_res = NULL;
        return DMS_SUCCESS;
    }

    cm_spin_lock(&tmp_res->lock, NULL);
    *buf_res = tmp_res;
    return DMS_SUCCESS;
}

void drc_leave_buf_res(drc_buf_res_t *buf_res)
{
    drc_dec_buf_res_ref(buf_res);
    cm_spin_unlock(&buf_res->lock);
    drc_buf_res_unlatch(buf_res->type);
}

/*
 * spin lock is held outside of this function.
 * res is the resource management structure.
 */
void drc_res_map_add_res(drc_res_bucket_t* bucket, char* res)
{
    bilist_node_t* list_node = (bilist_node_t*)res;
    cm_bilist_add_head(list_node, &bucket->bucket_list);
}

/*
 * spin lock is held outside of this function.
 * resid is the resource handle address.
 */
char* drc_res_map_lookup(const drc_res_map_t* res_map, drc_res_bucket_t* res_bucket, char* resid, uint32 len)
{
    bilist_node_t *iter_node = cm_bilist_head(&res_bucket->bucket_list);

    while (iter_node != NULL) {
        if (res_map->res_cmp_func((char*)iter_node, resid, len)) {
            break;
        }
        iter_node = iter_node->next;
    }

    return (char*)iter_node;
}

/*
 * spin lock is held outside of this function.
 * resid is the resource handle address.
 */
void drc_res_map_del_res(drc_res_map_t* res_map, drc_res_bucket_t* bucket, char* resid, uint32 len)
{
    bilist_node_t* match_node = NULL;
    match_node = (bilist_node_t*)drc_res_map_lookup(res_map, bucket, resid, len);
    if (match_node != NULL) {
        cm_bilist_del(match_node, &bucket->bucket_list);
    }

    return;
}

void drc_destroy(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_destroy(&ctx->lock_item_pool);

    drc_res_map_destroy(&ctx->global_buf_res.res_map);
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        cm_bilist_init(&ctx->global_buf_res.res_parts[i].list);
    }

    drc_res_map_destroy(&ctx->global_lock_res.res_map);
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        cm_bilist_init(&ctx->global_lock_res.res_parts[i].list);
    }

    drc_res_map_destroy(&ctx->global_xa_res.res_map);
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        cm_bilist_init(&ctx->global_xa_res.res_parts[i].list);
    }

    drc_res_map_destroy(&ctx->local_lock_res);
    drc_res_map_destroy(&ctx->txn_res_map);
    drc_res_map_destroy(&ctx->local_txn_map);

    if (ctx->chan != NULL) {
        cm_chan_free(ctx->chan);
        ctx->chan = NULL;
    }
}

int dcs_ckpt_get_page_owner_inner(void *db_handle, uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], uint8 *id)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter_buf_res(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (buf_res == NULL) {
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        *id = CM_INVALID_ID8;
        ret = drc_get_no_owner_id(db_handle, buf_res, id);
        drc_leave_buf_res(buf_res);
        return ret;
    }

    if (edp_inst != CM_INVALID_ID8 &&
        buf_res->claimed_owner != edp_inst) {
        bitmap64_set(&buf_res->edp_map, edp_inst);
    }

    *id = buf_res->claimed_owner;
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

int drc_get_page_owner_id(uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], dms_session_e sess_type, uint8 *id)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, sess_type, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter_buf_res(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (buf_res == NULL) {
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        drc_leave_buf_res(buf_res);
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (edp_inst != CM_INVALID_ID8 && buf_res->claimed_owner != edp_inst &&
        !bitmap64_exist(&buf_res->edp_map, edp_inst)) {
        bitmap64_set(&buf_res->edp_map, edp_inst);
    }

    *id = buf_res->claimed_owner;
    drc_leave_buf_res(buf_res);
    return DMS_SUCCESS;
}

int32 drc_get_page_master_id(char *pageid, unsigned char *master_id)
{
    dms_reset_error();
    uint8  inst_id;
    uint32 part_id;

    part_id = drc_page_partid(pageid);
    inst_id = DRC_PART_MASTER_ID(part_id);
    if (inst_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND, cm_display_pageid(pageid));
        return ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND;
    }

    *master_id = inst_id;
    return DMS_SUCCESS;
}

int drc_get_page_remaster_id(char pageid[DMS_PAGEID_SIZE], uint8 *id)
{
    uint8  inst_id;
    uint32 part_id;

    part_id = drc_page_partid(pageid);
    inst_id = DRC_PART_REMASTER_ID(part_id);
    if (inst_id == CM_INVALID_ID8) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND, cm_display_pageid(pageid));
        return ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND;
    }

    *id = inst_id;
    return DMS_SUCCESS;
}

void drc_add_buf_res_in_part_list(drc_buf_res_t *buf_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    buf_res->part_id = drc_page_partid(buf_res->data);
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[buf_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_add_head(&buf_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_del_buf_res_in_part_list(drc_buf_res_t *buf_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[buf_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&buf_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_add_lock_res_in_part_list(drc_buf_res_t *lock_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    lock_res->part_id = (uint16)drc_get_lock_partid((uint8 *)lock_res->data, sizeof(dms_drid_t), DRC_MAX_PART_NUM);
    drc_part_list_t *part = &ctx->global_lock_res.res_parts[lock_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_add_head(&lock_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_del_lock_res_in_part_list(drc_buf_res_t *lock_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_lock_res.res_parts[lock_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&lock_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_buf_res_shift_to_tail(drc_buf_res_t *buf_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[buf_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&buf_res->part_node, &part->list);
    cm_bilist_add_tail(&buf_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_buf_res_shift_to_head(drc_buf_res_t *buf_res)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = &ctx->global_buf_res.res_parts[buf_res->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&buf_res->part_node, &part->list);
    cm_bilist_add_head(&buf_res->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_release_convert_q(bilist_t *convert_q)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_lock_item_t *item = NULL;

    while (!cm_bilist_empty(convert_q)) {
        item = (drc_lock_item_t *)cm_bilist_pop_first(convert_q);
        drc_res_pool_free_item(&ctx->lock_item_pool, (char*)item);
    }
}

int32 drc_get_master_id(char *resid, uint8 type, uint8 *master_id)
{
    if (type == DRC_RES_PAGE_TYPE) {
        return drc_get_page_master_id(resid, master_id);
    }

    if (type == DRC_RES_GLOBAL_XA_TYPE) {
        return drc_get_xa_master_id((drc_global_xid_t *)resid, master_id);
    }

    return drc_get_lock_master_id((dms_drid_t*)resid, master_id);
}

uint8 drc_build_options(bool32 alloc, dms_session_e sess_type, uint8 intercept_type, bool32 check_master)
{
    uint8 options = DRC_RES_NORMAL;

    if (alloc) {
        options |= DRC_RES_ALLOC;
    }

    if (intercept_type == DMS_RES_INTERCEPT_TYPE_BIZ_SESSION) {
        options |= DRC_RES_CHECK_ACCESS | DRC_CHECK_BIZ_SESSION;
    }

    switch (sess_type) {
        case DMS_SESSION_NORMAL:
            options |= DRC_RES_CHECK_ACCESS;
            break;
        case DMS_SESSION_RECOVER:
        case DMS_SESSION_REFORM:
        default:
            break;
    }

    if (check_master) {
        options |= DRC_RES_CHECK_MASTER;
    }

    return options;
}

/*
* @brief userd by server to obtain DRC entry from DMS
* @[in] tag: Uniquely identify a page
* @[out] is_found: is_found = 0 means that there are no requested buffer in the buffer pool of the cluster currently
* @[out] drc_info: Save the DRC information of the current page, 
*        including page related information in Standby which held the COPY
*/
int dms_get_drc_info(int* is_found, dv_drc_buf_info* drc_info)
{
    drc_buf_res_t *buf_res = NULL;
    int32 ret = drc_enter_buf_res(drc_info->data, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, DMS_SESSION_NORMAL, &buf_res);
    if (ret != DMS_SUCCESS) {
        drc_info = NULL;
        return ret;
    }
    if (buf_res == NULL) {
        *is_found = 0;
        return DMS_SUCCESS;
    }
    *is_found = 1;
    drc_info->claimed_owner = buf_res->claimed_owner;
    drc_info->copy_insts = buf_res->copy_insts;
    drc_info->copy_promote = buf_res->copy_promote;
    drc_info->edp_map = buf_res->edp_map;
    drc_info->in_recovery = buf_res->need_recover;
    drc_info->last_edp = buf_res->last_edp;
    drc_info->len = buf_res->len;
    drc_info->lock_mode = buf_res->lock_mode;
    drc_info->lsn = buf_res->lsn;
    drc_info->part_id = buf_res->part_id;
    drc_info->recovery_skip = buf_res->need_flush;
    drc_info->type = buf_res->type;
    drc_leave_buf_res(buf_res);

    ret = drc_get_master_id(drc_info->data, DRC_RES_PAGE_TYPE, &drc_info->master_id);
    if (drc_info->copy_insts != 0 ||
        drc_info->claimed_owner != drc_info->dms_ctx.inst_id ||
        drc_info->master_id != drc_info->dms_ctx.inst_id) {
        ret = dms_send_request_buf_info(&drc_info->dms_ctx, drc_info);
    }
    return ret;
}

static inline void find_pos_in_res_pool(uint32 *pool_index, uint32 *item_index_in_matched_pool, drc_res_pool_t *pool)
{
    for (uint32 i_extend_num = 0; i_extend_num < pool->max_extend_num; i_extend_num++) {
        if (*item_index_in_matched_pool < pool->each_pool_size[i_extend_num]) {
            *pool_index = i_extend_num;
            break;
        }
        *item_index_in_matched_pool -= pool->each_pool_size[i_extend_num];
    }
}

static inline void fill_dv_drc_local_lock_result(drc_local_lock_res_result_t *drc_local_lock_res_result,
    drc_local_lock_res_t *drc_local_lock_res)
{
    cm_spin_lock(&drc_local_lock_res->lock, NULL);
    int ret = sprintf_s(drc_local_lock_res_result->lock_id, DMS_MAX_NAME_LEN, "%u/%u/%u/%u/%u",
        (uint32)drc_local_lock_res->resid.type, (uint32)drc_local_lock_res->resid.uid,
        drc_local_lock_res->resid.oid, drc_local_lock_res->resid.index, drc_local_lock_res->resid.part);
    if (ret < EOK) {
        LOG_DEBUG_ERR("[DRC][dms_get_drc_local_lock_res]:sprintf_s err: %d", ret);
        drc_local_lock_res_result->is_valid = CM_FALSE;
        cm_spin_unlock(&drc_local_lock_res->lock);
        return;
    }

    drc_local_lock_res_result->releasing = drc_local_lock_res->releasing;
    drc_local_lock_res_result->shared_count = drc_local_lock_res->latch_stat.shared_count;
    drc_local_lock_res_result->stat = drc_local_lock_res->latch_stat.stat;
    drc_local_lock_res_result->sid = drc_local_lock_res->latch_stat.sid;
    drc_local_lock_res_result->lock_mode = drc_local_lock_res->latch_stat.lock_mode;
    cm_spin_unlock(&drc_local_lock_res->lock);
    drc_local_lock_res_result->is_valid = CM_TRUE;
}

void dms_get_drc_local_lock_res(unsigned int *vmid, drc_local_lock_res_result_t *drc_local_lock_res_result)
{
    if (!g_dms.dms_init_finish) {
        drc_local_lock_res_result->is_valid = CM_FALSE;
        return;
    }

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t *res_pool = &ctx->local_lock_res.res_pool;

    drc_local_lock_res_t *drc_local_lock_res = NULL;
    uint32 pool_index = 0;
    uint32 item_index_in_matched_pool = *vmid;
    while (*vmid < res_pool->item_num) {
        item_index_in_matched_pool = *vmid;
        find_pos_in_res_pool(&pool_index, &item_index_in_matched_pool, res_pool);
        drc_local_lock_res = (drc_local_lock_res_t*)(res_pool->addr[pool_index]
            + item_index_in_matched_pool * sizeof(drc_local_lock_res_t));
        ++*vmid;
        if (DLS_LATCH_IS_OWNER(drc_local_lock_res->latch_stat.lock_mode)) {
            fill_dv_drc_local_lock_result(drc_local_lock_res_result, drc_local_lock_res);
            return;
        }
    }
    drc_local_lock_res_result->is_valid = CM_FALSE;
}

static void drc_recycle_buf_res_cancle(drc_buf_res_t *buf_res)
{
    cm_spin_lock(&buf_res->lock, NULL);
    buf_res->recycling = CM_FALSE;
    drc_buf_res_shift_to_head(buf_res);
    cm_spin_unlock(&buf_res->lock);
}

void drc_recycle_buf_res_by_part(drc_part_list_t *part, uint32 sess_id, void *db_handle)
{
    if (part->list.count == 0) {
        return;
    }
    dms_process_context_t ctx;
    cm_spin_lock(&part->lock, NULL);
    bilist_node_t *node = cm_bilist_tail(&part->list);
    cm_spin_unlock(&part->lock);

    if (node == NULL) {
        return;
    }
    drc_buf_res_t *buf_res = BILIST_NODE_OF(drc_buf_res_t, node, part_node);
    if (!drc_chk_4_recycle(buf_res->data, buf_res->len)) {
        return;
    }
    ctx.db_handle = db_handle;
    ctx.inst_id = g_dms.inst_id;
    ctx.sess_id = sess_id;
    if (drc_recycle_buf_res(&ctx, buf_res)) {
        return;
    }
    drc_recycle_buf_res_cancle(buf_res);
}

static void drc_recycle_buf_res_single(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = NULL;

    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part = &ctx->global_buf_res.res_parts[part_id];
        drc_recycle_buf_res_by_part(part, ctx->smon_recycle_sid, ctx->smon_recycle_handle);
    }
}

static void drc_recycle_buf_res_part_start(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = NULL;
    char buf_log[CM_BUFLEN_1K] = { 0 };
    char buf_num[CM_BUFLEN_32] = { 0 };
    MEMS_RETVOID_IFERR(strcat_s(buf_log, CM_BUFLEN_1K, "[DRC recycle]every part drc count:"));
    for (uint8 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part = &ctx->global_buf_res.res_parts[part_id];
        PRTS_RETVOID_IFERR(sprintf_s(buf_num, CM_BUFLEN_32, " %u", part->list.count));
        MEMS_RETVOID_IFERR(strcat_s(buf_log, CM_BUFLEN_1K, buf_num));
    }
    LOG_DEBUG_INF(buf_log);
}

static bool32 drc_recycle_buf_res_check(bool8 has_recycled)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_res_pool_t *pool = DRC_BUF_RES_POOL;

    if (pool->res_depleted) {
        if (!has_recycled) {
            LOG_DEBUG_INF("[DRC recycle]drc pool is depleted, notify db to recycle");
            drc_recycle_buf_res_notify_db(ctx->smon_recycle_sid);
        }
    }

    cm_spin_lock(&pool->lock, NULL);
    if (pool->extend_num == pool->max_extend_num && pool->used_num > pool->item_num * DRC_RECYCLE_THRESHOLD) {
        if (!has_recycled) {
            LOG_DEBUG_INF("[DRC recycle]start, extend: %u, total: %u, used: %u",
                pool->extend_num, pool->item_num, pool->used_num);
        }
        cm_spin_unlock(&pool->lock);
        return CM_TRUE;
    }
    cm_spin_unlock(&pool->lock);

    if (has_recycled) {
        pool->res_depleted = CM_FALSE;
        LOG_DEBUG_INF("[DRC recycle]end, total: %u, used: %u", pool->item_num, pool->used_num);
        drc_recycle_buf_res_part_start();
    } else {
        LOG_DEBUG_INF("[DRC recycle]skip, extend: %u, total: %u, used: %u",
            pool->extend_num, pool->item_num, pool->used_num);
    }

    return CM_FALSE;
}

static void drc_recycle_buf_res_start(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    // use single thread when there is no parallel thread
    if (!reform_info->parallel_enable) {
        drc_recycle_buf_res_single();
        return;
    }

    // try parallel thread first, and then use single thread when fail to use parallel thread
    if (drc_recycle_buf_res_parallel() != DMS_SUCCESS) {
        drc_recycle_buf_res_single();
    }
}

void drc_recycle_buf_res_set_pause(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_lock(&ctx->smon_recycle_lock, NULL);
    LOG_RUN_INF("[DRC recycle]pausing");
}

void drc_recycle_buf_res_set_running(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_unlock(&ctx->smon_recycle_lock);
    LOG_RUN_INF("[DRC recycle]running");
}

void drc_recycle_buf_res_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bool8 has_recycled = CM_FALSE;

    ctx->smon_recycle_handle = g_dms.callback.get_db_handle(&ctx->smon_recycle_sid, DMS_SESSION_TYPE_NONE);
    cm_panic_log(ctx->smon_recycle_handle != NULL, "alloc db handle failed");

    LOG_RUN_INF("[DRC recycle]drc_recycle_buf_res_thread start");
    while (!thread->closed) {
        if (drc_recycle_buf_res_check(has_recycled)) {
            cm_spin_lock(&ctx->smon_recycle_lock, NULL);
            drc_recycle_buf_res_start();
            cm_spin_unlock(&ctx->smon_recycle_lock);
            has_recycled = CM_TRUE;
        } else {
            has_recycled = CM_FALSE;
            cm_sleep(DMS_REFORM_SHORT_TIMEOUT);
        }
    }
    LOG_RUN_INF("[DRC recycle]drc_recycle_buf_res_thread close");
}
