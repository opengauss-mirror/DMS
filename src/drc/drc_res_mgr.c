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
    pool->can_extend = CM_TRUE;
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
static bool8 drc_res_pool_extend(drc_res_pool_t *pool)
{
    cm_panic(pool->addr[pool->extend_num] == NULL);
    uint64 sz = (uint64)pool->extend_step * (uint64)pool->item_size;
    pool->addr[pool->extend_num] = (char *)dms_malloc(sz);
    if (pool->addr[pool->extend_num] == NULL) {
        pool->can_extend = CM_FALSE;
        return CM_FALSE;
    }
    drc_init_over2g_buffer(pool->addr[pool->extend_num], 0, sz);
    drc_add_items(pool, pool->addr[pool->extend_num], pool->item_size, pool->extend_step);
    pool->item_num += pool->extend_step;
    pool->each_pool_size[pool->extend_num] = pool->extend_step;
    pool->extend_num++;
    pool->can_extend = (pool->extend_num < pool->max_extend_num);
    return CM_TRUE;
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
    cm_spin_lock(&pool->lock, NULL);
    if (cm_bilist_empty(&pool->free_list) &&
        (pool->extend_num >= pool->max_extend_num || !drc_res_pool_extend(pool))) {
        cm_spin_unlock(&pool->lock);
        return NULL;
    }
    char *item_addr = (char *)cm_bilist_pop_first(&pool->free_list);
    pool->used_num++;
    cm_spin_unlock(&pool->lock);
    errno_t err = memset_s(item_addr, pool->item_size, 0, pool->item_size);
    DMS_SECUREC_CHECK(err);
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

static void drc_init(drc_head_t *drc, char *resid, uint16 len, uint8 res_type)
{
    // init drc_head
    drc->type = res_type;
    drc->owner = CM_INVALID_ID8;
    drc->is_using = CM_TRUE;
    drc->len = len;
    init_drc_cvt_item(&drc->converting);

    // memory copy resid
    errno_t ret = memcpy_s(DRC_DATA(drc), len, resid, len);
    DMS_SECUREC_CHECK(ret);

    // init drc_page
    if (res_type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        drc_page->last_edp = CM_INVALID_ID8;
        drc_page->seq = 0;
    }
}

uint16 drc_get_partid(drc_head_t *drc)
{
    switch (drc->type) {
        case DRC_RES_PAGE_TYPE:
            return drc_page_partid(DRC_DATA(drc));
        case DRC_RES_LOCK_TYPE:
            return drc_get_lock_partid(DRC_DATA(drc), DMS_DRID_SIZE, DRC_MAX_PART_NUM);
        case DRC_RES_ALOCK_TYPE:
            return drc_get_lock_partid(DRC_DATA(drc), DMS_ALOCKID_SIZE, DRC_MAX_PART_NUM);
        default:
            cm_panic_log(CM_FALSE, "invalid type when get partid");
            return 0;
    }
}

void drc_add_into_part_list(drc_head_t *drc)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(drc->type);
    drc->part_id = drc_get_partid(drc);
    drc_part_list_t *part = &res_map->res_parts[drc->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_add_head(&drc->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

static inline void drc_remove_from_part_list(drc_head_t *drc)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(drc->type);
    drc_part_list_t *part = &res_map->res_parts[drc->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&drc->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

drc_head_t *drc_create(drc_res_pool_t *pool, char *resid, uint16 len, uint8 res_type, drc_res_bucket_t *bucket)
{
    drc_head_t *drc = (drc_head_t *)drc_res_pool_alloc_item(pool);
    if (drc == NULL) {
        LOG_DEBUG_WAR("[DRC][%s]drc create fail", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return NULL;
    }
    LOG_DEBUG_INF("[DRC][%s]drc create successful", cm_display_resid(resid, res_type));

    drc_init(drc, resid, len, res_type);
    drc_res_map_add_res(bucket, (char *)drc);
    drc_add_into_part_list(drc);

    return drc;
}

void drc_buf_res_set_inaccess(drc_global_res_map_t *res_map)
{
    cm_latch_x(&res_map->res_latch, g_dms.reform_ctx.sess_proc, NULL);
    res_map->drc_accessible_stage = DRC_ACCESS_STAGE_ALL_INACCESS;
    cm_unlatch(&res_map->res_latch, NULL);
}

drc_head_t *drc_find_or_create(char* resid, uint16 len, uint8 res_type, uint8 options)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(res_type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, resid, len);

    cm_spin_lock(&bucket->lock, NULL);
    drc_head_t *drc = (drc_head_t *)drc_res_map_lookup(res_map, bucket, resid, len);
    if (drc != NULL) {
        drc_inc_ref_count(drc);
        cm_spin_unlock(&bucket->lock);
        return drc;
    }

    if (!(options & DRC_RES_ALLOC)) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    drc = drc_create(&res_map->res_pool, resid, len, res_type, bucket);
    if (SECUREC_UNLIKELY(drc == NULL)) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    drc_inc_ref_count(drc);
    cm_spin_unlock(&bucket->lock);
    return drc;
}

int drc_latch(char *resid, uint8 res_type, uint8 options)
{
    if (!(options & DRC_RES_CHECK_ACCESS)) {
        return DMS_SUCCESS;
    }

    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);
    if (!cm_latch_timed_s(&res_map->res_latch, 1, CM_FALSE, NULL)) {
        LOG_DEBUG_WAR("[%s][drc_latch]fail to latch s", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    return DMS_SUCCESS;
}

void drc_unlatch(uint8 res_type, uint8 options)
{
    if (!(options & DRC_RES_CHECK_ACCESS)) {
        return;
    }

    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);
    cm_unlatch(&res_map->res_latch, NULL);
}

int drc_enter_check_access(char *resid, uint8 res_type, uint8 options)
{
    if (!(options & DRC_RES_CHECK_ACCESS)) {
        return DMS_SUCCESS;
    }

    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);
    if (res_map->drc_accessible_stage == DRC_ACCESS_STAGE_ALL_INACCESS) {
        LOG_DEBUG_WAR("[%s][drc_enter_check_access]drc is inaccessible", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    if (res_type == (uint8)DRC_RES_PAGE_TYPE && !(options & DRC_RES_RELEASE) &&
        res_map->drc_accessible_stage == PAGE_ACCESS_STAGE_REALESE_ACCESS) {
        LOG_DEBUG_WAR("[%s][drc_enter_check_access]data is inaccessible", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    if (res_type == DRC_RES_LOCK_TYPE && (options & DRC_CHECK_BIZ_SESSION) &&
        res_map->drc_accessible_stage == LOCK_ACCESS_STAGE_NON_BIZ_SESSION_ACCESS) {
        LOG_DEBUG_WAR("[%s][drc_enter_check_access]data is inaccessible", cm_display_resid(resid, res_type));
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
        return ERRNO_DMS_REFORM_IN_PROCESS;
    }

    return DMS_SUCCESS;
}

int drc_enter_check_master(char *resid, uint8 res_type, uint8 options)
{
    if (!(options & DRC_RES_CHECK_MASTER)) {
        return DMS_SUCCESS;
    }

    uint8 master_id = CM_INVALID_ID8;
    int ret = drc_get_master_id(resid, res_type, &master_id);
    DMS_RETURN_IF_ERROR(ret);

    if (dms_dst_id_is_self(master_id)) {
        return DMS_SUCCESS;
    }

    LOG_DEBUG_WAR("[%s][drc_enter_check_master]master is %d", cm_display_resid(resid, res_type), master_id);
    DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID, cm_display_resid(resid, res_type));
    return ERRNO_DMS_DRC_INVALID;
}

void drc_enter_buf_res_set_blocked(void)
{
    drc_global_res_map_t *buf_res_map = &g_drc_res_ctx.global_buf_res;
    drc_global_res_map_t *lock_res_map = &g_drc_res_ctx.global_lock_res;
    drc_global_res_map_t *xa_res_map = &g_drc_res_ctx.global_xa_res;
    drc_global_res_map_t *alock_res_map = &g_drc_res_ctx.global_alock_res;

    cm_latch_x(&buf_res_map->res_latch, 0, NULL);
    cm_latch_x(&lock_res_map->res_latch, 0, NULL);
    cm_latch_x(&xa_res_map->res_latch, 0, NULL);
    cm_latch_x(&alock_res_map->res_latch, 0, NULL);
}

void drc_enter_buf_res_set_unblocked(void)
{
    drc_global_res_map_t *buf_res_map = &g_drc_res_ctx.global_buf_res;
    drc_global_res_map_t *lock_res_map = &g_drc_res_ctx.global_lock_res;
    drc_global_res_map_t *xa_res_map = &g_drc_res_ctx.global_xa_res;
    drc_global_res_map_t *alock_res_map = &g_drc_res_ctx.global_alock_res;

    cm_unlatch(&xa_res_map->res_latch, NULL);
    cm_unlatch(&lock_res_map->res_latch, NULL);
    cm_unlatch(&buf_res_map->res_latch, NULL);
    cm_unlatch(&alock_res_map->res_latch, NULL);
}

int drc_enter_check(char *resid, uint8 res_type, uint8 options)
{
    int ret = drc_latch(resid, res_type, options);
    DMS_RETURN_IF_ERROR(ret);

    ret = drc_enter_check_access(resid, res_type, options);
    if (ret != DMS_SUCCESS) {
        drc_unlatch(res_type, options);
        return ret;
    }

    ret = drc_enter_check_master(resid, res_type, options);
    if (ret != DMS_SUCCESS) {
        drc_unlatch(res_type, options);
        return ret;
    }

    return DMS_SUCCESS;
}

void try_drc_page_inc_seq(drc_head_t *drc)
{
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *page_drc = (drc_page_t *)drc;
        page_drc->seq++;
    }
}

int drc_enter(char *resid, uint16 len, uint8 res_type, uint8 options, drc_head_t **drc)
{
    int ret = drc_enter_check(resid, res_type, options);
    DMS_RETURN_IF_ERROR(ret);

    *drc = drc_find_or_create(resid, len, res_type, options);
    if ((*drc) == NULL) {
        drc_unlatch(res_type, options);
        return DMS_SUCCESS;
    }

    cm_spin_lock(&(*drc)->lock, NULL);
    try_drc_page_inc_seq(*drc);
    return DMS_SUCCESS;
}

void drc_leave(drc_head_t *drc, uint8 options)
{
    uint8 res_type = drc->type;
    drc_dec_ref_count(drc);
    cm_spin_unlock(&drc->lock);
    drc_unlatch(res_type, options);
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

    drc_res_map_destroy(&ctx->global_alock_res.res_map);
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        cm_bilist_init(&ctx->global_alock_res.res_parts[i].list);
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
    drc_page_t *drc_page = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, (drc_head_t **)&drc_page);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (drc_page == NULL) {
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (drc_page->head.owner == CM_INVALID_ID8) {
        *id = CM_INVALID_ID8;
        ret = drc_get_no_owner_id(db_handle, (drc_head_t *)drc_page, id);
        drc_leave((drc_head_t *)drc_page, options);
        return ret;
    }

    if (edp_inst != CM_INVALID_ID8 &&
        drc_page->head.owner != edp_inst) {
        bitmap64_set(&drc_page->edp_map, edp_inst);
    }

    *id = drc_page->head.owner;
    drc_leave((drc_head_t *)drc_page, options);
    return DMS_SUCCESS;
}

int drc_get_page_owner_id(uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], dms_session_e sess_type, uint8 *id)
{
    drc_page_t *drc_page = NULL;
    uint8 options = drc_build_options(CM_FALSE, sess_type, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(pageid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, (drc_head_t **)&drc_page);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (drc_page == NULL) {
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (drc_page->head.owner == CM_INVALID_ID8) {
        drc_leave((drc_head_t *)drc_page, options);
        *id = CM_INVALID_ID8;
        return DMS_SUCCESS;
    }

    if (edp_inst != CM_INVALID_ID8 && drc_page->head.owner != edp_inst &&
        !bitmap64_exist(&drc_page->edp_map, edp_inst)) {
        bitmap64_set(&drc_page->edp_map, edp_inst);
    }

    *id = drc_page->head.owner;
    drc_leave((drc_head_t *)drc_page, options);
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

void drc_shift_to_tail(drc_head_t *drc)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(drc->type);
    drc_part_list_t *part = &res_map->res_parts[drc->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&drc->part_node, &part->list);
    cm_bilist_add_tail(&drc->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

void drc_shift_to_head(drc_head_t *drc)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(drc->type);
    drc_part_list_t *part = &res_map->res_parts[drc->part_id];
    cm_spin_lock(&part->lock, NULL);
    cm_bilist_del(&drc->part_node, &part->list);
    cm_bilist_add_head(&drc->part_node, &part->list);
    cm_spin_unlock(&part->lock);
}

static inline void drc_release_convert_q(bilist_t *convert_q)
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
    switch (type) {
        case DRC_RES_PAGE_TYPE:
            return drc_get_page_master_id(resid, master_id);
        case DRC_RES_GLOBAL_XA_TYPE:
            return drc_get_xa_master_id((drc_global_xid_t *)resid, master_id);
        case DRC_RES_LOCK_TYPE:
            return drc_get_lock_master_id(resid, DMS_DRID_SIZE, master_id);
        case DRC_RES_ALOCK_TYPE:
            return drc_get_lock_master_id(resid, DMS_ALOCKID_SIZE, master_id);
        default:
            return CM_INVALID_ID8;
    }
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
    drc_page_t *drc_page = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);

    uint32 count = 0;
    int32 ret;
    while (count < DMS_GET_DRC_INFO_COUNT) {
        ret = drc_enter(drc_info->data, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, (drc_head_t **)&drc_page);
        if (ret != DMS_SUCCESS) {
            drc_info = NULL;
            return ret;
        }
        if (drc_page == NULL) {
            *is_found = 0;
            return DMS_SUCCESS;
        }
        if (drc_page->head.owner != CM_INVALID_ID8) {
            *is_found = 1;
            drc_info->claimed_owner = drc_page->head.owner;
            drc_info->copy_insts = drc_page->head.copy_insts;
            drc_info->copy_promote = 0;
            drc_info->edp_map = drc_page->edp_map;
            drc_info->in_recovery = drc_page->need_recover;
            drc_info->last_edp = drc_page->last_edp;
            drc_info->len = drc_page->head.len;
            drc_info->lock_mode = drc_page->head.lock_mode;
            drc_info->lsn = drc_page->last_edp_lsn;
            drc_info->part_id = drc_page->head.part_id;
            drc_info->recovery_skip = drc_page->need_flush;
            drc_info->type = drc_page->head.type;
            drc_leave((drc_head_t *)drc_page, options);
            break;
        }
        drc_leave((drc_head_t *)drc_page, options);
        cm_sleep(DMS_GET_DRC_INFO_SLEEP_TIME);
        count++;
    }

    if (count == DMS_GET_DRC_INFO_COUNT) {
        LOG_DEBUG_WAR("[DRC][%s] get drc info timeout", cm_display_resid(drc_info->data, drc_page->head.type));
        return DMS_ERROR;
    }

    LOG_DEBUG_INF("[DRC][%s] get drc info: claimed_owner = %d, copy_insts = %llu, master_id = %d",
        cm_display_resid(drc_info->data, drc_page->head.type), drc_info->claimed_owner, drc_info->copy_insts,
        drc_info->master_id);

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
        *item_index_in_matched_pool -= (uint32)pool->each_pool_size[i_extend_num];
    }
}

static inline void fill_dv_drc_local_lock_result(drc_local_lock_res_result_t *drc_local_lock_res_result,
    drc_local_lock_res_t *drc_local_lock_res)
{
    cm_spin_lock(&drc_local_lock_res->lock, NULL);
    int ret = sprintf_s(drc_local_lock_res_result->lock_id, DMS_MAX_NAME_LEN, "%d/%d/%llu/%u/%u",
        drc_local_lock_res->resid.type, drc_local_lock_res->resid.uid,
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

void drc_release(drc_head_t *drc, drc_res_map_t *drc_res_map, drc_res_bucket_t *bucket)
{
    // remove convert_q
    drc_release_convert_q(&drc->convert_q);

    // remove drc from part list
    drc_remove_from_part_list(drc);

    // remove drc from hash bucket
    drc_res_map_del_res(drc_res_map, bucket, DRC_DATA(drc), drc->len);

    // free drc to resource pool, to be reused later
    drc_res_pool_free_item(&drc_res_map->res_pool, (char*)drc);
    drc->is_using = CM_FALSE;
}

static bool8 drc_recycle(dms_process_context_t *ctx, drc_global_res_map_t *global_res, drc_head_t *drc, uint64 seq)
{
    if (drc->copy_insts > 0 && dms_invalidate_share_copy(ctx, DRC_DATA(drc), drc->len, drc->type,
        drc->copy_insts, DMS_SESSION_NORMAL, CM_FALSE, CM_FALSE, seq) != DMS_SUCCESS) {
        LOG_DEBUG_WAR("[DRC recycle][%s]fail to release share copy: %llu",
            cm_display_resid(DRC_DATA(drc), drc->type), drc->copy_insts);
        return CM_FALSE;
    }
    
    if (drc->owner != CM_INVALID_ID8 && dms_invalidate_ownership(ctx, DRC_DATA(drc), drc->len,
        drc->type, DMS_SESSION_NORMAL, drc->owner, seq) != DMS_SUCCESS) {
        LOG_DEBUG_WAR("[DRC recycle][%s]fail to release owner: %d",
            cm_display_resid(DRC_DATA(drc), drc->type), drc->owner);
        return CM_FALSE;
    }

    drc_res_bucket_t* bucket = drc_res_map_get_bucket(&global_res->res_map, DRC_DATA(drc), drc->len);
    cm_spin_lock(&bucket->lock, NULL);
    while (drc->ref_count > 0) {
        cm_spin_unlock(&bucket->lock);
        cm_sleep(1);
        cm_spin_lock(&bucket->lock, NULL);
    }
    drc_release(drc, &global_res->res_map, bucket);
    cm_spin_unlock(&bucket->lock);
    return CM_TRUE;
}

static bool8 drc_chk_4_recycle(drc_head_t *drc, uint64 *seq)
{
    cm_spin_lock(&drc->lock, NULL);
    if (drc->converting.req_info.inst_id != CM_INVALID_ID8) {
        cm_spin_unlock(&drc->lock);
        return CM_FALSE;
    }

    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        *seq = drc_page->seq;
        if (drc_page->edp_map != 0 || drc_page->need_flush || drc_page->need_recover) {
            cm_spin_unlock(&drc->lock);
            return CM_FALSE;
        }
    }
    drc->is_recycling = CM_TRUE;
    cm_spin_unlock(&drc->lock);
    return CM_TRUE;
}

void drc_recycle_drc_by_part(dms_process_context_t *ctx, drc_global_res_map_t *obj_res_map, drc_part_list_t *part)
{
    cm_spin_lock(&part->lock, NULL);
    bilist_node_t *node = cm_bilist_tail(&part->list);
    cm_spin_unlock(&part->lock);

    if (node == NULL) {
        return;
    }    
    drc_head_t *drc = (drc_head_t *)BILIST_NODE_OF(drc_head_t, node, part_node);
    // check
    uint64 seq = 0;
    if (!drc_chk_4_recycle(drc, &seq)) {
        drc_shift_to_head(drc);
        return;
    }
    // recycle
    if (drc_recycle(ctx, obj_res_map, drc, seq)) {
        return;
    }
    // reset flag and move to head if recycling failed
    cm_spin_lock(&drc->lock, NULL);
    drc->is_recycling = CM_FALSE;
    cm_spin_unlock(&drc->lock);
    drc_shift_to_head(drc);
}

static void drc_recycle_drc_part_stat(drc_global_res_map_t *obj_res_map, char *obj_name)
{
    drc_part_list_t *part = NULL;
    char buf_log[CM_BUFLEN_1K] = { 0 };
    char buf_num[CM_BUFLEN_32] = { 0 };
    PRTS_RETVOID_IFERR(sprintf_s(buf_log, CM_BUFLEN_1K, "[DRC %s recycle]every part drc count:", obj_name));
    for (uint8 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        part = &obj_res_map->res_parts[part_id];
        PRTS_RETVOID_IFERR(sprintf_s(buf_num, CM_BUFLEN_32, " %u", part->list.count));
        MEMS_RETVOID_IFERR(strcat_s(buf_log, CM_BUFLEN_1K, buf_num));
    }
    LOG_DEBUG_WAR(buf_log);
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

static bool8 drc_recycle_internal(dms_process_context_t *ctx, drc_global_res_map_t *obj_res_map, char *obj_name)
{
    drc_res_pool_t *pool = &obj_res_map->res_map.res_pool;
    // check if need to recycle
    if (pool->can_extend || pool->used_num < pool->item_num * DRC_RECYCLE_THRESHOLD) {
        return CM_FALSE;
    }
    cm_spin_lock(&DRC_RES_CTX->smon_recycle_lock, NULL);
    // parallel recycling
    if (DMS_REFORM_INFO->parallel_enable &&
        dms_proc_parallel(DMS_PROC_PARALLEL_RECYCLE_DRC_RES, (void*)obj_res_map) == DMS_SUCCESS) {
        cm_spin_unlock(&DRC_RES_CTX->smon_recycle_lock);
        drc_recycle_drc_part_stat(obj_res_map, obj_name);
        return CM_TRUE;
    }
    // serial recycling
    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        drc_part_list_t *part = &obj_res_map->res_parts[part_id];
        drc_recycle_drc_by_part(ctx, obj_res_map, part);
    }
    cm_spin_unlock(&DRC_RES_CTX->smon_recycle_lock);
    drc_recycle_drc_part_stat(obj_res_map, obj_name);
    return CM_TRUE;
}

static drc_recycle_obj_t recycle_objs[] = {
    { &g_drc_res_ctx.global_buf_res,   "BUF RES"   },
    { &g_drc_res_ctx.global_lock_res,  "LOCK RES"  },
    { &g_drc_res_ctx.global_alock_res, "ALOCK RES" },
};

static inline bool8 drc_do_recycle_task(dms_process_context_t *ctx)
{
    uint8 recycle_obj_count = 0;
    uint8 obj_count = ELEMENT_COUNT(recycle_objs);
    for (uint8 i = 0; i < obj_count; i++) {
        if (drc_recycle_internal(ctx, recycle_objs[i].obj_res_map, recycle_objs[i].obj_name)) {
            recycle_obj_count++;
        }
    }
    return (recycle_obj_count > 0);
}

void drc_recycle_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif

    dms_process_context_t proc_ctx;
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    ctx->smon_recycle_handle = g_dms.callback.get_db_handle(&ctx->smon_recycle_sid, DMS_SESSION_TYPE_NONE);
    cm_panic_log(ctx->smon_recycle_handle != NULL, "alloc db handle failed");

    proc_ctx.inst_id   = g_dms.inst_id;
    proc_ctx.sess_id   = ctx->smon_recycle_sid;
    proc_ctx.db_handle = ctx->smon_recycle_handle;
    
    LOG_RUN_INF("[DRC recycle]drc_recycle_thread start");
    while (!thread->closed) {
        if (drc_do_recycle_task(&proc_ctx)) {
            continue;
        }
        cm_sleep(DMS_REFORM_SHORT_TIMEOUT);
    }
    LOG_RUN_INF("[DRC recycle]drc_recycle_thread close");
}
