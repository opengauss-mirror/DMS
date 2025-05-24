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
#include "drc_page.h"
#include "dms_reform_proc_parallel.h"
#include "drc_tran.h"

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

int32 drc_res_pool_init(drc_res_pool_t* pool, uint32 max_extend_num, uint32 res_size, uint32 res_num)
{
    status_t ret = memset_s(pool, sizeof(drc_res_pool_t), 0, sizeof(drc_res_pool_t));
    DMS_SECUREC_CHECK(ret);

    uint64 sz = (uint64)res_size * ((uint64)res_num);
    char *addr = (char *)dms_malloc(g_dms.drc_mem_context, sz);
    if (addr == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }
    cm_ptlist_init(&pool->addr_list);
    if (cm_ptlist_add(&pool->addr_list, (pointer_t)addr) != DMS_SUCCESS) {
        DMS_FREE_PROT_PTR(addr);
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    cm_bilist_init(&pool->free_list);
    GS_INIT_SPIN_LOCK(pool->lock);
    pool->item_num = res_num;
    pool->item_hwm = 0;
    pool->used_num = 0;
    pool->item_size = (uint64)res_size;
    pool->inited = CM_TRUE;
    pool->need_recycle = CM_FALSE;
    pool->extend_step = res_num;
    pool->max_extend_num = max_extend_num;
    return DMS_SUCCESS;
}

void drc_res_pool_reinit(drc_res_pool_t *pool)
{
    cm_spin_lock(&pool->lock, NULL);
    cm_bilist_init(&pool->free_list);
    pool->item_hwm = 0;
    pool->used_num = 0;
    pool->need_recycle = CM_FALSE;
    cm_spin_unlock(&pool->lock);
}

/*
 * spin lock is held outside
 */
static bool8 drc_res_pool_extend(drc_res_pool_t *pool)
{
    if (g_dms.drc_mem_context == NULL && pool->addr_list.count >= pool->max_extend_num) {
        return CM_FALSE;
    }
    uint64 sz = pool->extend_step * pool->item_size;
    char *addr = (char *)dms_malloc(g_dms.drc_mem_context, sz);
    if (addr == NULL) {
        pool->need_recycle = CM_TRUE;
        return CM_FALSE;
    }
    if (cm_ptlist_add(&pool->addr_list, (pointer_t)addr) != DMS_SUCCESS) {
        DMS_FREE_PROT_PTR(addr);
        pool->need_recycle = CM_TRUE;
        return CM_FALSE;
    }
    pool->item_num += pool->extend_step;
    pool->need_recycle = CM_FALSE;
    return CM_TRUE;
}

void drc_res_pool_destroy(drc_res_pool_t* pool)
{
    cm_spin_lock(&pool->lock, NULL);
    if (!pool->inited) {
        cm_spin_unlock(&pool->lock);
        return;
    }

    for (uint32 i = 0; i < pool->addr_list.count; i++) {
        char *addr = (char *)cm_ptlist_get(&pool->addr_list, i);
        DMS_FREE_PROT_PTR(addr);
    }

    cm_bilist_init(&pool->free_list);
    cm_destroy_ptlist(&pool->addr_list);
    pool->item_num = 0;
    pool->used_num = 0;
    pool->item_size = 0;
    pool->extend_step = 0;
    pool->inited = CM_FALSE;
    cm_spin_unlock(&pool->lock);
}

char *drc_res_pool_alloc_item_inner(drc_res_pool_t *pool)
{
    // 1. try alloc item from free list
    if (!cm_bilist_empty(&pool->free_list)) {
        return (char *)cm_bilist_pop_first(&pool->free_list);
    }

    // 2. try extend buffer
    if (pool->item_hwm == pool->item_num && !drc_res_pool_extend(pool)) {
        return NULL;
    }

    // 3. alloc from hwm
    CM_ASSERT(pool->item_hwm < pool->item_num);
    char *addr = drc_pool_find_item(pool, pool->item_hwm);
    CM_ASSERT(addr != NULL);
    errno_t err = memset_s(addr, pool->item_size, 0, pool->item_size);
    DMS_SECUREC_CHECK(err);
    pool->item_hwm++;
    return addr;
}

char* drc_res_pool_alloc_item(drc_res_pool_t* pool)
{
    cm_spin_lock(&pool->lock, NULL);
    char *item_addr = drc_res_pool_alloc_item_inner(pool);
    if (item_addr == NULL) {
        cm_spin_unlock(&pool->lock);
        return NULL;
    }
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
    res_map->buckets = (drc_res_bucket_t*)dms_malloc(g_dms.drc_mem_context, bucket_size);

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

    res_map->bucket_version = 0;
    res_map->res_type = res_type;
    res_map->res_cmp_func = res_cmp;
    res_map->res_hash_func = res_hash;
    res_map->inited = CM_TRUE;

    return DMS_SUCCESS;
}

void drc_res_map_reinit(drc_res_map_t *res_map)
{
    res_map->bucket_version++;
    drc_res_pool_reinit(&res_map->res_pool);
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
    errno_t ret = memset_s(drc, sizeof(drc_head_t), 0, sizeof(drc_head_t));
    DMS_SECUREC_CHECK(ret);

    // init drc_head
    drc->type = res_type;
    drc->owner = CM_INVALID_ID8;
    drc->is_using = CM_TRUE;
    drc->len = len;
    init_drc_cvt_item(&drc->converting);

    // memory copy resid
    ret = memcpy_s(DRC_DATA(drc), len, resid, len);
    DMS_SECUREC_CHECK(ret);

    // init drc_page
    if (res_type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        cm_bilist_node_init(&drc_page->flush_node);
        drc_page->owner_lsn = 0;
        drc_page->edp_map = 0;
        drc_page->rebuild_type = REFORM_ASSIST_LIST_NONE;
        drc_page->need_recover = CM_FALSE;
        drc_page->need_flush = CM_FALSE;
        drc_page->last_edp = CM_INVALID_ID8;
        drc_page->last_edp_lsn = 0;
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
        case DRC_RES_GLOBAL_XA_TYPE:
            return drc_get_xa_partid((drc_global_xid_t *)DRC_DATA(drc));
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
    DDES_FAULT_INJECTION_ACTION_TRIGGER_CUSTOM_ALWAYS(DMS_FI_DRC_NOT_ENOUGH, {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return NULL; });

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

drc_head_t *drc_alloc(uint8 options, drc_res_pool_t *pool, char *resid, uint16 len, uint8 res_type,
    drc_res_bucket_t *bucket)
{
    if (!(options & DRC_ALLOC)) {
        return NULL;
    }

    drc_head_t *drc = drc_create(pool, resid, len, res_type, bucket);
    if (SECUREC_UNLIKELY(drc == NULL)) {
        return NULL;
    } else {
        return drc;
    }
}

drc_head_t *drc_migrate(char *resid, uint16 len, uint8 res_type, uint8 options, uint8 old_master)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(res_type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, resid, len);
    drc_head_t *drc = NULL;
    dms_ack_drc_migrate_t ack;

    if (dms_req_drc_migrate(&ack, resid, len, res_type, options, old_master) != DMS_SUCCESS) {
        return NULL;
    }

    if (!ack.exist) {
        return drc_alloc(options, &res_map->res_pool, resid, len, res_type, bucket);
    }

    drc = drc_create(&res_map->res_pool, resid, len, res_type, bucket);
    if (SECUREC_UNLIKELY(drc == NULL)) {
        return NULL;
    }
    drc->owner = ack.owner;
    drc->lock_mode = ack.lock_mode;
    drc->copy_insts = ack.copy_insts;
    drc->converting = ack.converting;
    if (res_type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        drc_page->last_edp = ack.last_edp;
        drc_page->edp_map = ack.edp_map;
        drc_page->last_edp_lsn = ack.last_edp_lsn;
        drc_page->seq = ack.seq;
    }
    DRC_DISPLAY(drc, "DRM");
    dms_notify_old_master_release(drc, old_master, options);
    return drc;
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

    // accessed by old master(for migrate or release), return NULL if drc not exists
    if (options & DRC_RES_CHECK_OLD_MASTER) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    uint8 old_master = CM_INVALID_ID8;
    if (drc_get_old_master_id(resid, res_type, &old_master) != DMS_SUCCESS) {
        cm_spin_unlock(&bucket->lock);
        return NULL;
    }

    // old master is self, just create drc according options. otherwise, should ask old master for drc
    if (dms_dst_id_is_self(old_master)) {
        drc = drc_alloc(options, &res_map->res_pool, resid, len, res_type, bucket);
    } else {
        drc = drc_migrate(resid, len, res_type, options, old_master);
    }

    if (drc != NULL) {
        drc_inc_ref_count(drc);
    }
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

    switch (res_type) {
        case DRC_RES_PAGE_TYPE:
            if (!(options & DRC_RES_RELEASE) &&
                res_map->drc_accessible_stage == PAGE_ACCESS_STAGE_REALESE_ACCESS) {
                LOG_DEBUG_WAR("[%s][drc_enter_check_access]data is inaccessible", cm_display_resid(resid, res_type));
                DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
                return ERRNO_DMS_REFORM_IN_PROCESS;
            }
            break;
        case DRC_RES_LOCK_TYPE:
        case DRC_RES_ALOCK_TYPE:
            if ((options & DRC_CHECK_BIZ_SESSION) &&
                res_map->drc_accessible_stage == LOCK_ACCESS_STAGE_NON_BIZ_SESSION_ACCESS) {
                LOG_DEBUG_WAR("[%s][drc_enter_check_access]data is inaccessible", cm_display_resid(resid, res_type));
                DMS_THROW_ERROR(ERRNO_DMS_REFORM_IN_PROCESS);
                return ERRNO_DMS_REFORM_IN_PROCESS;
            }
        case DRC_RES_GLOBAL_XA_TYPE:
            break;
        default:
            LOG_RUN_ERR("invalid res type:%d", res_type);
            break;
    }

    return DMS_SUCCESS;
}

int drc_enter_check_old_master(char *resid, uint8 res_type, uint8 options)
{
    if (!(options & DRC_RES_CHECK_OLD_MASTER)) {
        return DMS_SUCCESS;
    }

    uint8 master_id = CM_INVALID_ID8;
    int ret = drc_get_old_master_id(resid, res_type, &master_id);
    DMS_RETURN_IF_ERROR(ret);

    if (dms_dst_id_is_self(master_id)) {
        return DMS_SUCCESS;
    }

    LOG_DEBUG_WAR("[%s][drc_enter_check_old_master]old_master is %d", cm_display_resid(resid, res_type), master_id);
    DMS_THROW_ERROR(ERRNO_DMS_DRC_INVALID, cm_display_resid(resid, res_type));
    return ERRNO_DMS_DRC_INVALID;
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

    ret = drc_enter_check_old_master(resid, res_type, options);
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

bool8 drm_create_inner(char *resid, uint16 len, uint8 res_type, uint8 options)
{
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(res_type);
    drc_res_map_t *res_map = &global_res_map->res_map;
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(res_map, resid, len);

    cm_spin_lock(&bucket->lock, NULL);
    drc_head_t *drc = (drc_head_t *)drc_res_map_lookup(res_map, bucket, resid, len);
    if (drc != NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_TRUE;
    }

    drc = drc_alloc(options, &res_map->res_pool, resid, len, res_type, bucket);
    if (drc == NULL) {
        cm_spin_unlock(&bucket->lock);
        return CM_FALSE;
    }

    switch (res_type) {
        case DRC_RES_PAGE_TYPE: {
            drm_migrate_page_t *migrate_page = (drm_migrate_page_t *)resid;
            drc_page_t *drc_page = (drc_page_t *)drc;
            errno_t err = memcpy_s(&drc->converting, sizeof(drc_cvt_item_t),
                &migrate_page->converting, sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            drc->owner = migrate_page->owner;
            drc->lock_mode = migrate_page->lock_mode;
            drc->copy_insts = migrate_page->copy_insts;
            drc_page->last_edp = migrate_page->last_edp;
            drc_page->edp_map = migrate_page->edp_map;
            drc_page->last_edp_lsn = migrate_page->last_edp_lsn;
            drc_page->seq = migrate_page->seq;
            break;
        }

        case DRC_RES_LOCK_TYPE: {
            drm_migrate_lock_t *migrate_lock = (drm_migrate_lock_t *)resid;
            errno_t err = memcpy_s(&drc->converting, sizeof(drc_cvt_item_t),
                &migrate_lock->converting, sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            drc->owner = migrate_lock->owner;
            drc->lock_mode = migrate_lock->lock_mode;
            drc->copy_insts = migrate_lock->copy_insts;
            break;
        }

        case DRC_RES_ALOCK_TYPE: {
            drm_migrate_alock_t *migrate_alock = (drm_migrate_alock_t *)resid;
            errno_t err = memcpy_s(&drc->converting, sizeof(drc_cvt_item_t),
                &migrate_alock->converting, sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            drc->owner = migrate_alock->owner;
            drc->lock_mode = migrate_alock->lock_mode;
            drc->copy_insts = migrate_alock->copy_insts;
            break;
        }

        case DRC_RES_GLOBAL_XA_TYPE: {
            drm_migrate_xa_t *migrate_xa = (drm_migrate_xa_t *)resid;
            drc->owner = migrate_xa->owner;
            break;
        }

        default:
            CM_ASSERT(0);
            break;
    }

    DRC_DISPLAY(drc, "DRM");
    cm_spin_unlock(&bucket->lock);

    return CM_TRUE;
}

bool8 drm_create(char* resid, uint16 len, uint8 res_type)
{
    uint8 options = drc_build_options(CM_TRUE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_TRUE);
    if (drc_enter_check(resid, res_type, options) != DMS_SUCCESS) {
        return CM_FALSE;
    }

    bool8 ret = drm_create_inner(resid, len, res_type, options);
    drc_unlatch(res_type, options);
    return ret;
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
    if (res_bucket->bucket_version != res_map->bucket_version) {
        cm_bilist_init(&res_bucket->bucket_list);
        res_bucket->bucket_version = res_map->bucket_version;
    }

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

static void uninit_drc_mem_context()
{
    ddes_memory_context_destroy(g_dms.drc_mem_context);
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

    uninit_drc_mem_context();
    drm_thread_deinit();
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

int32 drc_get_page_old_master_id(char *pageid, unsigned char *master_id)
{
    dms_reset_error();
    uint8  inst_id;
    uint32 part_id;

    part_id = drc_page_partid(pageid);
    inst_id = DRC_PART_OLD_MASTER_ID(part_id);
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
            return DMS_ERROR;
    }
}

int32 drc_get_old_master_id(char *resid, uint8 type, uint8 *master_id)
{
    switch (type) {
        case DRC_RES_PAGE_TYPE:
            return drc_get_page_old_master_id(resid, master_id);
        case DRC_RES_GLOBAL_XA_TYPE:
            return drc_get_xa_old_master_id((drc_global_xid_t *)resid, master_id);
        case DRC_RES_LOCK_TYPE:
            return drc_get_lock_old_master_id(resid, DMS_DRID_SIZE, master_id);
        case DRC_RES_ALOCK_TYPE:
            return drc_get_lock_old_master_id(resid, DMS_ALOCKID_SIZE, master_id);
        default:
            return DMS_ERROR;
    }
}

uint8 drc_build_options(bool32 alloc, dms_session_e sess_type, uint8 intercept_type, bool32 check_master)
{
    uint8 options = DRC_RES_NORMAL;

    if (alloc) {
        options |= DRC_ALLOC;
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
    drc_res_pool_t *pool = &ctx->local_lock_res.res_pool;

    while (*vmid < pool->item_hwm) {
        drc_local_lock_res_t *lock_res = (drc_local_lock_res_t *)drc_pool_find_item(pool, *vmid);
        if (lock_res == NULL) {
            drc_local_lock_res_result->is_valid = CM_FALSE;
            return;
        }
        ++*vmid;
        if (DLS_LATCH_IS_OWNER(lock_res->latch_stat.lock_mode)) {
            fill_dv_drc_local_lock_result(drc_local_lock_res_result, lock_res);
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
    drc_res_ctx_t *res_ctx = DRC_RES_CTX;

    if (drc->type == DRC_RES_GLOBAL_XA_TYPE && drc->owner != CM_INVALID_ID8) {
        LOG_DEBUG_WAR("[DRC recycle][%s]fail to release drc xa, owner:%d",
            cm_display_resid(DRC_DATA(drc), drc->type), drc->owner);
        return CM_FALSE;
    }

    if (drc->copy_insts > 0 && dms_invalidate_share_copy(ctx, DRC_DATA(drc), drc->len, drc->type,
        drc->copy_insts, DMS_SESSION_NORMAL, CM_FALSE, CM_FALSE, seq, NULL) != DMS_SUCCESS) {
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
        if (res_ctx->smon_recycle_pause) {
            return CM_FALSE;
        }
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

    if (drc->type == DRC_RES_GLOBAL_XA_TYPE) {
        if (drc->owner != CM_INVALID_ID8) {
            cm_spin_unlock(&drc->lock);
            return CM_FALSE;
        }
    }

    drc->is_recycling = CM_TRUE;
    cm_spin_unlock(&drc->lock);
    return CM_TRUE;
}

bool8 drc_recycle_part_check(uint16 part_id)
{
    uint8 curr_master = DRC_PART_MASTER_ID(part_id);
    uint8 old_master = DRC_PART_OLD_MASTER_ID(part_id);
    return dms_dst_id_is_self(old_master) && dms_dst_id_is_self(curr_master);
}

void drc_recycle_drc_by_part(dms_process_context_t *ctx, drc_global_res_map_t *obj_res_map, drc_part_list_t *part)
{
    cm_spin_lock(&part->lock, NULL);
    bilist_node_t *node = cm_bilist_tail(&part->list);
    cm_spin_unlock(&part->lock);

    if (node == NULL) {
        return;
    }
    // drc can not be released by other thread, so we can access drc directly here
    // so drc in old master can not processed here, otherwise there may be concurrency issues
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

static void drc_recycle_drc_part_stat(drc_global_res_map_t *obj_res_map, drc_res_pool_t *pool, char *name)
{
    drc_part_list_t *part = NULL;
    char buf_log[CM_BUFLEN_1K] = { 0 };
    char buf_num[CM_BUFLEN_32] = { 0 };
    LOG_DEBUG_INF("[DRC %s recycle]end, total: %u, used: %u", name, pool->item_num, pool->used_num);
    PRTS_RETVOID_IFERR(sprintf_s(buf_log, CM_BUFLEN_1K, "[DRC %s recycle]every part drc count:", name));
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
    ctx->smon_recycle_pause = CM_TRUE;
    cm_spin_lock(&ctx->smon_recycle_lock, NULL);
    LOG_RUN_INF("[DRC recycle]pausing");
}

void drc_recycle_buf_res_set_running(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_spin_unlock(&ctx->smon_recycle_lock);
    ctx->smon_recycle_pause = CM_FALSE;
    LOG_RUN_INF("[DRC recycle]running");
}

static inline bool8 drc_chk_if_need_recycle(drc_res_pool_t *pool)
{
    if (pool->used_num < pool->item_num * DRC_RECYCLE_THRESHOLD) {
        return CM_FALSE;
    }
    if (g_dms.drc_mem_context == NULL) {
        return (pool->need_recycle || pool->addr_list.count >= pool->max_extend_num);
    }
    uint64 used, total;
    ddes_memory_stat(g_dms.drc_mem_context, &used, &total);
    return (pool->need_recycle || used >= total * DRC_RECYCLE_THRESHOLD);
}

static bool8 recycle_global_drc(dms_process_context_t *ctx, drc_recycle_obj_t *obj)
{
    drc_res_ctx_t *res_ctx = DRC_RES_CTX;
    drc_global_res_map_t *global_drc_res = obj->global_drc_res;
    drc_res_pool_t *pool = &global_drc_res->res_map.res_pool;
    // check if need to recycle
    if (!drc_chk_if_need_recycle(pool)) {
        if (obj->has_recycled) {
            obj->has_recycled = CM_FALSE;
            drc_recycle_drc_part_stat(global_drc_res, pool, obj->name);
        }
        return CM_FALSE;
    }
    if (!obj->has_recycled) {
        obj->has_recycled = CM_TRUE;
        LOG_DEBUG_INF("[DRC %s recycle]start, extend: %u, total: %u, used: %u",
            obj->name, pool->addr_list.count, pool->item_num, pool->used_num);
    }
    cm_spin_lock(&DRC_RES_CTX->smon_recycle_lock, NULL);
    // parallel recycling
    if (DMS_REFORM_INFO->parallel_enable &&
        dms_proc_parallel(DMS_PROC_PARALLEL_RECYCLE_DRC_RES, (void*)global_drc_res) == DMS_SUCCESS) {
        cm_spin_unlock(&DRC_RES_CTX->smon_recycle_lock);
        return CM_TRUE;
    }
    // serial recycling
    for (uint16 part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
        if (drc_recycle_part_check(part_id)) {
            drc_part_list_t *part = &global_drc_res->res_parts[part_id];
            drc_recycle_drc_by_part(ctx, global_drc_res, part);
        }
        if (res_ctx->smon_recycle_pause) {
            break;
        }
    }
    cm_spin_unlock(&DRC_RES_CTX->smon_recycle_lock);
    return CM_TRUE;
}

static drc_recycle_obj_t recycle_objs[] = {
    { &g_drc_res_ctx.global_buf_res,   "BUF RES",   CM_FALSE },
    { &g_drc_res_ctx.global_lock_res,  "LOCK RES",  CM_FALSE },
    { &g_drc_res_ctx.global_alock_res, "ALOCK RES", CM_FALSE },
    { &g_drc_res_ctx.global_xa_res,    "XA RES",    CM_FALSE },
};

static void recycle_local_res_by_part(drc_res_ctx_t *ctx, drc_part_list_t *part)
{
    cm_spin_lock(&part->lock, NULL);
    bilist_node_t *node = cm_bilist_tail(&part->list);
    cm_spin_unlock(&part->lock);
    if (node == NULL) {
        return;
    }
    drc_local_lock_res_t *lock_res = (drc_local_lock_res_t *)BILIST_NODE_OF(drc_local_lock_res_t, node, lru_node);
    date_t begin = g_timer()->now;
    lock_res->recycling = CM_TRUE;
    cm_spin_lock(&lock_res->lock, NULL);
    // waiting for all owners to release the lock
    while (lock_res->latch_stat.stat != LATCH_STATUS_IDLE) {
        cm_spin_unlock(&lock_res->lock);
        if ((g_timer()->now - begin) / MICROSECS_PER_MILLISEC >= DMS_WAIT_MAX_TIME || ctx->smon_recycle_pause) {
            lock_res->recycling = CM_FALSE;
            lock_resx_move_to_lru_head(lock_res);
            LOG_DEBUG_WAR("[DLS] recycle local res(%s) timeout", cm_display_lockid(&lock_res->resid));
            return;
        }
        cm_sleep(1);
        cm_spin_lock(&lock_res->lock, NULL);
    }
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(&ctx->local_lock_res,
        (char *)&lock_res->resid, sizeof(dms_drid_t));
    // remove from hash bucket
    cm_spin_lock(&bucket->lock, NULL);
    drc_res_map_del_res(&ctx->local_lock_res, bucket, (char *)&lock_res->resid, sizeof(dms_drid_t));
    cm_spin_unlock(&bucket->lock);
    // remove from LRU part
    lock_resx_del_from_lru(lock_res);
    // change version and invalid local res which be cached
    cm_spin_lock(&lock_res->modify_mode_lock, NULL);
    lock_res->version = (uint64)cm_atomic_inc(&ctx->version);
    cm_spin_unlock(&lock_res->modify_mode_lock);
    // someone(dms_latch_s\dms_latch_x) may be waiting for the recycling to be completed
    // reset this flag and wake up them in time
    lock_res->recycling = CM_FALSE;
    cm_spin_unlock(&lock_res->lock);
    // free drc to resource pool, to be reused later
    drc_res_pool_free_item(&ctx->local_lock_res.res_pool, (char*)lock_res);
}

static bool8 recycle_local_res(drc_res_ctx_t *ctx)
{
    drc_res_pool_t *pool = &ctx->local_lock_res.res_pool;
    if (!drc_chk_if_need_recycle(pool)) {
        if (ctx->start_recycled) {
            ctx->start_recycled = CM_FALSE;
            LOG_DEBUG_INF("[DRC local res recycle]end, total: %u, used: %u", pool->item_num, pool->used_num);
        }
        return CM_FALSE;
    }
    if (!ctx->start_recycled) {
        ctx->start_recycled = CM_TRUE;
        LOG_DEBUG_INF("[DRC local res recycle]start, total: %u, used: %u", pool->item_num, pool->used_num);
    }
    cm_spin_lock(&ctx->smon_recycle_lock, NULL);
    for (uint32 i = 0; i < DRC_MAX_PART_NUM; i++) {
        if (ctx->smon_recycle_pause) {
            break;
        }
        recycle_local_res_by_part(ctx, &ctx->local_res_parts[i]);
    }
    cm_spin_unlock(&ctx->smon_recycle_lock);
    return CM_TRUE;
}

static bool8 drc_do_recycle_task(dms_process_context_t *ctx)
{
    bool8 ret = CM_FALSE;
    drc_res_ctx_t *res_ctx = DRC_RES_CTX;
    uint8 obj_count = ELEMENT_COUNT(recycle_objs);
    for (uint8 i = 0; i < obj_count; i++) {
        if (recycle_global_drc(ctx, &recycle_objs[i])) {
            ret = CM_TRUE;
        }
        if (res_ctx->smon_recycle_pause) {
            return CM_FALSE;
        }
    }
    return (recycle_local_res(res_ctx) || ret);
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
    mes_block_sighup_signal();

    proc_ctx.inst_id   = g_dms.inst_id;
    proc_ctx.sess_id   = ctx->smon_recycle_sid;
    proc_ctx.db_handle = ctx->smon_recycle_handle;

    LOG_RUN_INF("[DRC recycle]drc_recycle_thread start");
    while (!thread->closed) {
        if (!ctx->smon_recycle_pause && drc_do_recycle_task(&proc_ctx)) {
            continue;
        }
        cm_sleep(DMS_REFORM_SHORT_TIMEOUT);
    }
    LOG_RUN_INF("[DRC recycle]drc_recycle_thread close");
}