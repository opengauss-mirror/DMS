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
 * drc_lock.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_lock.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DRC_LOCK_H__
#define __DRC_LOCK_H__

#include "cm_latch.h"
#include "dms_msg.h"
#include "drc.h"
#include "dms.h"
#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_drc_local_latch_stat {
    volatile uint16 shared_count;
    volatile uint16 stat;
    volatile uint32 sid;
    uint8 lock_mode;    /* master register mode */
    uint8 unused[3];
} drc_local_latch_t;

typedef struct st_drc_local_lock_res {
    bilist_node_t   node;
    dms_drid_t      resid;
    volatile bool8  recycling;
    volatile bool8  releasing;
    bool8           is_reform_visit;
    uint8           partid;
    uint64          version;
    char            aligned1[CM_CACHE_LINE_SIZE];
    spinlock_t      lock;
    bilist_node_t   lru_node;
    char            aligned2[CM_CACHE_LINE_SIZE];
    drc_local_latch_t latch_stat;
    spinlock_t modify_mode_lock;
} drc_local_lock_res_t;

int drc_confirm_converting(void *db_handle, char* resid, uint8 type, uint8 *lock_mode);

#define STAT_RPC_BEGIN                  uint64 _rpc_begin_ = (uint64)g_timer()->now
#define STAT_RPC_WAIT_USECS             ((uint64)g_timer()->now - _rpc_begin_)

static inline void lock_resx_add_lru_head(drc_local_lock_res_t *lock_res)
{
    drc_part_list_t *lru_list = DRC_LOCAL_RES_PART(lock_res->partid);
    cm_spin_lock(&lru_list->lock, NULL);
    cm_bilist_add_head(&lock_res->lru_node, &lru_list->list);
    cm_spin_unlock(&lru_list->lock);
}

static inline void lock_resx_del_from_lru(drc_local_lock_res_t *lock_res)
{
    drc_part_list_t *lru_list = DRC_LOCAL_RES_PART(lock_res->partid);
    cm_spin_lock(&lru_list->lock, NULL);
    cm_bilist_del(&lock_res->lru_node, &lru_list->list);
    cm_spin_unlock(&lru_list->lock);
}

static inline void lock_resx_move_to_lru_head(drc_local_lock_res_t *lock_res)
{
    drc_part_list_t *lru_list = DRC_LOCAL_RES_PART(lock_res->partid);
    cm_spin_lock(&lru_list->lock, NULL);
    cm_bilist_del(&lock_res->lru_node, &lru_list->list);
    cm_bilist_add_head(&lock_res->lru_node, &lru_list->list);
    cm_spin_unlock(&lru_list->lock);
}

bool8 drc_get_lock_resx_by_drid(dms_drid_t *drid, drc_local_lock_res_t **lock_res, uint64 *ver);

static inline bool8 drc_get_lock_resx_by_dlatch(dms_drlatch_t *dlatch, drc_local_lock_res_t **lock_res)
{
    bool8 ret = drc_get_lock_resx_by_drid(&dlatch->drid, (drc_local_lock_res_t **)&dlatch->handle, &dlatch->version);
    *lock_res = (drc_local_lock_res_t *)dlatch->handle;
    return ret;
}

// use BKDR hash algorithm, get the hash id
static inline uint32 drc_resource_id_hash(char *id, uint32 len, uint32 range)
{
    uint32 seed = 131; // this is BKDR hash seed: 31 131 1313 13131 131313 etc..
    uint32 hash = 0;
    uint32 i;

    for (i = 0; i < len; i++) {
        hash = hash * seed + (*id++);
    }

    return (hash % range);
}

static inline uint16 drc_get_lock_partid(char *id, uint32 len, uint32 range)
{
    uint32 trunc_len = 0;
#ifndef OPENGAUSS
    if (DMS_DR_IS_TABLE_TYPE(((dms_drid_t *)id)->type)) {
        // Ignoring part id is to hash the table and partition into the same part, accelerating table lcok rebuild.
        trunc_len = (uint32)(sizeof(((dms_drid_t *)0)->parent) + sizeof(((dms_drid_t *)0)->part));
    }
#endif

    return (uint16)drc_resource_id_hash(id, len - trunc_len, range);
}

static inline int32 drc_get_lock_master_id(void *lock_id, uint8 len, uint8 *master_id)
{
    uint32 part_id = drc_get_lock_partid((char *)lock_id, len, DRC_MAX_PART_NUM);
    *master_id = DRC_PART_MASTER_ID(part_id);
    return CM_SUCCESS;
}

static inline int32 drc_get_lock_old_master_id(void *lock_id, uint8 len, uint8 *master_id)
{
    uint32 part_id = drc_get_lock_partid((char *)lock_id, len, DRC_MAX_PART_NUM);
    *master_id = DRC_PART_OLD_MASTER_ID(part_id);
    return CM_SUCCESS;
}

#ifdef __cplusplus
}
#endif

#endif /* __DRC_LOCK_H__ */
