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
 * drc_res_mgr.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_res_mgr.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DRC_RES_MGR_H__
#define __DRC_RES_MGR_H__

#include "drc.h"
#include "drc_lock.h"
#include "dms_process.h"
#include "dms_cm.h"
#include "cm_hash.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRC_RES_NORMAL              0
#define DRC_RES_ALLOC               1   // if alloc or not when drc not exists
#define DRC_RES_CHECK_ACCESS        2   // handle_reform & handle_proc should not to check access
#define DRC_RES_CHECK_MASTER        4   // if recheck master id or not
#define DRC_RES_RELEASE             8   // if for release, no need wait recovery finish
#define DRC_CHECK_BIZ_SESSION  16

#define DMS_RES_MAP_INIT_PARAM 2
#define DMS_GET_DRC_INFO_COUNT 100
#define DMS_GET_DRC_INFO_SLEEP_TIME 10

typedef struct st_drc_recycle_obj {
    drc_global_res_map_t *global_drc_res;
    char *name;
    bool8 has_recycled;
} drc_recycle_obj_t;

static inline uint16 drc_page_partid(char pageid[DMS_PAGEID_SIZE])
{
    uint32 hash_val = g_dms.callback.get_page_hash_val(pageid);
    return (uint16)cm_hash_uint32(hash_val, DRC_MAX_PART_NUM);
}

static inline void drc_set_deposit_id(uint8 instance_id, uint8 deposit_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->deposit_map[instance_id] = deposit_id;
}

static inline void drc_inc_ref_count(drc_head_t *drc)
{
    (void)cm_atomic32_inc(&drc->ref_count);
}

static inline void drc_dec_ref_count(drc_head_t *drc)
{
    cm_panic(drc->ref_count >= 1);
    (void)cm_atomic32_dec(&drc->ref_count);
}

static inline char *drc_pool_find_item(drc_res_pool_t *pool,  uint32 index)
{
    uint32 addr_idx = index / pool->extend_step;
    uint32 offset   = index % pool->extend_step;
    char *addr = (char *)cm_ptlist_get(&pool->addr_list, addr_idx);
    if (addr == NULL) {
        return NULL;
    }
    return (addr + offset * pool->item_size);
}

int drc_get_page_owner_id(uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], dms_session_e sess_type, uint8 *id);
int dcs_ckpt_get_page_owner_inner(void *db_handle, uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], uint8 *id);
int drc_get_page_remaster_id(char pageid[DMS_PAGEID_SIZE], uint8 *id);
void drc_shift_to_tail(drc_head_t *drc);
void drc_shift_to_head(drc_head_t *drc);
void drc_buf_res_set_inaccess(drc_global_res_map_t *res_map);
int drc_enter(char *resid, uint16 len, uint8 res_type, uint8 options, drc_head_t **drc);
void drc_leave(drc_head_t *drc, uint8 options);
uint8 drc_build_options(bool32 alloc, dms_session_e sess_type, uint8 intercept_type, bool32 check_master);
void dms_get_drc_local_lock_res(unsigned int *vmid, drc_local_lock_res_result_t *drc_local_lock_res_result);
void drc_recycle_thread(thread_t *thread);
void drc_recycle_drc_by_part(dms_process_context_t *ctx, drc_global_res_map_t *obj_res_map, drc_part_list_t *part);
void drc_recycle_buf_res_set_running(void);
void drc_recycle_buf_res_set_pause(void);
void drc_enter_buf_res_set_blocked(void);
void drc_enter_buf_res_set_unblocked(void);
void drc_release(drc_head_t *drc, drc_res_map_t *drc_res_map, drc_res_bucket_t *bucket);

#ifdef __cplusplus
}
#endif

#endif /* __DRC_RES_MGR_H__ */
