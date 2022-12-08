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
#define DRC_RES_BEFORE_RCY          2   // if access page before recovery, should set in recovery flag for new buf_res
#define DRC_RES_CHECK_ACCESS        4   // handle_reform & handle_proc should not to check access
#define DRC_RES_CHECK_MASTER        8   // if recheck master id or not
#define DRC_RES_IGNORE_DATA         0x10    // if for release, no need wait recovery finish

#define DMS_RES_MAP_INIT_PARAM 2
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

static inline void drc_inc_buf_res_ref(drc_buf_res_t *buf_res)
{
    (void)cm_atomic32_inc(&buf_res->count);
}

static inline void drc_dec_buf_res_ref(drc_buf_res_t *buf_res)
{
    cm_panic(buf_res->count >= 1);
    (void)cm_atomic32_dec(&buf_res->count);
}

int32 drc_get_page_owner_id(uint8 edp_inst, char pageid[DMS_PAGEID_SIZE], bool32 sess_rcy, uint8 *id);
int32 drc_get_page_remaster_id(char pageid[DMS_PAGEID_SIZE], uint8 *id);
void drc_add_buf_res_in_part_list(drc_buf_res_t *buf_res);
void drc_del_buf_res_in_part_list(drc_buf_res_t *buf_res);
void drc_add_lock_res_in_part_list(drc_buf_res_t *lock_res);
void drc_del_lock_res_in_part_list(drc_buf_res_t *lock_res);
void drc_release_convert_q(bilist_t *convert_q);
bool32 drc_buf_res_set_inaccess(drc_global_res_map_t *res_map);
int drc_enter_buf_res(char *resid, uint16 len, uint8 res_type, uint8 options, drc_buf_res_t **buf_res);
void drc_leave_buf_res(drc_buf_res_t *buf_res);
void drc_buf_res_unlatch(uint8 res_type);
uint8 drc_build_options(bool32 alloc, bool32 rcy_flag, bool32 check_master);

#ifdef __cplusplus
}
#endif

#endif /* __DRC_RES_MGR_H__ */
