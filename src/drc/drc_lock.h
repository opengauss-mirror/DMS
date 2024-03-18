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
    bool8           is_owner;
    bool8           is_locked;
    volatile bool8  releasing;  // align later
    uint8           unused;
    spinlock_t      lock;
    drc_local_latch_t latch_stat;
} drc_local_lock_res_t;

/* local lock resource API */
drc_local_lock_res_t* drc_get_local_resx(dms_drid_t *lock_id);
void drc_lock_local_resx(drc_local_lock_res_t *lock_res, spin_statis_t *stat, spin_statis_instance_t *stat_instance);
void drc_unlock_local_resx(drc_local_lock_res_t *lock_res);
void drc_get_local_lock_statx(drc_local_lock_res_t *lock_res, bool8 *is_locked, bool8 *is_owner);
void drc_set_local_lock_statx(drc_local_lock_res_t *lock_res, bool8 is_locked, bool8 is_owner);
void drc_get_local_latch_statx(drc_local_lock_res_t *lock_res, drc_local_latch_t **latch_stat);
int drc_confirm_owner(void *db_handle, char* resid, uint8 *lock_mode);
int drc_confirm_converting(void *db_handle, char* resid, uint8 *lock_mode);

#define STAT_TOTAL_WAIT_USECS_BEGIN     uint64 _begin_time_ = (uint64)g_timer()->now
#define STAT_TOTAL_WAIT_USECS_END       dms_ctx->wait_usecs = (uint64)g_timer()->now - _begin_time_

#define STAT_RPC_BEGIN                  uint64 _rpc_begin_ = (uint64)g_timer()->now
#define STAT_RPC_WAIT_USECS             ((uint64)g_timer()->now - _rpc_begin_)

#ifdef __cplusplus
}
#endif

#endif /* __DRC_LOCK_H__ */
