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
 * dls_spinlock.c
 *
 *
 * IDENTIFICATION
 *    src/dls/dls_spinlock.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_spinlock.h"
#include "dls_msg.h"
#include "dms_error.h"
#include "drc_lock.h"
#include "dms_msg.h"
#include "cm_timer.h"

static bool8 dls_request_spin_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 timeout_ticks)
{
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;

    do {
        if (!dms_drc_accessible(dms_ctx->type) && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
            return CM_FALSE;
        }

        if (dls_request_lock(dms_ctx, lock_res, DMS_LOCK_NULL, DMS_LOCK_EXCLUSIVE) == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            return CM_FALSE;
        }
        dls_sleep(&spin_times, &wait_ticks, DLS_SPIN_COUNT);
    } while (CM_TRUE);
}

static inline void dms_spin_stat_wait_usecs(spin_statis_t *stat, uint64 ss_wait_usecs)
{
    if (stat != NULL) {
        stat->ss_wait_usecs += ss_wait_usecs;
    }
}

static inline void dms_instance_stat_wait_usecs(spin_statis_instance_t *stat, uint64 ss_wait_usecs)
{
    if (stat != NULL) {
        stat->ss_wait_usecs += ss_wait_usecs;
    }
}

static inline void dms_wait4_spinlock(drc_local_lock_res_t *lock_res, spin_statis_instance_t *stat_instance)
{
    uint32 count = 0;
    while (lock_res->latch_stat.stat != LATCH_STATUS_IDLE || lock_res->releasing) {
        if (++count >= GS_SPIN_COUNT) {
            count = 0;
            cm_spin_sleep();
            SPIN_STAT_INC(stat_instance, wait_times);
        }
    }
}

void dms_spin_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    if (SECUREC_UNLIKELY(dlock->drid.type == DMS_DR_TYPE_INVALID || dlock->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add spinlock(%s) failed, because lock not initialized", cm_display_lockid(&dlock->drid));
    }

    LOG_DEBUG_INF("[DLS] entry spinlock(%s)", cm_display_lockid(&dlock->drid));

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlock->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    dls_init_dms_ctx(dms_ctx, &dlock->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (!lock_res->releasing && latch_stat->stat == LATCH_STATUS_IDLE) {
            drc_lock_local_resx(lock_res, dms_ctx->stat, dms_ctx->stat_instance);
            
            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                STAT_RPC_BEGIN;
                if (latch_stat->lock_mode == DMS_LOCK_NULL && !dls_request_spin_lock(dms_ctx, lock_res, 1)) {
                    dms_spin_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
                    dms_instance_stat_wait_usecs(dms_ctx->stat_instance, STAT_RPC_WAIT_USECS);
                    drc_unlock_local_resx(lock_res);
                    continue;
                }
                dms_spin_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
                dms_instance_stat_wait_usecs(dms_ctx->stat_instance, STAT_RPC_WAIT_USECS);
                latch_stat->stat = LATCH_STATUS_X;
                latch_stat->sid  = dms_ctx->sess_id;
                drc_unlock_local_resx(lock_res);
                break;
            }
            drc_unlock_local_resx(lock_res);
        }
        dms_wait4_spinlock(lock_res, dms_ctx->stat_instance);
    } while (CM_TRUE);
    STAT_TOTAL_WAIT_USECS_END;
}

void dms_spin_unlock(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    if (SECUREC_UNLIKELY(dlock->drid.type == DMS_DR_TYPE_INVALID || dlock->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic(0);
    }

    LOG_DEBUG_INF("[DLS] release spinlock(%s)", cm_display_lockid(&dlock->drid));
    drc_local_lock_res_t *lock_res = NULL;
    lock_res = drc_get_local_resx(&dlock->drid);
    drc_lock_local_resx(lock_res, NULL, NULL);
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    drc_unlock_local_resx(lock_res);
}

void dms_init_spinlock(dms_drlock_t *lock, dms_dr_type_t type, unsigned long long oid, unsigned short uid)
{
    DLS_INIT_DR_RES(&lock->drid, type, oid, uid, 0, CM_INVALID_ID32, CM_INVALID_ID32);
}

void dms_init_spinlock2(dms_drlock_t *lock, dms_dr_type_t type, unsigned int oid, unsigned short uid, unsigned int idx,
    unsigned int parent_part, unsigned int part)
{
    DLS_INIT_DR_RES(&lock->drid, type, oid, uid, idx, parent_part, part);
}

static int32 dls_do_spin_try_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    if (SECUREC_UNLIKELY(dlock->drid.type == DMS_DR_TYPE_INVALID || dlock->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic(0);
    }
    
    LOG_DEBUG_INF("[DLS] try add spinlock(%s),", cm_display_lockid(&dlock->drid));

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlock->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->stat != LATCH_STATUS_IDLE || lock_res->releasing) {
        LOG_DEBUG_INF("[DLS] try add spinlock(%s), lockmode(%u) is locked",
            cm_display_lockid(&dlock->drid), (uint32)latch_stat->lock_mode);
        return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
    }

    drc_lock_local_resx(lock_res, NULL, NULL);
    if (latch_stat->stat != LATCH_STATUS_IDLE || lock_res->releasing) {
        drc_unlock_local_resx(lock_res);
        LOG_DEBUG_INF("[DLS] try add spinlock(%s), lockmode(%u) is locked",
            cm_display_lockid(&dlock->drid), (uint32)latch_stat->lock_mode);
        return ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED;
    }

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        int32 ret = dls_try_request_lock(dms_ctx, lock_res, DMS_LOCK_NULL, DMS_LOCK_EXCLUSIVE);
        if (ret != DMS_SUCCESS) {
            drc_unlock_local_resx(lock_res);
            return ret;
        }
    }
    latch_stat->stat = LATCH_STATUS_X;
    latch_stat->sid  = dms_ctx->sess_id;
    drc_unlock_local_resx(lock_res);
    return DMS_SUCCESS;
}

unsigned char dms_spin_try_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    dms_reset_error();
    if (SECUREC_UNLIKELY(dlock->drid.type == DMS_DR_TYPE_INVALID || dlock->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add spinlock(%s) failed, because lock not initialized", cm_display_lockid(&dlock->drid));
    }
    uint32 spin_times = 0;

    dls_init_dms_ctx(dms_ctx, &dlock->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_TRUE);
    for (;;) {
        int32 ret = dls_do_spin_try_lock(dms_ctx, dlock);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (ret != ERRNO_DMS_DCS_ASK_FOR_RES_MSG_FAULT) {
            dls_cancel_request_lock(dms_ctx);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}

unsigned char dms_spin_timed_lock(dms_context_t *dms_ctx, dms_drlock_t *dlock, unsigned int timeout_ticks)
{
    dms_reset_error();
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;
    if (SECUREC_UNLIKELY(dlock->drid.type == DMS_DR_TYPE_INVALID || dlock->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic(0);
    }

    dls_init_dms_ctx(dms_ctx, &dlock->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    for (;;) {
        if (dls_do_spin_try_lock(dms_ctx, dlock) == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            dls_cancel_request_lock(dms_ctx);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, &wait_ticks, GS_SPIN_COUNT);
    }
}

static inline void dms_wait4releasing(drc_local_lock_res_t *lock_res, spin_statis_instance_t *stat_instance)
{
    uint32 count = 0;
    while (lock_res->releasing) {
        if (++count >= GS_SPIN_COUNT) {
            count = 0;
            cm_spin_sleep();
            SPIN_STAT_INC(stat_instance, wait_times);
        }
    }
}

void dms_spin_lock_innode_s(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    cm_panic_log(dlock->drid.type == DMS_DR_TYPE_SHARED_INNODE, "[DLS](%s)lock type %d is invalid",
        cm_display_lockid(&dlock->drid), dlock->drid.type);

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlock->drid);
    CM_ASSERT(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] add shared_innode lock(%s) stat=%u, lock_mode=%u, shared_count=%u",
        cm_display_lockid(&dlock->drid), (uint32)latch_stat->stat, (uint32)latch_stat->lock_mode,
        (uint32)latch_stat->shared_count);

    dls_init_dms_ctx(dms_ctx, &dlock->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (lock_res->releasing) {
            dms_wait4releasing(lock_res, dms_ctx->stat_instance);
        }

        drc_lock_local_resx(lock_res, dms_ctx->stat, dms_ctx->stat_instance);
        if (latch_stat->stat == LATCH_STATUS_S) {
            CM_ASSERT(latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE);
            CM_ASSERT(DLS_LATCH_IS_LOCKED(latch_stat->stat) && latch_stat->shared_count > 0);
            latch_stat->shared_count++;
            drc_unlock_local_resx(lock_res);
            break;
        }
        CM_ASSERT(latch_stat->stat == LATCH_STATUS_IDLE);
        if (latch_stat->lock_mode != DMS_LOCK_EXCLUSIVE) {
            CM_ASSERT(latch_stat->lock_mode == DMS_LOCK_NULL);
            STAT_RPC_BEGIN;
            // change lock_mode in func dls_modify_lock_mode, before claim owner
            if (!dls_request_spin_lock(dms_ctx, lock_res, 1)) {
                dms_spin_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
                dms_instance_stat_wait_usecs(dms_ctx->stat_instance, STAT_RPC_WAIT_USECS);
                drc_unlock_local_resx(lock_res);
                continue;
            }
            dms_spin_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
            dms_instance_stat_wait_usecs(dms_ctx->stat_instance, STAT_RPC_WAIT_USECS);
        }
        latch_stat->stat = LATCH_STATUS_S;
        latch_stat->shared_count = 1;
        latch_stat->sid = dms_ctx->sess_id;
        drc_unlock_local_resx(lock_res);
        break;
    } while (CM_TRUE);
    STAT_TOTAL_WAIT_USECS_END;
    LOG_DEBUG_INF("[DLS] add shared_innode lock finished");
}

void dms_spin_unlock_innode_s(dms_context_t *dms_ctx, dms_drlock_t *dlock)
{
    cm_panic_log(dlock->drid.type == DMS_DR_TYPE_SHARED_INNODE, "[DLS](%s)lock type %d is invalid",
        cm_display_lockid(&dlock->drid), dlock->drid.type);

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlock->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;
    
    drc_lock_local_resx(lock_res, NULL, NULL);
    CM_ASSERT(latch_stat->shared_count > 0);
    latch_stat->shared_count--;

    if (latch_stat->shared_count == 0) {
        latch_stat->stat = LATCH_STATUS_IDLE;
    }
    LOG_DEBUG_INF("[DLS] shared_innode unlock(%s), shared_count=%u ",
        cm_display_lockid(&dlock->drid), (uint32)latch_stat->shared_count);
    drc_unlock_local_resx(lock_res);
}