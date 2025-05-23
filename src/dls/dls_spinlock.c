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

void dms_init_spinlock(dms_drlock_t *lock, dms_dr_type_t type, unsigned long long oid, unsigned short uid)
{
    DLS_INIT_DR_RES(&lock->drid, type, oid, uid, 0, CM_INVALID_ID32, CM_INVALID_ID32);
    lock->handle  = NULL;
    lock->version = 0;
}

void dms_init_spinlock2(dms_drlock_t *lock, dms_dr_type_t type, unsigned int oid, unsigned short uid, unsigned int idx,
    unsigned int parent_part, unsigned int part)
{
    DLS_INIT_DR_RES(&lock->drid, type, oid, uid, idx, parent_part, part);
    lock->handle  = NULL;
    lock->version = 0;
}

static inline int32 dls_request_spinlock(drc_local_lock_res_t *lock_res, uint32 sid, bool8 is_try)
{
    dms_context_t dms_ctx;
    dls_init_dms_ctx(&dms_ctx, lock_res, sid, is_try);
    return dls_request_lock(&dms_ctx, lock_res, DMS_LOCK_NULL, DMS_LOCK_EXCLUSIVE);
}

static inline void dms_spinlock_stat_wait_usecs(spin_statis_t *stat, spin_statis_instance_t *stat_instance,
    uint64 ss_wait_usecs)
{
    if (stat != NULL) {
        stat->ss_wait_usecs += ss_wait_usecs;
    }
    if (stat_instance != NULL) {
        stat_instance->ss_wait_usecs += ss_wait_usecs;
    }
}

void dms_spin_lock(dms_drlock_t *dlock, unsigned int sid, void *dms_stat, void *inst_stat)
{
    uint32 count = 0;
    drc_local_lock_res_t *lock_res = NULL;
    spin_statis_t *stat = (spin_statis_t*)dms_stat;
    spin_statis_instance_t *stat_instance = (spin_statis_instance_t *)inst_stat;

    LOG_DEBUG_INF("[DLS] entry spinlock" DRID_FORMATE, DRID_ELEMENT(&dlock->drid));

    do {
        dls_enter_lock_res(dlock, stat, stat_instance, &lock_res);

        if (lock_res->releasing || lock_res->recycling) {
            dls_leave_lock_res(lock_res);
            DLS_WAIT_FOR_LOCK_RELEASE;
            continue;
        }
        drc_local_latch_t *latch_stat = &lock_res->latch_stat;

        if (latch_stat->stat != LATCH_STATUS_IDLE) {
            dls_leave_lock_res(lock_res);
            DLS_WAIT_FOR_SPINLOCK;
            continue;
        }

        if (latch_stat->lock_mode == DMS_LOCK_NULL) {
            STAT_RPC_BEGIN;
            if (dls_request_spinlock(lock_res, sid, CM_FALSE) != DMS_SUCCESS) {
                dls_leave_lock_res(lock_res);
                dms_spinlock_stat_wait_usecs(stat, stat_instance, STAT_RPC_WAIT_USECS);
                cm_spin_sleep();
                continue;
            }
            dms_spinlock_stat_wait_usecs(stat, stat_instance, STAT_RPC_WAIT_USECS);
        }
        latch_stat->sid  = sid;
        latch_stat->stat = LATCH_STATUS_X;
        dls_leave_lock_res(lock_res);
        return;
    } while (CM_TRUE);
}

void dms_spin_unlock(dms_drlock_t *dlock)
{
    LOG_DEBUG_INF("[DLS] release spinlock" DRID_FORMATE, DRID_ELEMENT(&dlock->drid));
    drc_local_lock_res_t *lock_res = dls_get_lock_res(dlock);
    cm_panic(lock_res != NULL);
    cm_spin_lock(&lock_res->lock, NULL);
    lock_res->latch_stat.stat = LATCH_STATUS_IDLE;
    cm_spin_unlock(&lock_res->lock);
}

static int32 dls_do_spin_try_lock(dms_drlock_t *dlock, uint32 sid)
{
    drc_local_lock_res_t *lock_res = NULL;
    LOG_DEBUG_INF("[DLS] try add spinlock" DRID_FORMATE, DRID_ELEMENT(&dlock->drid));
    
    dls_enter_lock_res(dlock, NULL, NULL, &lock_res);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->stat != LATCH_STATUS_IDLE || lock_res->releasing || lock_res->recycling) {
        LOG_DEBUG_INF("[DLS] try add spinlock" DRID_FORMATE ", lockmode(%u) is locked",
            DRID_ELEMENT(&dlock->drid), (uint32)latch_stat->lock_mode);
        dls_leave_lock_res(lock_res);
        return ERRNO_DMS_DLS_TRY_LOCK_FAILED;
    }

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        int32 ret = dls_request_spinlock(lock_res, sid, CM_TRUE);
        if (ret != DMS_SUCCESS) {
            dls_leave_lock_res(lock_res);
            return ret;
        }
    }
    latch_stat->stat = LATCH_STATUS_X;
    latch_stat->sid  = sid;
    dls_leave_lock_res(lock_res);
    return DMS_SUCCESS;
}

unsigned char dms_spin_try_lock(dms_drlock_t *dlock, unsigned int sid)
{
    dms_reset_error();
    uint32 spin_times = 0;

    for (;;) {
        int32 ret = dls_do_spin_try_lock(dlock, sid);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (ret != ERRNO_DMS_DCS_SEND_MSG_FAULT && ret != ERRNO_DMS_DCS_RECV_MSG_FAULT) {
            dms_cancel_request_res((char*)&dlock->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, DLS_SPIN_COUNT);
    }
}

unsigned char dms_spin_timed_lock(dms_drlock_t *dlock, unsigned int sid, unsigned int timeout_ticks)
{
    dms_reset_error();
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;

    for (;;) {
        if (dls_do_spin_try_lock(dlock, sid) == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            dms_cancel_request_res((char*)&dlock->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, &wait_ticks, DLS_SPIN_COUNT);
    }
}

void dms_spin_lock_innode_s(dms_drlock_t *dlock, unsigned int sid)
{
    uint32 count = 0;
    drc_local_lock_res_t *lock_res = NULL;
    spin_statis_instance_t *stat_instance = NULL;

    do {
        dls_enter_lock_res(dlock, NULL, NULL, &lock_res);

        if (lock_res->releasing || lock_res->recycling) {
            dls_leave_lock_res(lock_res);
            DLS_WAIT_FOR_LOCK_RELEASE;
            continue;
        }

        drc_local_latch_t *latch_stat = &lock_res->latch_stat;
        LOG_DEBUG_INF("[DLS] add shared_innode lock" DRID_FORMATE " stat=%u, lock_mode=%u, shared_count=%u",
            DRID_ELEMENT(&dlock->drid), (uint32)latch_stat->stat, (uint32)latch_stat->lock_mode,
            (uint32)latch_stat->shared_count);

        if (latch_stat->stat == LATCH_STATUS_S) {
            CM_ASSERT(latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE);
            CM_ASSERT(DLS_LATCH_IS_LOCKED(latch_stat->stat) && latch_stat->shared_count > 0);
            latch_stat->shared_count++;
            dls_leave_lock_res(lock_res);
            break;
        }
        CM_ASSERT(latch_stat->stat == LATCH_STATUS_IDLE);
        if (latch_stat->lock_mode != DMS_LOCK_EXCLUSIVE) {
            CM_ASSERT(latch_stat->lock_mode == DMS_LOCK_NULL);
            if (dls_request_spinlock(lock_res, sid, CM_FALSE) != DMS_SUCCESS) {
                dls_leave_lock_res(lock_res);
                cm_spin_sleep();
                continue;
            }
        }
        latch_stat->stat = LATCH_STATUS_S;
        latch_stat->shared_count = 1;
        latch_stat->sid = sid;
        dls_leave_lock_res(lock_res);
        LOG_DEBUG_INF("[DLS] add shared_innode" DRID_FORMATE " lock finished", DRID_ELEMENT(&dlock->drid));
        return;
    } while (CM_TRUE);
}

void dms_spin_unlock_innode_s(dms_drlock_t *dlock)
{
    drc_local_lock_res_t *lock_res = dls_get_lock_res(dlock);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    cm_spin_lock(&lock_res->lock, NULL);
    CM_ASSERT(latch_stat->shared_count > 0);
    latch_stat->shared_count--;

    if (latch_stat->shared_count == 0) {
        latch_stat->stat = LATCH_STATUS_IDLE;
    }
    LOG_DEBUG_INF("[DLS] shared_innode unlock(%s), shared_count=%u ",
        cm_display_lockid(&dlock->drid), (uint32)latch_stat->shared_count);
    cm_spin_unlock(&lock_res->lock);
}