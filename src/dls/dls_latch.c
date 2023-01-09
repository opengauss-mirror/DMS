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
 * dls_latch.c
 *
 *
 * IDENTIFICATION
 *    src/dls/dls_latch.c
 *
 * -------------------------------------------------------------------------
 */

#include "cm_latch.h"
#include "dcs_msg.h"
#include "dls_msg.h"
#include "dms.h"
#include "dms_errno.h"
#include "drc_lock.h"
#include "dms_msg.h"

void dms_init_latch(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned int oid, unsigned short uid)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, oid, uid, 0, 0, 0);
}

void dms_init_latch2(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned int oid, unsigned short uid, unsigned int idx,
    unsigned int parent_part, unsigned int part)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, oid, uid, idx, parent_part, part);
}

static bool8 dls_request_latch(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, dms_lock_mode_t mode, bool8 timeout, uint32 timeout_ticks)
{
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;

    do {
        if (dls_request_lock(dms_ctx, lock_res, curr_mode, mode) == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (timeout && SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            return CM_FALSE;
        }

#ifndef WIN32
        fas_cpu_pause();
#endif // !WIN32
        spin_times++;
        if (SECUREC_UNLIKELY(spin_times == DLS_SPIN_COUNT)) {
            cm_sleep(DLS_MSG_RETRY_TIME);
            spin_times = 0;
            wait_ticks++;
        }
    } while (CM_TRUE);
}

static inline bool8 dls_request_latch_s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, bool8 timeout, uint32 timeout_ticks)
{
    return dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_SHARE, timeout, timeout_ticks);
}

static inline bool8 dls_request_latch_x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, bool8 timeout, uint32 timeout_ticks)
{
    return dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_EXCLUSIVE, timeout, timeout_ticks);
}

static bool8 dms_latch_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res)
{
    CM_ASSERT(!lock_res->is_locked);

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;
    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        CM_ASSERT(!lock_res->is_owner);

        if (!dls_request_latch_s(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, 1)) {
            return CM_FALSE;
        }

        lock_res->is_owner = CM_TRUE;
        latch_stat->lock_mode = DMS_LOCK_SHARE;
    }

    latch_stat->stat = LATCH_STATUS_S;
    latch_stat->shared_count = 1;
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->sid_sum = dms_ctx->sess_id;
    lock_res->is_locked = CM_TRUE;

    return CM_TRUE;
}

static void dms_latch_spin_sleep(const drc_local_latch_t *latch_stat)
{
    uint32 count = 0;
    while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
        count++;
        if (count >= GS_SPIN_COUNT) {
            cm_spin_sleep();
            count = 0;
        }
    }
}

void dms_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned char is_force)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_s(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    do {
        drc_lock_local_resx(lock_res);

        if (lock_res->releasing) {
            drc_unlock_local_resx(lock_res);
            dms_wait4releasing(lock_res);
            continue;
        }

        drc_local_latch_t *latch_stat = &lock_res->latch_stat;

        LOG_DEBUG_INF("[DLS] add latch_s(%s) stat=%u, lock_mode=%u, is_owner=%u, locked=%u, is_force=%u, "
            "shared_count=%u", cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
            (uint32)latch_stat->lock_mode, (uint32)lock_res->is_owner,
            (uint32)lock_res->is_locked, (uint32)is_force, (uint32)latch_stat->shared_count);

        if (latch_stat->stat == LATCH_STATUS_IDLE) {
            // s->i->s no need for local latch
            // if node already got S or X, can grant S directly
            if (!dms_latch_idle2s(dms_ctx, lock_res)) {
                drc_unlock_local_resx(lock_res);
                cm_sleep(DMS_MSG_SLEEP_TIME);
                continue;
            }

            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished");
            return;
        } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
            CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);

            latch_stat->shared_count++;
            latch_stat->sid_sum += dms_ctx->sess_id;
            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished");
            return;
        } else {
            drc_unlock_local_resx(lock_res);
            dms_latch_spin_sleep(latch_stat);
        }
    } while (CM_TRUE);
}

static bool8 dms_latch_timed_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 wait_ticks)
{
    CM_ASSERT(!lock_res->is_locked);

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        CM_ASSERT(!lock_res->is_owner);

        if (!dls_request_latch_s(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks)) {
            return CM_FALSE;
        }

        latch_stat->lock_mode = DMS_LOCK_SHARE;
        lock_res->is_owner = CM_TRUE;
    }

    latch_stat->stat = LATCH_STATUS_S;
    latch_stat->shared_count = 1;
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->sid_sum = dms_ctx->sess_id;
    lock_res->is_locked = CM_TRUE;

    return CM_TRUE;
}

bool8 dms_latch_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks, unsigned char is_force)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_timed_s(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    if (g_dms.scrlock_ctx.enable) {
        return dms_scrlock_timed_s(dms_ctx, dlatch, wait_ticks);
    }

    uint32 ticks = 0;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    do {
        drc_lock_local_resx(lock_res);

        if (lock_res->releasing) {
            drc_unlock_local_resx(lock_res);
            dms_wait4releasing(lock_res);
            continue;
        }

        drc_local_latch_t *latch_stat = &lock_res->latch_stat;

        LOG_DEBUG_INF("[DLS] add latch_timed_s(%s) stat=%u, lock_mode=%u, is_force=%u, shared_count=%u",
            cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
            (uint32)latch_stat->lock_mode, (uint32)is_force, (uint32)latch_stat->shared_count);

        if (latch_stat->stat == LATCH_STATUS_IDLE) {
            bool8 ret = dms_latch_timed_idle2s(dms_ctx, lock_res, ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0));
            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished, ret:%u", (uint32)ret);
            if (!ret) {
                dls_cancel_request_lock(dms_ctx, &dlatch->drid);
                return CM_FALSE;
            }
            return CM_TRUE;
        } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
            CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);

            latch_stat->shared_count++;
            latch_stat->sid_sum += dms_ctx->sess_id;

            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished");
            return CM_TRUE;
        } else {
            drc_unlock_local_resx(lock_res);

            uint32 count = 0;
            while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    LOG_DEBUG_INF("[DLS] add timed latch_s(%s) timeout", cm_display_lockid(&dlatch->drid));
                    return CM_FALSE;
                }

                count++;
                if (count >= GS_SPIN_COUNT) {
                    cm_spin_sleep();
                    count = 0;
                    ticks++;
                }
            }
        }
    } while (CM_TRUE);
}

static bool32 dls_latch_ix2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, drc_local_latch_t *latch_stat,
    dms_dr_type_t type)
{
    uint32 count = 0;
    while (latch_stat->shared_count > 0) {
        if (drc_owner_table_lock_shared(dms_ctx, latch_stat, type)) {
            break;
        }
        count++;
        if (count >= GS_SPIN_COUNT) {
            cm_spin_sleep();
            count = 0;
        }
    }

    drc_lock_local_resx(lock_res);
    if (latch_stat->shared_count == 0 || drc_owner_table_lock_shared(dms_ctx, latch_stat, type)) {
        /* No need to request again */
        if (latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->sid_sum = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }

        if (dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, 1)) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->sid_sum = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->lock_mode = DMS_LOCK_EXCLUSIVE;
            lock_res->is_locked = CM_TRUE;
            lock_res->is_owner = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }
    }
    latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
    drc_unlock_local_resx(lock_res);
    return CM_FALSE;
}

static bool32 dls_latch_timed_ix2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    drc_local_latch_t *latch_stat, dms_dr_type_t type, uint32 wait_ticks)
{
    uint32 count = 0;
    uint32 ticks = 0;

    while (latch_stat->shared_count > 0) {
        if (drc_owner_table_lock_shared(dms_ctx, latch_stat, type)) {
            break;
        }
        if (ticks >= wait_ticks) {
            return CM_FALSE;
        }
        count++;
        if (count >= GS_SPIN_COUNT) {
            cm_spin_sleep();
            count = 0;
            ticks++;
        }
    }

    drc_lock_local_resx(lock_res);
    if (latch_stat->shared_count == 0 || drc_owner_table_lock_shared(dms_ctx, latch_stat, type)) {
        /* No need to request again */
        if (latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->sid_sum = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }

        if (dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks - ticks)) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->sid_sum = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->lock_mode = DMS_LOCK_EXCLUSIVE;
            lock_res->is_owner = CM_TRUE;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }
    }
    drc_unlock_local_resx(lock_res);
    return CM_FALSE;
}

static bool8 dms_latch_idle2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, drc_local_latch_t *latch_stat)
{
    CM_ASSERT(!lock_res->is_locked);

    if (latch_stat->lock_mode != DMS_LOCK_EXCLUSIVE) {
        if (!dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, 1)) {
            return CM_FALSE;
        }

        latch_stat->lock_mode = DMS_LOCK_EXCLUSIVE;
    }

    CM_ASSERT(latch_stat->shared_count == 0);
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->sid_sum = dms_ctx->sess_id;
    latch_stat->stat = LATCH_STATUS_X;
    lock_res->is_locked = CM_TRUE;
    lock_res->is_owner = CM_TRUE;

    return CM_TRUE;
}

void dms_latch_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_x(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    do {
        drc_lock_local_resx(lock_res);

        if (lock_res->releasing) {
            drc_unlock_local_resx(lock_res);
            dms_wait4releasing(lock_res);
            continue;
        }

        drc_local_latch_t *latch_stat = &lock_res->latch_stat;

        LOG_DEBUG_INF("[DLS] add latch_x(%s) stat=%u, lock_mode=%u, owner=%u, locked=%u, shared_count=%u",
            cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat, (uint32)latch_stat->lock_mode,
            (uint32)lock_res->is_owner, (uint32)lock_res->is_locked, (uint32)latch_stat->shared_count);

        if (latch_stat->stat == LATCH_STATUS_IDLE) {
            if (!dms_latch_idle2x(dms_ctx, lock_res, latch_stat)) {
                drc_unlock_local_resx(lock_res);
                cm_sleep(DMS_MSG_SLEEP_TIME);
                continue;
            }

            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_x(%s) finished", cm_display_lockid(&dlatch->drid));
            return;
        } else if (latch_stat->stat == LATCH_STATUS_S) {
            CM_ASSERT(lock_res->is_locked && lock_res->is_owner && latch_stat->shared_count > 0);

            latch_stat->stat = LATCH_STATUS_IX;
            drc_unlock_local_resx(lock_res);
            if (!dls_latch_ix2x(dms_ctx, lock_res, latch_stat, dlatch->drid.type)) {
                cm_sleep(DMS_MSG_SLEEP_TIME);
                continue;
            }

            LOG_DEBUG_INF("[DLS] add latch_x(%s) finished", cm_display_lockid(&dlatch->drid));
            return;
        } else {
            drc_unlock_local_resx(lock_res);
            dms_latch_spin_sleep(latch_stat);
        }
    } while (CM_TRUE);
}

static bool8 dms_latch_timed_idle2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 wait_ticks)
{
    CM_ASSERT(!lock_res->is_locked);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode != DMS_LOCK_EXCLUSIVE) {
        if (!dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks)) {
            return CM_FALSE;
        }

        latch_stat->lock_mode = DMS_LOCK_EXCLUSIVE;
    }

    CM_ASSERT(latch_stat->shared_count == 0);
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->sid_sum = dms_ctx->sess_id;
    latch_stat->stat = LATCH_STATUS_X;
    lock_res->is_locked = CM_TRUE;
    lock_res->is_owner = CM_TRUE;

    return CM_TRUE;
}

bool8 dms_latch_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_timed_x(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    if (g_dms.scrlock_ctx.enable) {
        return dms_scrlock_timed_x(dms_ctx, dlatch, wait_ticks);
    }

    uint32 ticks = 0;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    do {
        drc_lock_local_resx(lock_res);

        if (lock_res->releasing) {
            drc_unlock_local_resx(lock_res);
            dms_wait4releasing(lock_res);
            continue;
        }

        drc_local_latch_t *latch_stat = &lock_res->latch_stat;

        LOG_DEBUG_INF("[DLS] add latch_timed_x(%s) stat=%u, lock_mode=%u, shared_count=%u",
            cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
            (uint32)latch_stat->lock_mode, (uint32)latch_stat->shared_count);

        if (latch_stat->stat == LATCH_STATUS_IDLE) {
            bool8 ret =
                dms_latch_timed_idle2x(dms_ctx, lock_res, ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0));

            drc_unlock_local_resx(lock_res);
            if (!ret) {
                dls_cancel_request_lock(dms_ctx, &dlatch->drid);
                return CM_FALSE;
            }
            return CM_TRUE;
        } else if (latch_stat->stat == LATCH_STATUS_S) {
            CM_ASSERT(lock_res->is_locked && lock_res->is_owner && latch_stat->shared_count > 0);

            latch_stat->stat = LATCH_STATUS_IX;

            drc_unlock_local_resx(lock_res);

            if (dls_latch_timed_ix2x(dms_ctx, lock_res, latch_stat, dlatch->drid.type,
                ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0))) {
                return CM_TRUE;
            }

            drc_lock_local_resx(lock_res);
            latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
            drc_unlock_local_resx(lock_res);

            dls_cancel_request_lock(dms_ctx, &dlatch->drid);
            return CM_FALSE;
        } else {
            drc_unlock_local_resx(lock_res);

            uint32 count = 0;
            while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    LOG_DEBUG_INF("[DLS] add timed latch_x(%s) timeout", cm_display_lockid(&dlatch->drid));
                    return CM_FALSE;
                }

                count++;
                if (count >= GS_SPIN_COUNT) {
                    cm_spin_sleep();
                    count = 0;
                    ticks++;
                }
            }
        }
    } while (CM_TRUE);
}

void dms_unlatch(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] release latch(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    if (g_dms.scrlock_ctx.enable) {
        dms_scrlock_unlock(dms_ctx, dlatch);
        return;
    }

    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
    CM_ASSERT(lock_res->is_owner);

    drc_lock_local_resx(lock_res);

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->shared_count > 0) {
        latch_stat->shared_count--;
        latch_stat->sid_sum -= dms_ctx->sess_id;
    }

    if (latch_stat->shared_count == 0) {
        lock_res->is_locked = CM_FALSE;
        latch_stat->sid_sum = 0;
        if (latch_stat->stat == LATCH_STATUS_S || latch_stat->stat == LATCH_STATUS_X) {
            latch_stat->stat = LATCH_STATUS_IDLE;
        }
    }

    drc_unlock_local_resx(lock_res);

    LOG_DEBUG_INF("[DLS] release latch(%s), shared_count=%u, is_locked:%u, ",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->shared_count, (uint32)lock_res->is_locked);
}

void dms_latch_degrade(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    CM_ASSERT(lock_res != NULL);

    drc_lock_local_resx(lock_res);
    CM_ASSERT(lock_res->latch_stat.stat == LATCH_STATUS_X);

    lock_res->latch_stat.stat = LATCH_STATUS_S;
    lock_res->latch_stat.shared_count = 1;

    drc_unlock_local_resx(lock_res);
}

static int32 dms_try_latch_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res)
{
    CM_ASSERT(!lock_res->is_locked);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        CM_ASSERT(!lock_res->is_owner);

        int32 ret = dls_try_request_lock(dms_ctx, lock_res, DMS_LOCK_NULL, DMS_LOCK_SHARE);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
        lock_res->is_owner = CM_TRUE;
        latch_stat->lock_mode = DMS_LOCK_SHARE;
    }

    latch_stat->stat = LATCH_STATUS_S;
    latch_stat->shared_count = 1;
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->sid_sum = dms_ctx->sess_id;
    lock_res->is_locked = CM_TRUE;
    return DMS_SUCCESS;
}

static int32 dls_try_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    drc_lock_local_resx(lock_res);
    if (lock_res->releasing) {
        drc_unlock_local_resx(lock_res);
        return ERRNO_DMS_DLS_TRY_LOCK_FAILED;
    }

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] try add latch_s(%s) stat=%u, lock_mode=%u, is_owner=%u, locked=%u, "
        "shared_count=%u", cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
        (uint32)latch_stat->lock_mode, (uint32)lock_res->is_owner,
        (uint32)lock_res->is_locked, (uint32)latch_stat->shared_count);

    if (latch_stat->stat == LATCH_STATUS_IDLE) {
        int32 ret = dms_try_latch_idle2s(dms_ctx, lock_res);
        drc_unlock_local_resx(lock_res);
        LOG_DEBUG_INF("[DLS] try add latch_s finished, result:%d", ret);
        return ret;
    }

    if (latch_stat->stat == LATCH_STATUS_S) {
        CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);
        latch_stat->shared_count++;
        latch_stat->sid_sum += dms_ctx->sess_id;
        drc_unlock_local_resx(lock_res);
        LOG_DEBUG_INF("[DLS] try add latch_s finished, result:success");
        return DMS_SUCCESS;
    }
    drc_unlock_local_resx(lock_res);
    LOG_DEBUG_INF("[DLS] add latch_s finished, result:failed");
    return ERRNO_DMS_DLS_TRY_LOCK_FAILED;
}

unsigned char dms_try_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    uint32 spin_times = 0;

    for (;;) {
        int32 ret = dls_try_latch_s(dms_ctx, dlatch);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (ret != ERR_MES_WAIT_OVERTIME) {
            dls_cancel_request_lock(dms_ctx, &dlatch->drid);
            return CM_FALSE;
        }

#ifndef WIN32
        fas_cpu_pause();
#endif // !WIN32

        spin_times++;
        if (SECUREC_UNLIKELY(spin_times == GS_SPIN_COUNT)) {
            cm_spin_sleep();
            spin_times = 0;
        }
    }
}
