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
#include "cm_timer.h"
#include "dls_msg.h"
#include "dms.h"
#include "dms_error.h"
#include "dms_msg.h"
#include "dms_stat.h"
#include "drc_res_mgr.h"

void dms_init_latch(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned long long oid, unsigned short uid)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, oid, uid, 0, CM_INVALID_ID32, CM_INVALID_ID32);
}

void dms_init_latch2(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned int oid, unsigned short uid, unsigned int idx,
    unsigned int parent_part, unsigned int part)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, oid, uid, idx, parent_part, part);
}

static bool8 dls_request_latch(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode, bool8 timeout, uint32 timeout_ticks)
{
    uint32 spin_times = 0;
    uint32 wait_ticks = 0;

    do {
        if (!dms_drc_accessible(dms_ctx->type) && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
            return CM_FALSE;
        }

        if (dls_request_lock(dms_ctx, lock_res, curr_mode, mode) == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (timeout && SECUREC_UNLIKELY(wait_ticks >= timeout_ticks)) {
            return CM_FALSE;
        }

        dls_sleep(&spin_times, &wait_ticks, DLS_SPIN_COUNT);
    } while (CM_TRUE);
}

static inline bool8 dls_request_latch_s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, bool8 timeout, uint32 timeout_ticks)
{
    dls_init_dms_ctx(dms_ctx, &lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_S_REMOTE, CM_TRUE);
    bool8 ret = dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_SHARE, timeout, timeout_ticks);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S_REMOTE);
    return ret;
}

static inline bool8 dls_request_latch_x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, bool8 timeout, uint32 timeout_ticks)
{
    dls_init_dms_ctx(dms_ctx, &lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_X_REMOTE, CM_TRUE);
    bool8 ret = dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_EXCLUSIVE, timeout, timeout_ticks);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X_REMOTE);
    return ret;
}

static inline void dms_latch_stat_wait_usecs(latch_statis_t *stat, uint64 ss_wait_usecs)
{
    if (LATCH_NEED_STAT(stat)) {
        stat->spin_stat.ss_wait_usecs += ss_wait_usecs;
    }
}

static bool8 dms_latch_timed_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 wait_ticks)
{
    CM_ASSERT(!DLS_LATCH_IS_LOCKED(lock_res->latch_stat.stat));
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        STAT_RPC_BEGIN;
        // change lock_mode in func dls_modify_lock_mode, before claim owner
        if (!dls_request_latch_s(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks)) {
            dms_latch_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
            return CM_FALSE;
        }
        dms_latch_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
    }

    latch_stat->stat = LATCH_STATUS_S;
    latch_stat->shared_count = 1;
    latch_stat->sid = dms_ctx->sess_id;

    return CM_TRUE;
}

static inline bool8 dms_latch_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res)
{
    return dms_latch_timed_idle2s(dms_ctx, lock_res, 1);
}

static inline bool8 dms_wait4_latch_s(drc_local_lock_res_t *lock_res, latch_statis_t *stat,
    uint32 wait_ticks, uint32 *ticks, bool8 is_force)
{
    uint32 count = 0;
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    while (lock_res->releasing || latch_stat->stat == LATCH_STATUS_X ||
        (latch_stat->stat == LATCH_STATUS_IX && !is_force)) {
        if (ticks != NULL && (*ticks) >= wait_ticks) {
            return CM_FALSE;
        }
        if (++count >= GS_SPIN_COUNT) {
            if (ticks != NULL) {
                (*ticks)++;
            }
            count = 0;
            SPIN_STAT_INC(stat, s_sleeps);
            cm_spin_sleep();
        }
    }
    return CM_TRUE;
}

static inline bool8 dms_wait4_latch_x(drc_local_lock_res_t *lock_res, latch_statis_t *stat,
    uint32 wait_ticks, uint32 *ticks)
{
    uint32 count = 0;
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    while (lock_res->releasing || latch_stat->stat == LATCH_STATUS_X || latch_stat->stat == LATCH_STATUS_IX) {
        if (ticks != NULL && (*ticks) >= wait_ticks) {
            return CM_FALSE;
        }
        if (++count >= GS_SPIN_COUNT) {
            if (ticks != NULL) {
                (*ticks)++;
            }
            count = 0;
            SPIN_STAT_INC(stat, x_sleeps);
            cm_spin_sleep();
        }
    }
    return CM_TRUE;
}

void dms_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned char is_force)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_s(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    latch_statis_t *stat = dms_ctx->stat;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;
    
    LOG_DEBUG_INF("[DLS] add latch_s(%s) stat=%u, lock_mode=%u, is_force=%u, shared_count=%u",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat, (uint32)latch_stat->lock_mode,
        (uint32)is_force, (uint32)latch_stat->shared_count);

    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (!lock_res->releasing && (latch_stat->stat < LATCH_STATUS_IX ||
            (latch_stat->stat == LATCH_STATUS_IX && is_force))) {
            drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->s_spin : NULL,
                (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);

            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                if (!dms_latch_idle2s(dms_ctx, lock_res)) {
                    drc_unlock_local_resx(lock_res);
                    continue;
                }
                drc_unlock_local_resx(lock_res);
                break;
            }
            if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
                CM_ASSERT(DLS_LATCH_IS_OWNER(latch_stat->lock_mode) && latch_stat->shared_count > 0);
                latch_stat->shared_count++;
                drc_unlock_local_resx(lock_res);
                break;
            }
            drc_unlock_local_resx(lock_res);
        }
        if (LATCH_NEED_STAT(stat)) {
            stat->misses++;
        }
        (void)dms_wait4_latch_s(lock_res, stat, 0, NULL, is_force);
    } while (CM_TRUE);
    LOG_DEBUG_INF("[DLS] add latch_s finished");
    STAT_TOTAL_WAIT_USECS_END;
}

bool8 dms_latch_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks, unsigned char is_force)
{
    dms_reset_error();
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_timed_s(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif
    bool8 ret = CM_FALSE;
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_S, CM_TRUE);
    if (SECUREC_UNLIKELY(g_dms.scrlock_ctx.enable)) {
        ret = dms_scrlock_timed_s(dms_ctx, dlatch, wait_ticks);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
        return ret;
    }

    uint32 ticks = 0;
    latch_statis_t *stat = dms_ctx->stat;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] add latch_timed_s(%s) stat=%u, lock_mode=%u, is_force=%u, shared_count=%u",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
        (uint32)latch_stat->lock_mode, (uint32)is_force, (uint32)latch_stat->shared_count);

    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (!lock_res->releasing && (latch_stat->stat < LATCH_STATUS_IX ||
            (latch_stat->stat == LATCH_STATUS_IX && is_force))) {
            drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->s_spin : NULL,
                (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);

            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                ret = dms_latch_timed_idle2s(dms_ctx, lock_res, ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0));
                drc_unlock_local_resx(lock_res);
                if (!ret) {
                    dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
                }
                break;
            }
            if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
                CM_ASSERT(DLS_LATCH_IS_OWNER(latch_stat->lock_mode) && latch_stat->shared_count > 0);
                latch_stat->shared_count++;
                drc_unlock_local_resx(lock_res);
                ret = CM_TRUE;
                break;
            }
            drc_unlock_local_resx(lock_res);
        }
        if (LATCH_NEED_STAT(stat)) {
            stat->misses++;
        }
        if (!dms_wait4_latch_s(lock_res, stat, wait_ticks, &ticks, is_force)) {
            break;
        }
    } while (CM_TRUE);
    LOG_DEBUG_INF("[DLS] add latch_timed_s finished, ret:%u", (uint32)ret);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
    STAT_TOTAL_WAIT_USECS_END;
    return ret;
}

static bool32 dls_latch_ix2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, drc_local_latch_t *latch_stat,
    dms_dr_type_t type)
{
    latch_statis_t *stat = dms_ctx->stat;
    uint32 count = 0;

    if (LATCH_NEED_STAT(stat)) {
        stat->misses++;
    }
    while (latch_stat->shared_count > 0) {
        count++;
        if (count >= GS_SPIN_COUNT) {
            SPIN_STAT_INC(stat, ix_sleeps);
            cm_spin_sleep();
            count = 0;
        }
    }

    drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->ix_spin : NULL,
        (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);
    if (latch_stat->shared_count == 0) {
        /* No need to request again */
        if (latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }

        STAT_RPC_BEGIN;
        // change lock_mode in func dls_modify_lock_mode, before claim owner
        if (dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, 1)) {
            dms_latch_stat_wait_usecs(stat, STAT_RPC_WAIT_USECS);
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }
        dms_latch_stat_wait_usecs(stat, STAT_RPC_WAIT_USECS);
    }
    latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
    drc_unlock_local_resx(lock_res);
    return CM_FALSE;
}

static bool32 dls_latch_timed_ix2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    drc_local_latch_t *latch_stat, dms_drlatch_t *dlatch, uint32 wait_ticks)
{
    uint32 count = 0;
    uint32 ticks = 0;
    latch_statis_t *stat = dms_ctx->stat;

    if (LATCH_NEED_STAT(stat)) {
        stat->misses++;
    }
    while (latch_stat->shared_count > 0) {
        if (ticks >= wait_ticks) {
            return CM_FALSE;
        }
        count++;
        if (count >= GS_SPIN_COUNT) {
            SPIN_STAT_INC(stat, ix_sleeps);
            cm_spin_sleep();
            count = 0;
            ticks++;
        }
    }

    drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->ix_spin : NULL,
        (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);
    if (latch_stat->shared_count == 0) {
        /* No need to request again */
        if (latch_stat->lock_mode == DMS_LOCK_EXCLUSIVE) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }

        STAT_RPC_BEGIN;
        // change lock_mode in func dls_modify_lock_mode, before claim owner
        bool8 ret = dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks - ticks);
        if (ret) {
            dms_latch_stat_wait_usecs(stat, STAT_RPC_WAIT_USECS);
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        } else {
            dms_latch_stat_wait_usecs(stat, STAT_RPC_WAIT_USECS);
            drc_unlock_local_resx(lock_res);
            dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
            return CM_FALSE;
        }
    }
    drc_unlock_local_resx(lock_res);
    return CM_FALSE;
}

static bool8 dms_latch_timed_idle2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 wait_ticks)
{
    CM_ASSERT(!DLS_LATCH_IS_LOCKED(lock_res->latch_stat.stat));
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode != DMS_LOCK_EXCLUSIVE) {
        STAT_RPC_BEGIN;
        // change lock_mode in func dls_modify_lock_mode, before claim owner
        if (!dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks)) {
            dms_latch_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
            return CM_FALSE;
        }
        dms_latch_stat_wait_usecs(dms_ctx->stat, STAT_RPC_WAIT_USECS);
    }

    CM_ASSERT(latch_stat->shared_count == 0);
    latch_stat->sid = dms_ctx->sess_id;
    latch_stat->stat = LATCH_STATUS_X;

    return CM_TRUE;
}

static inline bool8 dms_latch_idle2x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res)
{
    return dms_latch_timed_idle2x(dms_ctx, lock_res, 1);
}

void dms_latch_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_x(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    latch_statis_t *stat = dms_ctx->stat;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] add latch_x(%s) stat=%u, lock_mode=%u, shared_count=%u",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat, (uint32)latch_stat->lock_mode,
        (uint32)latch_stat->shared_count);

    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (!lock_res->releasing && latch_stat->stat < LATCH_STATUS_IX) {
            drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->x_spin : NULL,
                (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);

            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                if (!dms_latch_idle2x(dms_ctx, lock_res)) {
                    drc_unlock_local_resx(lock_res);
                    continue;
                }
                drc_unlock_local_resx(lock_res);
                break;
            }
            if (latch_stat->stat == LATCH_STATUS_S) {
                CM_ASSERT(DLS_LATCH_IS_OWNER(latch_stat->lock_mode) && latch_stat->shared_count > 0);
                latch_stat->stat = LATCH_STATUS_IX;
                drc_unlock_local_resx(lock_res);
                if (!dls_latch_ix2x(dms_ctx, lock_res, latch_stat, dlatch->drid.type)) {
                    continue;
                }
                break;
            }
            drc_unlock_local_resx(lock_res);
        }
        if (LATCH_NEED_STAT(stat)) {
            stat->misses++;
        }
        (void)dms_wait4_latch_x(lock_res, stat, 0, NULL);
    } while (CM_TRUE);
    LOG_DEBUG_INF("[DLS] add latch_x(%s) finished", cm_display_lockid(&dlatch->drid));
    STAT_TOTAL_WAIT_USECS_END;
}

bool8 dms_latch_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks)
{
    dms_reset_error();
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] add latch_timed_x(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif
    bool8 ret = CM_FALSE;
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_X, CM_TRUE);
    if (SECUREC_UNLIKELY(g_dms.scrlock_ctx.enable)) {
        ret = dms_scrlock_timed_x(dms_ctx, dlatch, wait_ticks);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
        return ret;
    }

    uint32 ticks = 0;
    latch_statis_t *stat = dms_ctx->stat;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] add latch_timed_x(%s) stat=%u, lock_mode=%u, shared_count=%u",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
        (uint32)latch_stat->lock_mode, (uint32)latch_stat->shared_count);

    STAT_TOTAL_WAIT_USECS_BEGIN;
    do {
        if (!lock_res->releasing && latch_stat->stat < LATCH_STATUS_IX) {
            drc_lock_local_resx(lock_res, (LATCH_NEED_STAT(stat)) ? &stat->x_spin : NULL,
                (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);

            if (latch_stat->stat == LATCH_STATUS_IDLE) {
                ret = dms_latch_timed_idle2x(dms_ctx, lock_res, ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0));
                drc_unlock_local_resx(lock_res);
                if (!ret) {
                    dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
                }
                break;
            }
            if (latch_stat->stat == LATCH_STATUS_S) {
                CM_ASSERT(DLS_LATCH_IS_OWNER(latch_stat->lock_mode) && latch_stat->shared_count > 0);
                latch_stat->stat = LATCH_STATUS_IX;
                drc_unlock_local_resx(lock_res);
                ret = dls_latch_timed_ix2x(dms_ctx, lock_res, latch_stat, dlatch,
                    ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0));
                if (!ret) {
                    drc_lock_local_resx(lock_res, NULL, (LATCH_NEED_STAT(stat)) ? &stat->spin_stat : NULL);
                    latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
                    drc_unlock_local_resx(lock_res);
                }
                break;
            }
            drc_unlock_local_resx(lock_res);
        }
        if (LATCH_NEED_STAT(stat)) {
            stat->misses++;
        }
        if (!dms_wait4_latch_x(lock_res, stat, wait_ticks, &ticks)) {
            break;
        }
    } while (CM_TRUE);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
    STAT_TOTAL_WAIT_USECS_END;
    return ret;
}

void dms_unlatch(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
#ifndef OPENGAUSS
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(
            0, "[DLS] release latch(%s) failed, because latch not initialized", cm_display_lockid(&dlatch->drid));
    }
#endif

    if (SECUREC_UNLIKELY(g_dms.scrlock_ctx.enable)) {
        dms_scrlock_unlock(dms_ctx, dlatch);
        return;
    }

    latch_statis_t *stat = dms_ctx->stat;
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);
#ifdef OPENGAUSS
    CM_ASSERT(DLS_LATCH_IS_OWNER(lock_res->latch_stat.lock_mode));
#endif

    spin_statis_t *stat_spin = NULL;
    spin_statis_instance_t *stat_spin_ex = NULL;

    if (LATCH_NEED_STAT(stat)) {
        stat_spin = (lock_res->latch_stat.stat == LATCH_STATUS_S) ? &stat->s_spin : &stat->x_spin;
        stat_spin_ex = &stat->spin_stat;
    }

    drc_lock_local_resx(lock_res, stat_spin, stat_spin_ex);

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->shared_count > 0) {
        latch_stat->shared_count--;
    }

    if (latch_stat->shared_count == 0) {
        if (latch_stat->stat == LATCH_STATUS_S || latch_stat->stat == LATCH_STATUS_X) {
            latch_stat->stat = LATCH_STATUS_IDLE;
        }
    }

    LOG_DEBUG_INF("[DLS] release latch(%s), shared_count=%u ",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->shared_count);
    drc_unlock_local_resx(lock_res);
}

static int32 dms_try_latch_idle2s(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res)
{
    CM_ASSERT(!DLS_LATCH_IS_LOCKED(lock_res->latch_stat.stat));
    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->lock_mode == DMS_LOCK_NULL) {
        // change lock_mode in func dls_modify_lock_mode, before claim owner
        dls_init_dms_ctx(dms_ctx, &lock_res->resid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_TRUE);
        int32 ret = dls_try_request_lock(dms_ctx, lock_res, DMS_LOCK_NULL, DMS_LOCK_SHARE);
        DMS_RETURN_IF_ERROR(ret);
    }

    latch_stat->stat = LATCH_STATUS_S;
    latch_stat->shared_count = 1;
    latch_stat->sid = dms_ctx->sess_id;
    return DMS_SUCCESS;
}

static int32 dls_try_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    cm_panic(lock_res != NULL);

    drc_lock_local_resx(lock_res, NULL, NULL);
    if (lock_res->releasing) {
        drc_unlock_local_resx(lock_res);
        DMS_THROW_ERROR(ERRNO_DMS_DLS_TRY_LOCK_FAILED);
        return ERRNO_DMS_DLS_TRY_LOCK_FAILED;
    }

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    LOG_DEBUG_INF("[DLS] try add latch_s(%s) stat=%u, lock_mode=%u, shared_count=%u",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->stat,
        (uint32)latch_stat->lock_mode, (uint32)latch_stat->shared_count);

    if (latch_stat->stat == LATCH_STATUS_IDLE) {
        int32 ret = dms_try_latch_idle2s(dms_ctx, lock_res);
        drc_unlock_local_resx(lock_res);
        if (ret != DMS_SUCCESS && ret != ERRNO_DMS_DRC_LOCK_ABANDON_TRY) {
            dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
        }
        LOG_DEBUG_INF("[DLS] try add latch_s finished, result:%d", ret);
        return ret;
    }

    if (latch_stat->stat == LATCH_STATUS_S) {
        CM_ASSERT(DLS_LATCH_IS_OWNER(latch_stat->lock_mode) && latch_stat->shared_count > 0);
        latch_stat->shared_count++;
        drc_unlock_local_resx(lock_res);
        LOG_DEBUG_INF("[DLS] try add latch_s finished, result:success");
        return DMS_SUCCESS;
    }
    drc_unlock_local_resx(lock_res);
    LOG_DEBUG_INF("[DLS] add latch_s finished, result:failed");
    DMS_THROW_ERROR(ERRNO_DMS_DLS_TRY_LOCK_FAILED);
    return ERRNO_DMS_DLS_TRY_LOCK_FAILED;
}

unsigned char dms_try_latch_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    dms_reset_error();
    uint32 spin_times = 0;

    for (;;) {
        int32 ret = dls_try_latch_s(dms_ctx, dlatch);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }

        if (ret != ERRNO_DMS_DCS_ASK_FOR_RES_MSG_FAULT) {
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}

static int dms_ask_res_owner_id_l(dms_context_t *dms_ctx, unsigned char *owner_id)
{
    *owner_id = CM_INVALID_ID8;
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, dms_ctx->sess_type, dms_ctx->intercept_type, CM_TRUE);
    int ret = drc_enter(dms_ctx->resid, dms_ctx->len, dms_ctx->type, options, &drc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (drc == NULL) {
        return DMS_SUCCESS;
    }
    *owner_id = drc->owner;
    drc_leave(drc);
    return DMS_SUCCESS;
}

int dms_get_latch_owner_id(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned char *owner_id)
{
    drc_local_lock_res_t *lock_res = drc_get_local_resx(&dlatch->drid);
    if (lock_res == NULL) {
        LOG_DEBUG_ERR("[DLS] failed to get latch owner id, lock_res is NULL");
        return CM_ERROR;
    }

    dms_ctx->len  = DMS_DRID_SIZE;
    dms_ctx->type = DRC_RES_LOCK_TYPE;
    errno_t err = memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, (char*)&lock_res->resid, dms_ctx->len);
    DMS_SECUREC_CHECK(err);

    uint8 master_id;
    int32 ret = drc_get_master_id(dms_ctx->resid, DRC_RES_LOCK_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DLS] failed to get master id when get latch owner id");
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        return dms_ask_res_owner_id_l(dms_ctx, owner_id);
    } else {
        return dms_ask_res_owner_id_r(dms_ctx, master_id, owner_id);
    }
}

unsigned char dms_try_latch_table(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, dms_lock_mode_t lock_mode)
{
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] try add table latch(%s) lock_mode = %u failed, because table latch not initialized",
            cm_display_lockid(&dlatch->drid), lock_mode);
    }
    dms_reset_error();
    uint32 spin_times = 0;

    dls_init_dms_ctx(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_TRUE);
    for (;;) {
        int32 ret = dls_try_request_lock(dms_ctx, NULL, dms_ctx->curr_mode, lock_mode);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }
        if (ret != ERRNO_DMS_DCS_ASK_FOR_RES_MSG_FAULT) {
            dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}

unsigned char dms_latch_table_timed(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, dms_lock_mode_t lock_mode,
    unsigned int wait_ticks)
{
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add table latch timed(%s) lock_mode = %u failed, because table latch not initialized",
            cm_display_lockid(&dlatch->drid), lock_mode);
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE, CM_TRUE);
    if (!dls_request_latch(dms_ctx, NULL, dms_ctx->curr_mode, lock_mode, CM_TRUE, wait_ticks)) {
        dls_cancel_request_lock(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE);
        LOG_DEBUG_ERR("[DLS] add table latch timed(%s) lock_mode = %u failed", cm_display_lockid(&dlatch->drid),
            lock_mode);
        return CM_FALSE;
    }
    LOG_DEBUG_INF("[DLS] add table latch timed(%s) lock_mode = %u successfully", cm_display_lockid(&dlatch->drid),
        lock_mode);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE);

    return CM_TRUE;
}

unsigned char dms_latch_table(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, dms_lock_mode_t lock_mode)
{
    if (SECUREC_UNLIKELY(dlatch->drid.type == DMS_DR_TYPE_INVALID || dlatch->drid.type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add table latch(%s) lock_mode = %u failed, because table latch not initialized",
            cm_display_lockid(&dlatch->drid), lock_mode);
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, &dlatch->drid, DMS_DRID_SIZE, DRC_RES_LOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE, CM_TRUE);
    if (!dls_request_latch(dms_ctx, NULL, dms_ctx->curr_mode, lock_mode, CM_FALSE, CM_INFINITE_TIMEOUT)) {
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE);
        LOG_DEBUG_ERR("[DLS] add table latch(%s) lock_mode = %u failed", cm_display_lockid(&dlatch->drid), lock_mode);
        return CM_FALSE;
    }
    LOG_DEBUG_INF("[DLS] add table latch(%s) lock_mode = %u successfully", cm_display_lockid(&dlatch->drid), lock_mode);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_TABLE);

    return CM_TRUE;
}

int dms_get_reform_locking(void)
{
    return g_dms.reform_ctx.reform_info.is_locking;
}

void dms_lock_res_ctrl_shared_mode(uint32 sid)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    cm_latch_s(&reform_ctx->res_ctrl_latch, sid, CM_FALSE, NULL);
}

void dms_unlock_res_ctrl()
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    cm_unlatch(&reform_ctx->res_ctrl_latch, NULL);
}

// alatch
unsigned char dms_alatch_timed_s(dms_context_t *dms_ctx, alockid_t *alockid, unsigned int wait_ticks)
{
    if (SECUREC_UNLIKELY(alockid->type == DMS_DR_TYPE_INVALID || alockid->type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add alatch_timed_s(%s) failed, latch not initialized", cm_display_alockid(alockid));
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_S, CM_TRUE);
    if (!dls_request_latch(dms_ctx, NULL, dms_ctx->curr_mode, DMS_LOCK_SHARE, CM_TRUE, wait_ticks)) {
        dls_cancel_request_lock(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_S);
        LOG_DEBUG_ERR("[DLS] add alatch_timed_s(%s) failed", cm_display_alockid(alockid));
        return CM_FALSE;
    }
    LOG_DEBUG_INF("[DLS] add alatch_timed_s(%s) successfully", cm_display_alockid(alockid));
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_S);
    return CM_TRUE;
}

unsigned char dms_alatch_timed_x(dms_context_t *dms_ctx, alockid_t *alockid, unsigned int wait_ticks)
{
    if (SECUREC_UNLIKELY(alockid->type == DMS_DR_TYPE_INVALID || alockid->type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] add alatch_timed_x(%s) failed, latch not initialized", cm_display_alockid(alockid));
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE, CM_FALSE);
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_X, CM_TRUE);
    if (!dls_request_latch(dms_ctx, NULL, dms_ctx->curr_mode, DMS_LOCK_EXCLUSIVE, CM_TRUE, wait_ticks)) {
        dls_cancel_request_lock(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_X);
        LOG_DEBUG_ERR("[DLS] add alatch_timed_x(%s) failed", cm_display_alockid(alockid));
        return CM_FALSE;
    }
    LOG_DEBUG_INF("[DLS] add alatch_timed_x(%s) successfully", cm_display_alockid(alockid));
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_DLS_REQ_ALOCK_X);
    return CM_TRUE;
}

unsigned char dms_try_alatch_s(dms_context_t *dms_ctx, alockid_t *alockid)
{
    if (SECUREC_UNLIKELY(alockid->type == DMS_DR_TYPE_INVALID || alockid->type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] try add alatch_s(%s) failed, latch not initialized", cm_display_alockid(alockid));
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE, CM_TRUE);
    uint32 spin_times = 0;
    for (;;) {
        int32 ret = dls_try_request_lock(dms_ctx, NULL, dms_ctx->curr_mode, DMS_LOCK_SHARE);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }
        if (ret != ERRNO_DMS_DCS_ASK_FOR_RES_MSG_FAULT) {
            dls_cancel_request_lock(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}

unsigned char dms_try_alatch_x(dms_context_t *dms_ctx, alockid_t *alockid)
{
    if (SECUREC_UNLIKELY(alockid->type == DMS_DR_TYPE_INVALID || alockid->type >= DMS_DR_TYPE_MAX)) {
        cm_panic_log(0, "[DLS] try add alatch_x(%s) failed, latch not initialized", cm_display_alockid(alockid));
    }
    dms_reset_error();

    dls_init_dms_ctx(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE, CM_TRUE);
    uint32 spin_times = 0;
    for (;;) {
        int32 ret = dls_try_request_lock(dms_ctx, NULL, dms_ctx->curr_mode, DMS_LOCK_EXCLUSIVE);
        if (ret == DMS_SUCCESS) {
            return CM_TRUE;
        }
        if (ret != ERRNO_DMS_DCS_ASK_FOR_RES_MSG_FAULT) {
            dls_cancel_request_lock(dms_ctx, alockid, DMS_ALOCKID_SIZE, DRC_RES_ALOCK_TYPE);
            return CM_FALSE;
        }
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}
