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
#include "dms_error.h"
#include "drc_lock.h"
#include "dms_msg.h"
#include "dms_stat.h"
#include "drc_page.h"

void dms_init_pl_latch(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned long long oid, unsigned short uid)
{
    DLS_INIT_DR_RES_EX(&dlatch->drid, type, uid, oid, 0);
}

void dms_init_latch(dms_drlatch_t *dlatch, dms_dr_type_t type, unsigned int oid, unsigned short uid)
{
    DLS_INIT_DR_RES(&dlatch->drid, type, oid, uid, 0, CM_INVALID_ID32, CM_INVALID_ID32);
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
        if (!dms_drc_accessible((uint8)DRC_RES_LOCK_TYPE) && dms_ctx->sess_type == DMS_SESSION_NORMAL) {
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
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_S_REMOTE, CM_TRUE);
    bool8 ret = dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_SHARE, timeout, timeout_ticks);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S_REMOTE);
    return ret;
}

static inline bool8 dls_request_latch_x(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res,
    dms_lock_mode_t curr_mode, bool8 timeout, uint32 timeout_ticks)
{
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_X_REMOTE, CM_TRUE);
    bool8 ret = dls_request_latch(dms_ctx, lock_res, curr_mode, DMS_LOCK_EXCLUSIVE, timeout, timeout_ticks);
    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X_REMOTE);
    return ret;
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
    latch_stat->rmid = dms_ctx->rmid;
    latch_stat->rmid_sum = dms_ctx->rmid;
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
                continue;
            }

            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished");
            return;
        } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
            CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);

            latch_stat->shared_count++;
            latch_stat->rmid_sum += dms_ctx->rmid;
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
    latch_stat->rmid = dms_ctx->rmid;
    latch_stat->rmid_sum = dms_ctx->rmid;
    lock_res->is_locked = CM_TRUE;

    return CM_TRUE;
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
 
    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_S, CM_TRUE);
    if (g_dms.scrlock_ctx.enable) {
        bool8 ret = dms_scrlock_timed_s(dms_ctx, dlatch, wait_ticks);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
        return ret;
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
                dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
                return CM_FALSE;
            }
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
            return CM_TRUE;
        } else if ((latch_stat->stat == LATCH_STATUS_S) || (latch_stat->stat == LATCH_STATUS_IX && is_force)) {
            CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);

            latch_stat->shared_count++;
            latch_stat->rmid_sum += dms_ctx->rmid;

            drc_unlock_local_resx(lock_res);
            LOG_DEBUG_INF("[DLS] add latch_s finished");
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
            return CM_TRUE;
        } else {
            drc_unlock_local_resx(lock_res);

            uint32 count = 0;
            while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    LOG_DEBUG_INF("[DLS] add timed latch_s(%s) timeout", cm_display_lockid(&dlatch->drid));
                    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_S);
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
            latch_stat->rmid = dms_ctx->rmid;
            latch_stat->rmid_sum = dms_ctx->rmid;
            latch_stat->stat = LATCH_STATUS_X;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }

        if (dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, 1)) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->rmid = dms_ctx->rmid;
            latch_stat->rmid_sum = dms_ctx->rmid;
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
    drc_local_latch_t *latch_stat, dms_drlatch_t *dlatch, uint32 wait_ticks)
{
    uint32 count = 0;
    uint32 ticks = 0;
    dms_dr_type_t type = dlatch->drid.type;

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
            latch_stat->rmid = dms_ctx->rmid;
            latch_stat->rmid_sum = dms_ctx->rmid;
            latch_stat->stat = LATCH_STATUS_X;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        }
        bool8 ret = dls_request_latch_x(dms_ctx, lock_res, latch_stat->lock_mode, CM_TRUE, wait_ticks - ticks);
        if (ret) {
            latch_stat->sid = dms_ctx->sess_id;
            latch_stat->rmid = dms_ctx->rmid;
            latch_stat->rmid_sum = dms_ctx->rmid;
            latch_stat->stat = LATCH_STATUS_X;
            latch_stat->lock_mode = DMS_LOCK_EXCLUSIVE;
            lock_res->is_owner = CM_TRUE;
            lock_res->is_locked = CM_TRUE;
            latch_stat->shared_count = 0;
            drc_unlock_local_resx(lock_res);
            return CM_TRUE;
        } else {
            drc_unlock_local_resx(lock_res);
            dls_cancel_request_lock(dms_ctx, &dlatch->drid);
            return CM_FALSE;
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
    latch_stat->rmid = dms_ctx->rmid;
    latch_stat->rmid_sum = dms_ctx->rmid;
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
    latch_stat->rmid = dms_ctx->rmid;
    latch_stat->rmid_sum = dms_ctx->rmid;
    latch_stat->stat = LATCH_STATUS_X;
    lock_res->is_locked = CM_TRUE;
    lock_res->is_owner = CM_TRUE;

    return CM_TRUE;
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

    dms_begin_stat(dms_ctx->sess_id, DMS_EVT_LATCH_X, CM_TRUE);
    if (g_dms.scrlock_ctx.enable) {
        bool8 ret = dms_scrlock_timed_x(dms_ctx, dlatch, wait_ticks);
        dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
        return ret;
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
                dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
                return CM_FALSE;
            }
            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
            return CM_TRUE;
        } else if (latch_stat->stat == LATCH_STATUS_S) {
            CM_ASSERT(lock_res->is_locked && lock_res->is_owner && latch_stat->shared_count > 0);

            latch_stat->stat = LATCH_STATUS_IX;

            drc_unlock_local_resx(lock_res);

            if (dls_latch_timed_ix2x(dms_ctx, lock_res, latch_stat, dlatch,
                ((wait_ticks > ticks) ? (wait_ticks - ticks) : 0))) {
                dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
                return CM_TRUE;
            }

            drc_lock_local_resx(lock_res);
            latch_stat->stat = latch_stat->shared_count > 0 ? LATCH_STATUS_S : LATCH_STATUS_IDLE;
            drc_unlock_local_resx(lock_res);

            dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
            return CM_FALSE;
        } else {
            drc_unlock_local_resx(lock_res);

            uint32 count = 0;
            while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {
                if (ticks >= wait_ticks) {
                    LOG_DEBUG_INF("[DLS] add timed latch_x(%s) timeout", cm_display_lockid(&dlatch->drid));
                    dms_end_stat_ex(dms_ctx->sess_id, DMS_EVT_LATCH_X);
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
#ifdef OPENGAUSS
    CM_ASSERT(lock_res->is_owner);
#endif

    drc_lock_local_resx(lock_res);

    drc_local_latch_t *latch_stat = &lock_res->latch_stat;

    if (latch_stat->shared_count > 0) {
        latch_stat->shared_count--;
        latch_stat->rmid_sum -= dms_ctx->rmid;
    }

    if (latch_stat->shared_count == 0) {
        lock_res->is_locked = CM_FALSE;
        latch_stat->rmid_sum = 0;
        if (latch_stat->stat == LATCH_STATUS_S || latch_stat->stat == LATCH_STATUS_X) {
            latch_stat->stat = LATCH_STATUS_IDLE;
        }
    }

    LOG_DEBUG_INF("[DLS] release latch(%s), shared_count=%u, is_locked:%u, ",
        cm_display_lockid(&dlatch->drid), (uint32)latch_stat->shared_count, (uint32)lock_res->is_locked);
    drc_unlock_local_resx(lock_res);
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
    latch_stat->rmid = dms_ctx->rmid;
    latch_stat->rmid_sum = dms_ctx->rmid;
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
        DMS_THROW_ERROR(ERRNO_DMS_DLS_TRY_LOCK_FAILED);
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
        if (ret != DMS_SUCCESS) {
            dls_cancel_request_lock(dms_ctx, &dlatch->drid);
        }
        LOG_DEBUG_INF("[DLS] try add latch_s finished, result:%d", ret);
        return ret;
    }

    if (latch_stat->stat == LATCH_STATUS_S) {
        CM_ASSERT(lock_res->is_owner && lock_res->is_locked && latch_stat->shared_count > 0);
        latch_stat->shared_count++;
        latch_stat->rmid_sum += dms_ctx->rmid;
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

        if (ret != ERR_MES_WAIT_OVERTIME) {
            return CM_FALSE;
        }

        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);
    }
}

static int dms_ask_res_owner_id_l(dms_context_t *dms_ctx, unsigned char *owner_id)
{
    *owner_id = CM_INVALID_ID8;
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, dms_ctx->sess_type, CM_TRUE);
    int ret = drc_enter_buf_res(dms_ctx->resid, DMS_DRID_SIZE, dms_ctx->type, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (buf_res == NULL) {
        return DMS_SUCCESS;
    }
    *owner_id = buf_res->claimed_owner;
    drc_leave_buf_res(buf_res);
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
