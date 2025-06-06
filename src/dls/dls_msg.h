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
 * dls_msg.h
 *
 *
 * IDENTIFICATION
 *    src/dls/dls_msg.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DLS_MSG_H__
#define __DLS_MSG_H__

#include "cm_types.h"
#include "dms.h"
#include "dms_cm.h"
#include "drc_lock.h"
#include "dms_msg.h"
#include "cmpt_msg_mesi.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DLS_SPIN_COUNT 1
#define DLS_MSG_RETRY_TIME 3 // ms
#define DLS_MIN_WAIT_TIME 3000 // ms

/*
 * if type + id can uniquely identify lock resource,
 * you can ignore uid.
 */
#define DLS_INIT_DR_RES(drid, _type, _oid, _uid, _idx, _parent, _part)  \
    do {                                                                \
        dms_reset_drid(drid);                                           \
        (drid)->type = _type;                                           \
        (drid)->oid = _oid;                                             \
        (drid)->uid = _uid;                                             \
        (drid)->index = _idx;                                           \
        (drid)->parent = _parent;                                       \
        (drid)->part = _part;                                           \
    } while (0)

int32 dls_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode);
int32 dls_try_request_lock(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, dms_lock_mode_t curr_mode,
    dms_lock_mode_t mode);
int32 dls_invld_lock_ownership(void *db_handle, char *resid, uint8 res_type, uint8 req_mode, bool8 is_try);
int32 dls_handle_grant_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dls_handle_already_owner_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);
int32 dls_handle_lock_ready_ack(dms_context_t *dms_ctx,
    drc_local_lock_res_t *lock_res, uint8 master_id, dms_message_t *msg, dms_lock_mode_t mode);

int32 dls_owner_transfer_lock(dms_process_context_t *proc_ctx, dms_res_req_info_t *req_info);
void dls_cancel_request_lock(dms_context_t *dms_ctx);

static inline void dls_sleep(uint32 *spin_times, uint32 *wait_ticks, uint32 spin_step)
{
#ifndef WIN32
    fas_cpu_pause();
#endif // !WIN32
    (*spin_times)++;
    if (SECUREC_UNLIKELY(*spin_times == spin_step)) {
        cm_spin_sleep();
        *spin_times = 0;
        if (wait_ticks != NULL) {
            (*wait_ticks)++;
        }
    }
}

static inline void dms_reset_drid(dms_drid_t *drid)
{
    errno_t err = memset_s(drid, sizeof(dms_drid_t), 0, sizeof(dms_drid_t));
    DMS_SECUREC_CHECK(err);
}

static inline void dls_init_dms_ctx(dms_context_t *dms_ctx, drc_local_lock_res_t *lock_res, uint32 sid,
    bool8 is_try)
{
    (void)memset_s(dms_ctx, sizeof(dms_context_t), 0, sizeof(dms_context_t));
    dms_ctx->sess_id        = sid;
    dms_ctx->is_try         = is_try;
    dms_ctx->inst_id        = g_dms.inst_id;
    dms_ctx->len            = (size_t)DMS_DRID_SIZE;
    dms_ctx->type           = DRC_RES_LOCK_TYPE;
    dms_ctx->curr_mode      = lock_res->latch_stat.lock_mode;
    dms_ctx->sess_type      = g_dms.callback.get_session_type(sid);
    dms_ctx->intercept_type = g_dms.callback.get_intercept_type(sid);
    DMS_SECUREC_CHECK(memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, (char*)&lock_res->resid, DMS_DRID_SIZE));
}

static inline void dls_init_dms_ctx_ext(dms_context_t *dms_ctx, void *resid, uint8 len, uint8 type, bool8 is_try)
{
    dms_ctx->len          = len;
    dms_ctx->type         = type;
    dms_ctx->is_try       = is_try;
    dms_ctx->check_handle = dms_ctx->db_handle;
    DMS_SECUREC_CHECK(memcpy_s(dms_ctx->resid, DMS_RESID_SIZE, resid, len));
}

static inline drc_local_lock_res_t *dls_get_lock_res(dms_drlatch_t *dlatch)
{
    drc_local_lock_res_t *lock_res = (drc_local_lock_res_t*)dlatch->handle;
    if (SECUREC_UNLIKELY(lock_res == NULL)) {
        (void)drc_get_lock_resx_by_dlatch(dlatch, &lock_res);
    }
    return lock_res;
}

static inline void dls_enter_lock_res(dms_drlatch_t *dlatch, spin_statis_t *spin_stat,
    spin_statis_instance_t *stat_instance, drc_local_lock_res_t **lock_res)
{
    *lock_res = (drc_local_lock_res_t *)dlatch->handle;
    do {
        if (*lock_res != NULL) {
            cm_spin_lock_with_stat(&(*lock_res)->lock, spin_stat, stat_instance);
            if (dlatch->version == (*lock_res)->version) {
                lock_resx_move_to_lru_head(*lock_res);
                return;
            }
            cm_spin_unlock(&(*lock_res)->lock);
        }
        if (!drc_get_lock_resx_by_dlatch(dlatch, lock_res)) {
            cm_spin_sleep();
        }
    } while (CM_TRUE);
}

static inline void dls_leave_lock_res(drc_local_lock_res_t *lock_res)
{
    cm_spin_unlock(&lock_res->lock);
}

#define DRID_FORMATE       "(%u/%u/%llu/%u/%u)"
#define DRID_ELEMENT(drid) (uint32)(drid)->type,(uint32)(drid)->uid,(drid)->oid,(drid)->index,(drid)->part

#define DLS_WAIT_FOR_LATCH_S                                                                            \
    do {                                                                                                \
        if (LATCH_NEED_STAT(stat)) {                                                                    \
            stat->misses++;                                                                             \
        }                                                                                               \
        while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S &&           \
            !(latch_stat->stat == LATCH_STATUS_IX && is_force)) {                                       \
            if (++count >= GS_SPIN_COUNT) {                                                             \
                SPIN_STAT_INC(stat, s_sleeps);                                                          \
                cm_spin_sleep();                                                                        \
                count = 0;                                                                              \
            }                                                                                           \
        }                                                                                               \
    } while (0)

#define DLS_WAIT_FOR_LATCH_TIMED_S                                                                       \
    do {                                                                                                 \
        if (LATCH_NEED_STAT(stat)) {                                                                     \
            stat->misses++;                                                                              \
        }                                                                                                \
        while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S &&            \
            !(latch_stat->stat == LATCH_STATUS_IX && is_force)) {                                        \
            if (ticks >= wait_ticks) {                                                                   \
                dms_cancel_request_res((char*)&dlatch->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);     \
                LOG_DEBUG_INF("[DLS]%s" DRID_FORMATE " timeout", __func__, DRID_ELEMENT(&dlatch->drid)); \
                return CM_FALSE;                                                                         \
            }                                                                                            \
            if (++count >= GS_SPIN_COUNT) {                                                              \
                ticks++;                                                                                 \
                count = 0;                                                                               \
                cm_spin_sleep();                                                                         \
                SPIN_STAT_INC(stat, s_sleeps);                                                           \
            }                                                                                            \
        }                                                                                                \
    }while (0)

#define DLS_WAIT_FOR_LATCH_X                                                                            \
    do {                                                                                                \
        if (LATCH_NEED_STAT(stat)) {                                                                    \
            stat->misses++;                                                                             \
        }                                                                                               \
        while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {           \
            if (++count >= GS_SPIN_COUNT) {                                                             \
                SPIN_STAT_INC(stat, x_sleeps);                                                          \
                cm_spin_sleep();                                                                        \
                count = 0;                                                                              \
            }                                                                                           \
        }                                                                                               \
    } while (0)

#define DLS_WAIT_FOR_LATCH_TIMED_X                                                                       \
    do {                                                                                                 \
        if (LATCH_NEED_STAT(stat)) {                                                                     \
            stat->misses++;                                                                              \
        }                                                                                                \
        while (latch_stat->stat != LATCH_STATUS_IDLE && latch_stat->stat != LATCH_STATUS_S) {            \
            if (ticks >= wait_ticks) {                                                                   \
                dms_cancel_request_res((char*)&dlatch->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);     \
                LOG_DEBUG_INF("[DLS]%s" DRID_FORMATE " timeout", __func__, DRID_ELEMENT(&dlatch->drid)); \
                return CM_FALSE;                                                                         \
            }                                                                                            \
            if (++count >= GS_SPIN_COUNT) {                                                              \
                SPIN_STAT_INC(stat, x_sleeps);                                                           \
                cm_spin_sleep();                                                                         \
                count = 0;                                                                               \
                ticks++;                                                                                 \
            }                                                                                            \
        }                                                                                                \
    } while (0)

#define DLS_WAIT_LATCH_TIMEOUT                                                                          \
    do {                                                                                                \
        if (ticks >= wait_ticks) {                                                                      \
            dms_cancel_request_res((char*)&dlatch->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);        \
            LOG_DEBUG_INF("[DLS]%s" DRID_FORMATE " timeout", __func__, DRID_ELEMENT(&dlatch->drid));    \
            return CM_FALSE;                                                                            \
        }                                                                                               \
        cm_spin_sleep();                                                                                \
    } while (0)

#define DLS_WAIT_FOR_LOCK_RELEASE                                                                       \
    while (lock_res->releasing || lock_res->recycling) {                                                \
        if (++count >= GS_SPIN_COUNT) {                                                                 \
            cm_spin_sleep();                                                                            \
            count = 0;                                                                                  \
            SPIN_STAT_INC(stat_instance, wait_times);                                                   \
        }                                                                                               \
    }

#define DLS_WAIT_FOR_LOCK_RELEASE_TIMED                                                                 \
    while (lock_res->releasing || lock_res->recycling) {                                                \
        if (ticks >= wait_ticks) {                                                                      \
            dms_cancel_request_res((char*)&dlatch->drid, DMS_DRID_SIZE, sid, DRC_RES_LOCK_TYPE);        \
            LOG_DEBUG_INF("[DLS]%s" DRID_FORMATE " timeout", __func__, DRID_ELEMENT(&dlatch->drid));    \
            return CM_FALSE;                                                                            \
        }                                                                                               \
        if (++count >= GS_SPIN_COUNT) {                                                                 \
            ticks++;                                                                                    \
            count = 0;                                                                                  \
            SPIN_STAT_INC(stat_instance, wait_times);                                                   \
            cm_spin_sleep();                                                                            \
        }                                                                                               \
    }

#define DLS_WAIT_FOR_SPINLOCK                                                                           \
    while (lock_res->latch_stat.stat != LATCH_STATUS_IDLE) {                                            \
        SPIN_STAT_INC(stat, spins);                                                                     \
        if (++count >= GS_SPIN_COUNT) {                                                                 \
            count = 0;                                                                                  \
            cm_spin_sleep();                                                                            \
            SPIN_STAT_INC(stat_instance, wait_times);                                                   \
        }                                                                                               \
    }

#define DLS_WAIT_FOR_LOCK_TRANSFER                                                                      \
    do {                                                                                                \
        if ((g_timer()->now - begin) / MICROSECS_PER_MILLISEC >= DMS_WAIT_MAX_TIME ||                   \
            g_dms.reform_ctx.reform_info.is_locking || is_try) {                                        \
            if (*lock_res != NULL) {                                                                    \
                (*lock_res)->releasing = CM_FALSE;                                                      \
            }                                                                                           \
            LOG_DEBUG_WAR("[DLS] release lock(%s) timeout", cm_display_lockid(lockid));                 \
            return DMS_ERROR;                                                                           \
        }                                                                                               \
        dls_sleep(&spin_times, NULL, GS_SPIN_COUNT);                                                    \
    } while (0)

#ifdef __cplusplus
}
#endif
#endif /* __DLS_MSG_H__ */