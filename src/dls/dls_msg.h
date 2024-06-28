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

#ifdef __cplusplus
extern "C" {
#endif

#define DLS_SPIN_COUNT 1
#define DLS_MSG_RETRY_TIME 3 // ms

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
void dls_cancel_request_lock(dms_context_t *dms_ctx, void *lockid, uint8 len, uint8 type);

void dls_init_dms_ctx(dms_context_t *dms_ctx, void *resid, uint8 len, uint8 type, bool8 is_try);

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

#ifdef __cplusplus
}
#endif
#endif /* __DLS_MSG_H__ */