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
 * dms_reform_alock.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_alock.c
 *
 * -------------------------------------------------------------------------
 */
#include "drc_res_mgr.h"
#include "dms_reform_msg.h"
#include "dms_reform_proc.h"
#include "dms_reform_proc_stat.h"

// rebuild
int dms_reform_rebuild_alock(void *handle, uint8 thread_index, uint8 thread_num)
{
    return g_dms.callback.rebuild_alock_parallel(handle, thread_index, thread_num);
}

int dms_reform_send_req_alock_rebuild(dms_alock_info_t *lock_info, uint8 new_master, unsigned char thread_index)
{
    int ret;
    uint32 append_size = (uint32)sizeof(dms_alock_info_t);
    if (thread_index == CM_INVALID_ID8) {
        ret = dms_reform_req_rebuild_lock(MSG_REQ_ALOCK_REBUILD, (void *)lock_info, append_size, new_master);
    } else {
        ret = dms_reform_req_rebuild_lock_parallel(MSG_REQ_ALOCK_REBUILD, (void *)lock_info, append_size, new_master,
                                                   thread_index);
    }
    return ret;
}

int dms_alock_rebuild_drc_parallel(dms_context_t *dms_ctx, dms_alock_info_t *lock_info, unsigned char thread_index)
{
    uint8 remaster_id;
    dms_drid_t *lock_id = (dms_drid_t *)&lock_info->resid;
    int ret = drc_get_lock_remaster_id(lock_id, &remaster_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRC][%s]dms_alock_rebuild_drc_parallel, fail to get remaster id", cm_display_lockid(lock_id));
        return ret;
    }
    LOG_DEBUG_INF("[DRC][%s]dms_alock_rebuild_drc_parallel, remaster(%d)", cm_display_lockid(lock_id), remaster_id);

    if (remaster_id == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_ALOCK_LOCAL);
        ret = dms_reform_proc_lock_rebuild(lock_id, lock_info->lock_mode, remaster_id);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_ALOCK_LOCAL);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_ALOCK_REMOTE);
        ret = dms_reform_send_req_alock_rebuild(lock_info, remaster_id, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_ALOCK_REMOTE);
    }
    return ret;
}

int dms_reform_proc_alock_info_rebuild(void *lock_info, uint8 src_inst)
{
    dms_alock_info_t *alock_info = (dms_alock_info_t *)lock_info;
    int ret = dms_reform_proc_lock_rebuild(&alock_info->resid, alock_info->lock_mode, src_inst);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]dms_reform_proc_alock_info_rebuild, myid:%u", g_dms.inst_id);
    }
    return ret;
}

void dms_reform_proc_req_alock_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    dms_reform_proc_req_lock_rebuild_base(ctx, receive_msg, sizeof(dms_alock_info_t),
        dms_reform_proc_alock_info_rebuild);
}