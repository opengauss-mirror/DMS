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
 * dms_reform_proc_parallel.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc_parallel.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc.h"
#include "dms_error.h"
#include "dms_process.h"
#include "drc_page.h"

static void dms_reform_parallel_thread_inner(parallel_thread_t *parallel)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;

    for (int i = 0; i < parallel->res_num; i++) {
        resource_id_t *res_id = &parallel->res_id[i];
        int ret = parallel_info->parallel_proc(res_id, parallel);
        if (ret != DMS_SUCCESS) {
            (void)cm_atomic32_inc(&parallel_info->parallel_fail);
            LOG_RUN_ERR("[DMS REFORM]dms_reform_parallel_thread_inner error: %d", ret);
            return;
        }
    }
}

static void dms_reform_parallel_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    // this thread will invoke startup method in opengauss
    // need_startup flag need set to be true
    g_dms.callback.dms_thread_init(CM_TRUE, (char **)&thread->reg_data);
#endif
    char thread_name[CM_MAX_THREAD_NAME_LEN];
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = (parallel_thread_t *)thread->argument;
    PRTS_RETVOID_IFERR(sprintf_s(thread_name, CM_MAX_THREAD_NAME_LEN, "dms_parallel_%d", parallel->index));
    cm_set_thread_name(thread_name);

    LOG_RUN_INF("[DMS REFORM]%s thread started", thread_name);
    while (!thread->closed) {
        if (parallel->thread_status == DMS_THREAD_STATUS_IDLE ||
            parallel->thread_status == DMS_THREAD_STATUS_PAUSED) {
            DMS_REFORM_SHORT_SLEEP;
            continue;
        }
        if (parallel->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_DEBUG_INF("[DMS REFORM]%s paused", thread_name);
            parallel->thread_status = DMS_THREAD_STATUS_PAUSED;
            (void)cm_atomic32_dec(&parallel_info->parallel_active);
            continue;
        }
        if (parallel->thread_status == DMS_THREAD_STATUS_RUNNING) {
            dms_reform_parallel_thread_inner(parallel);
            parallel->thread_status = DMS_THREAD_STATUS_PAUSING;
        }
    }
    LOG_RUN_INF("[DMS REFORM]%s thread close", thread_name);
}

int dms_reform_parallel_thread_init(dms_profile_t *dms_profile)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;

    if (dms_profile->parallel_thread_num > DMS_PARALLEL_MAX_THREAD) {
        LOG_RUN_ERR("[DMS REFORM]invalid parameter, parallel_thread_num: %d", dms_profile->parallel_thread_num);
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "parallel_thread_num");
        return ERRNO_DMS_PARAM_INVALID;
    }

    if (dms_profile->parallel_thread_num <= 1) {
        reform_info->parallel_enable = CM_FALSE;
        parallel_info->parallel_num = 0;
        return DMS_SUCCESS;
    }

    parallel_info->parallel_num = dms_profile->parallel_thread_num;
    reform_info->parallel_enable = CM_TRUE;
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        parallel->handle = g_dms.callback.get_db_handle(&parallel->sess_id, DMS_SESSION_TYPE_NONE);
        if (parallel->handle == NULL) {
            LOG_RUN_ERR("[DMS REFORM]fail to get db session");
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
            return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
        }
        parallel->index = i;
        if (cm_create_thread(dms_reform_parallel_thread, 0, (void *)parallel, &parallel->thread) != CM_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]create dms_reform_parallel_%d failed", i);
            return ERR_MES_WORK_THREAD_FAIL;
        }
    }

    return DMS_SUCCESS;
}

void dms_reform_parallel_thread_deinit(void)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;

    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        cm_close_thread(&parallel->thread);
    }
}

// assign resource to all thread
static void dms_reform_parallel_assign_resource(resource_id_t res_id)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    uint32 index = parallel_info->parallel_res_num % parallel_info->parallel_num;
    parallel_thread_t *parallel = &parallel_info->parallel[index];
    parallel->res_id[parallel->res_num] = res_id;
    parallel->res_num++;
    parallel_info->parallel_res_num++;
    CM_ASSERT(parallel->res_num <= DMS_PARALLEL_MAX_RESOURCE);
}

static void dms_reform_parallel_assign_channels(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    resource_id_t res_id = { 0 };
    uint8 node_id = 0;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        node_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(node_id)) {
            continue;
        }
        for (uint8 j = 0; j < reform_ctx->channel_cnt; j++) {
            res_id.node_id = node_id;
            res_id.channel_index = j;
            dms_reform_parallel_assign_resource(res_id);
        }
    }
}

static void dms_reform_parallel_assign_parts_for_clean(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    resource_id_t res_id = { 0 };

    if (share_info->full_clean) {
        for (part_id = 0; part_id < DRC_MAX_PART_NUM; part_id++) {
            res_id.part_id = part_id;
            dms_reform_parallel_assign_resource(res_id);
        }
    } else {
        for (uint8 i = 0; i < inst_part->count; i++) {
            res_id.part_id = part_id;
            dms_reform_parallel_assign_resource(res_id);
            part_id = part_mngr->part_map[part_id].next;
        }
    }
}

static void dms_reform_parallel_assign_parts(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    resource_id_t res_id = { 0 };

    for (uint8 i = 0; i < inst_part->count; i++) {
        res_id.part_id = part_id;
        dms_reform_parallel_assign_resource(res_id);
        part_id = part_mngr->part_map[part_id].next;
    }
}

static void dms_reform_parallel_assign_thread(void)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    resource_id_t res_id = { 0 };

    for (uint8 i = 0; i < parallel_info->parallel_num; i++) {
        res_id.thread_num = (uint8)parallel_info->parallel_num;
        res_id.thread_index = i;
        dms_reform_parallel_assign_resource(res_id);
    }
}

static void dms_reform_parallel_assign_migrate_task(void)
{
    migrate_info_t local_migrate_info;
    resource_id_t res_id = { 0 };

    dms_reform_migrate_collect_local_task(&local_migrate_info);
    for (uint8 i = 0; i < local_migrate_info.migrate_task_num; i++) {
        res_id.migrate_task = local_migrate_info.migrate_task[i];
        dms_reform_parallel_assign_resource(res_id);
    }
}

static int dms_reform_reconnect_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    return mes_connect_batch(&res_id->node_id, 1);
}

static int dms_reform_drc_clean_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = NULL;
    uint16 part_id = res_id->part_id;
    int ret = DMS_SUCCESS;

    if (share_info->full_clean) {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_LOCK_TYPE);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        drc_release_buf_res_by_part(part_list, DRC_RES_PAGE_TYPE);
    } else {
        part_list = &ctx->global_lock_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list, parallel->sess_id);
        DMS_RETURN_IF_ERROR(ret);
        part_list = &ctx->global_buf_res.res_parts[part_id];
        ret = dms_reform_clean_buf_res_by_part(part_list, parallel->sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return DMS_SUCCESS;
}

static int dms_reform_migrate_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    return dms_reform_migrate_inner(&res_id->migrate_task, parallel->handle, parallel->sess_id);
}

static int dms_reform_repair_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = NULL;
    int ret = DMS_SUCCESS;

    // lock
    part_list = &ctx->global_lock_res.res_parts[res_id->part_id];
    ret = dms_reform_repair_by_part(part_list, parallel->handle, parallel->sess_id);
    DMS_RETURN_IF_ERROR(ret);

    // page
    part_list = &ctx->global_buf_res.res_parts[res_id->part_id];
    ret = dms_reform_repair_by_part(part_list, parallel->handle, parallel->sess_id);
    DMS_RETURN_IF_ERROR(ret);

    return DMS_SUCCESS;
}

static int dms_reform_drc_rcy_clean_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = &ctx->global_buf_res.res_parts[res_id->part_id];
    dms_reform_recovery_set_flag_by_part(part_list);
    return DMS_SUCCESS;
}

static int dms_reform_flush_copy_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    bilist_t *part_list = &ctx->global_buf_res.res_parts[res_id->part_id];
    return dms_reform_flush_copy_by_part(part_list, parallel->handle, parallel->sess_id);
}

static int dms_reform_rebuild_parallel_proc(resource_id_t *res_id, parallel_thread_t *parallel)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    int ret = DMS_SUCCESS;

    dms_reform_rebuild_buffer_init((uint8)parallel->index);
    ret = dms_reform_rebuild_buf_res(parallel->handle, parallel->sess_id, (uint8)parallel->index,
        (uint8)parallel_info->parallel_num);
    dms_reform_rebuild_buffer_free(parallel->handle, (uint8)parallel->index);
    DMS_RETURN_IF_ERROR(ret);

    dms_reform_rebuild_buffer_init((uint8)parallel->index);
    ret = dms_reform_rebuild_lock(parallel->sess_id, (uint8)parallel->index, (uint8)parallel_info->parallel_num);
    dms_reform_rebuild_buffer_free(parallel->handle, (uint8)parallel->index);
    DMS_RETURN_IF_ERROR(ret);

    return DMS_SUCCESS;
}

static int dms_reform_ctl_rcy_clean_parallel_proc(resource_id_t* res_id, parallel_thread_t* parallel)
{
    parallel_info_t* parallel_info = DMS_PARALLEL_INFO;
    g_dms.callback.dms_ctl_rcy_clean_parallel(parallel->handle, (uint8)parallel->index,
        (uint8)parallel_info->parallel_num);
    return DMS_SUCCESS;
}

dms_reform_parallel_t g_dms_reform_parallels[DMS_REFORM_PARALLEL_COUNT] = {
    [DMS_REFORM_PARALLEL_RECONNECT] = { "dms_reform_reconnect_parallel", dms_reform_parallel_assign_channels,
    dms_reform_reconnect_parallel_proc },

    [DMS_REFORM_PARALLEL_DRC_CLEAN] = { "dms_reform_drc_clean_parallel", dms_reform_parallel_assign_parts_for_clean,
    dms_reform_drc_clean_parallel_proc },

    [DMS_REFORM_PARALLEL_MIGRATE] = { "dms_reform_migrate_parallel", dms_reform_parallel_assign_migrate_task,
    dms_reform_migrate_parallel_proc },

    [DMS_REFORM_PARALLEL_REPAIR] = { "dms_reform_repair_parallel", dms_reform_parallel_assign_parts,
    dms_reform_repair_parallel_proc },

    [DMS_REFORM_PARALLEL_DRC_RCY_CLEAN] = { "dms_reform_drc_rcy_clean_parallel", dms_reform_parallel_assign_parts,
    dms_reform_drc_rcy_clean_parallel_proc },

    [DMS_REFORM_PARALLEL_FLUSH_COPY] = { "dms_reform_flush_copy_parallel", dms_reform_parallel_assign_parts,
    dms_reform_flush_copy_parallel_proc },

    [DMS_REFORM_PARALLEL_REBUILD] = { "dms_reform_rebuild_parallel", dms_reform_parallel_assign_thread,
    dms_reform_rebuild_parallel_proc },

    [DMS_REFORM_PARALLEL_CTL_RCY_CLEAN] = { "dms_reform_ctl_rcy_clean_parallel", dms_reform_parallel_assign_thread,
    dms_reform_ctl_rcy_clean_parallel_proc },
};

static int dms_reform_parallel_inner(dms_parallel_proc parallel_proc)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;

    // reset callback function and fail_num
    parallel_info->parallel_proc = parallel_proc;
    parallel_info->parallel_fail = 0;
    parallel_info->parallel_active = (atomic32_t)parallel_info->parallel_num;

    // set all assist threads RUNNING
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        parallel->thread_status = DMS_THREAD_STATUS_RUNNING;
    }

    // wait all assist threads FINISH
    while (parallel_info->parallel_active != 0) {
        DMS_REFORM_SHORT_SLEEP;
    }

    // check fail num
    if (parallel_info->parallel_fail != 0) {
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "parallel fail");
        return ERRNO_DMS_REFORM_FAIL;
    }

    return DMS_SUCCESS;
}

static void dms_reform_parallel_assign_init(void)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;

    // reinit assist_thread info
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        parallel->res_num = 0;
    }
    parallel_info->parallel_res_num = 0;
}

static int dms_reform_parallel(dms_reform_parallel_e parallel_type)
{
    CM_ASSERT(parallel_type < DMS_REFORM_PARALLEL_COUNT);
    dms_reform_parallel_t *reform_parallel = &g_dms_reform_parallels[parallel_type];
    int ret = DMS_SUCCESS;

    LOG_RUN_INF("[DMS REFORM][PARALLEL]%s enter", reform_parallel->desc);
    dms_reform_parallel_assign_init();
    reform_parallel->assign_proc();

    ret = dms_reform_parallel_inner(reform_parallel->proc);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM][PARALLEL]%s error, ret: %d", reform_parallel->desc, ret);
        return ret;
    }
    LOG_RUN_INF("[DMS REFORM][PARALLEL]%s success", reform_parallel->desc);
    dms_reform_next_step();
    return DMS_SUCCESS;
}

int dms_reform_reconnect_parallel(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    int ret = dms_reform_parallel(DMS_REFORM_PARALLEL_RECONNECT);
    DMS_RETURN_IF_ERROR(ret);

#ifdef OPENGAUSS
    reform_info->bitmap_connect = share_info->bitmap_online;
#else
    reform_info->bitmap_connect = share_info->bitmap_in;
#endif
    return DMS_SUCCESS;
}

int dms_reform_drc_clean_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_DRC_CLEAN);
}

int dms_reform_migrate_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_MIGRATE);
}

int dms_reform_repair_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_REPAIR);
}

int dms_reform_drc_rcy_clean_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_DRC_RCY_CLEAN);
}

int dms_reform_flush_copy_parallel(void)
{
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FULL_CLEAN)) {
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    return dms_reform_parallel(DMS_REFORM_PARALLEL_FLUSH_COPY);
}

int dms_reform_rebuild_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_REBUILD);
}

int dms_reform_ctl_rcy_clean_parallel(void)
{
    return dms_reform_parallel(DMS_REFORM_PARALLEL_CTL_RCY_CLEAN);
}