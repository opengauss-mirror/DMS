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
 * dms_reform.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform.h"
#include "dms_reform_proc.h"
#include "dms_reform_judge.h"
#include "dms_reform_preempt.h"
#include "dms_reform_msg.h"
#include "dms_error.h"
#include "cm_timer.h"
#include "dms_reform_health.h"
#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_fault_inject.h"
#ifndef WIN32
#include "config.h"
#endif



bool8 dms_dst_id_is_self(uint8 dst_id)
{
    return g_dms.inst_id == dst_id;
}

bool8 dms_reform_list_exist(instance_list_t *list, uint8 inst_id)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (list->inst_id_list[i] == inst_id) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

void dms_reform_list_to_bitmap(uint64 *bitmap, instance_list_t *list)
{
    *bitmap = 0;
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        bitmap64_set(bitmap, (uint8)list->inst_id_list[i]);
    }
}

void dms_reform_bitmap_to_list(instance_list_t *list, uint64 bitmap)
{
    dms_reform_list_init(list);

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&bitmap, i)) {
            dms_reform_list_add(list, i);
        }
    }
}

int dms_reform_in_process(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (reform_info->thread_status == DMS_THREAD_STATUS_RUNNING ||
        reform_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
        return CM_TRUE;
    } else {
        return CM_FALSE;
    }
}

int dms_drc_accessible(unsigned char res_type)
{
    drc_global_res_map_t *res_map = drc_get_global_res_map(res_type);
    switch (res_type) {
        case DRC_RES_PAGE_TYPE:
            return (int)res_map->drc_accessible_stage == DRC_ACCESS_STAGE_ALL_ACCESS;
        case DRC_RES_ALOCK_TYPE:
        case DRC_RES_LOCK_TYPE:
            return (int)res_map->drc_accessible_stage != DRC_ACCESS_STAGE_ALL_INACCESS;
        case DRC_RES_GLOBAL_XA_TYPE:
            return (int)res_map->drc_accessible_stage != DRC_ACCESS_STAGE_ALL_INACCESS;
        default:
            return CM_TRUE;
    }
}

static void dms_reform_proc_set_running(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    while (CM_TRUE) {
        if (reform_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            reform_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            break;
        }
        DMS_REFORM_SHORT_SLEEP;
    }
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc running");
    reform_info->thread_status = DMS_THREAD_STATUS_RUNNING;
    cm_sem_post(&reform_context->sem_proc);
}

#ifndef OPENGAUSS
static void dms_reform_set_reform_behavior(void)
{
    g_dms.callback.set_inst_behavior(g_dms.reform_ctx.handle_judge, DMS_INST_BEHAVIOR_IN_REFORM);
}
#endif

void dms_reform_set_start(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_INF("[DMS REFORM]dms_reform_set_start");
#ifndef OPENGAUSS
    dms_reform_set_reform_behavior();
#endif
    reform_info->reform_fail = CM_FALSE;
    reform_info->true_start = CM_FALSE;
    reform_info->reform_done = CM_FALSE;
    reform_info->err_code = DMS_SUCCESS;
    reform_info->reform_step_index = 0;
    reform_info->reform_phase_index = 0;
    reform_info->reform_phase = 0;
    reform_info->reform_pause = CM_FALSE;
    reform_info->current_step = (uint8)share_info->reform_step[reform_info->reform_step_index++];
    reform_info->proc_time = (uint64)g_timer()->now;
    dms_reform_proc_stat_clear_current();
    dms_reform_health_set_running();
    dms_reform_proc_set_running();
    dms_rebuild_assist_list_init();
#ifndef OPENGAUSS
    if (share_info->reform_type != DMS_REFORM_TYPE_FOR_AZ_FAILOVER &&
        share_info->reform_type != DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE &&
        share_info->reform_type != DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_PROMOTE) {
        g_dms.callback.reset_link(g_dms.reform_ctx.handle_normal);
    }
#endif

    LOG_DEBUG_FUNC_SUCCESS;
}

static int dms_reform_init_thread(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;

    cm_sem_init(&reform_context->sem_proc);
    ret = cm_create_thread(dms_reform_proc_thread, 0, NULL, &reform_context->thread_reform);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]fail to create dms_reform_thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    ret = cm_create_thread(dms_reform_judgement_thread, 0, NULL, &reform_context->thread_judgement);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]fail to create dms_reform_judgement_thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    ret = cm_create_thread(dms_reformer_preempt_thread, 0, NULL, &reform_context->thread_reformer);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]fail to create dms_reformer_thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    cm_sem_init(&reform_context->sem_health);
    ret = cm_create_thread(dms_reform_health_thread, 0, NULL, &reform_context->thread_health);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]fail to create dms_reform_health_thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    return DMS_SUCCESS;
}

#ifndef OPENGAUSS
#ifndef UT_TEST
static bool8 dms_reform_get_maintain(void)
{
    if (g_dms.callback.check_is_maintain == NULL) {
        cm_panic_log(0, "[DMS REFORM]check_is_maintain interface is NULL");
    }

    unsigned int is_maintain = g_dms.callback.check_is_maintain();
    LOG_RUN_INF("[DMS REFORM]DMS_MAINTAIN is %s", (is_maintain > 0) ? "TRUE" : "FALSE");
    return (bool8)is_maintain;
}
#endif
#endif

static void dms_reform_init_for_maintain(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    drc_part_t *part_map = NULL;

    if (!reform_info->maintain) {
        return;
    }

    ctx->global_alock_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_lock_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_xa_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    inst_part->count = DRC_MAX_PART_NUM;
    inst_part->expected_num = DRC_MAX_PART_NUM;
    inst_part->first = CM_INVALID_ID16;
    inst_part->last = CM_INVALID_ID16;
    for (uint8 i = 0; i < DRC_MAX_PART_NUM; i++) {
        part_map = &part_mngr->part_map[i];
        part_map->inst_id = (uint8)g_dms.inst_id;
        part_map->next = inst_part->first;
        inst_part->first = i;
        if (inst_part->last == CM_INVALID_ID16) {
            inst_part->last = i;
        }
    }
}

void dms_reform_db_handle_deinit(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    DMS_RELEASE_DB_HANDLE(reform_context->handle_proc);
    DMS_RELEASE_DB_HANDLE(reform_context->handle_judge);
    DMS_RELEASE_DB_HANDLE(reform_context->handle_normal);
    DMS_RELEASE_DB_HANDLE(reform_context->handle_health);

    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        DMS_RELEASE_DB_HANDLE(parallel->handle);
    }
}

static void dms_init_scrlock_ctx(dms_profile_t *dms_profile)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    errno_t ret = memcpy_s(reform_context->scrlock_reinit_ctx.log_path, DMS_OCK_LOG_PATH_LEN,
        dms_profile->ock_log_path, DMS_OCK_LOG_PATH_LEN);
    DMS_SECUREC_CHECK(ret);
    reform_context->scrlock_reinit_ctx.scrlock_server_port = dms_profile->scrlock_server_port;
    reform_context->scrlock_reinit_ctx.log_level = dms_profile->scrlock_log_level;
    reform_context->scrlock_reinit_ctx.worker_num = dms_profile->scrlock_worker_cnt;
    reform_context->scrlock_reinit_ctx.worker_bind_core = dms_profile->enable_scrlock_worker_bind_core;
    reform_context->scrlock_reinit_ctx.worker_bind_core_start = dms_profile->scrlock_worker_bind_core_start;
    reform_context->scrlock_reinit_ctx.worker_bind_core_end = dms_profile->scrlock_worker_bind_core_end;
    reform_context->scrlock_reinit_ctx.sleep_mode = dms_profile->enable_scrlock_server_sleep_mode;
    reform_context->scrlock_reinit_ctx.server_bind_core_start = dms_profile->scrlock_server_bind_core_start;
    reform_context->scrlock_reinit_ctx.server_bind_core_end = dms_profile->scrlock_server_bind_core_end;
    reform_context->scrlock_reinit_ctx.enable_ssl = dms_profile->enable_ssl;
}

static int32 dms_reform_init_db_handle()
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

    reform_context->handle_proc = g_dms.callback.get_db_handle(&reform_context->sess_proc, DMS_SESSION_TYPE_NONE);
    if (reform_context->handle_proc == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_judge = g_dms.callback.get_db_handle(&reform_context->sess_judge, DMS_SESSION_TYPE_NONE);
    if (reform_context->handle_judge == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_normal = g_dms.callback.get_db_handle(&reform_context->sess_normal, DMS_SESSION_TYPE_NONE);
    if (reform_context->handle_normal == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_health = g_dms.callback.get_db_handle(&reform_context->sess_health, DMS_SESSION_TYPE_NONE);
    if (reform_context->handle_health == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }

    return DMS_SUCCESS;
}

int dms_reform_init(dms_profile_t *dms_profile)
{
    LOG_RUN_INF("[DMS] dms_reform_init start");
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;
    g_dms.cluster_ver = 0;

    if (g_dms.scrlock_ctx.enable) {
        dms_init_scrlock_ctx(dms_profile);
    }

    reform_context->catalog_centralized = (bool8)dms_profile->resource_catalog_centralized;
    reform_context->channel_cnt = dms_profile->channel_cnt;
    reform_context->mes_has_init = (bool8)dms_profile->conn_created_during_init;
    reform_context->share_info_lock = 0;

    DMS_RFI_INIT(dms_profile->gsdb_home);

    if ((ret = dms_reform_init_db_handle()) != DMS_SUCCESS) {
        return ret;
    }

#if defined(OPENGAUSS) || defined(UT_TEST)
    reform_info->build_complete = CM_TRUE;
    reform_info->maintain = CM_FALSE;
    reform_info->rst_recover = CM_FALSE;
#else
    bool32 build_complete = CM_FALSE;
    // Notice: judgement thread does not work at this moment, so handle_judge can be used here
    g_dms.callback.check_if_build_complete(g_dms.reform_ctx.handle_judge, &build_complete);
    reform_info->build_complete = (bool8)build_complete;
    bool32 rst_recover = CM_FALSE;
    g_dms.callback.check_if_restore_recover(g_dms.reform_ctx.handle_judge, &rst_recover);
    reform_info->rst_recover = (bool8)rst_recover;
    reform_info->maintain = dms_reform_get_maintain();
    reform_info->file_unable = CM_FALSE;
    reform_info->ddl_unable = CM_FALSE;
#endif
    if (reform_info->build_complete && !reform_info->maintain) {
        ret = dms_reform_cm_res_init();
        if (ret != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
            return ret;
        }
    }
    reform_info->reformer_id = CM_INVALID_ID8;
    reform_info->start_time = (uint64)g_timer()->now;
    reform_context->ignore_offline = CM_TRUE;
    share_info->version_num = 0;

    ret = dms_reform_parallel_thread_init(dms_profile);
    DMS_RETURN_IF_ERROR(ret);

    ret = dms_reform_init_thread();
    DMS_RETURN_IF_ERROR(ret);
    dms_reform_init_for_maintain();

    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_OUT);
    LOG_RUN_INF("[DMS REFORM] dms reform init success. time: %llu", reform_info->start_time);
    return DMS_SUCCESS;
}

void dms_reform_uninit(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

#ifdef DMS_TEST
    dms_reform_cm_simulation_uninit();
#endif
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->reform_fail = CM_TRUE;
    LOG_RUN_INF("[DMS REFORM]set reform fail, dms_reform_uninit");
    cm_close_thread(&reform_context->thread_judgement);
    cm_close_thread(&reform_context->thread_reformer);
    cm_close_thread_with_sem(&reform_context->thread_reform, &reform_context->sem_proc);
    cm_close_thread_with_sem(&reform_context->thread_health, &reform_context->sem_health);
    cm_sem_destroy(&reform_context->sem_proc);
    cm_sem_destroy(&reform_context->sem_health);
    dms_reform_parallel_thread_deinit();
    dms_reform_db_handle_deinit();
    DMS_RFI_DEINIT;
}

int dms_wait_reform(unsigned int *has_offline)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;

#ifndef OPENGAUSS
    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_JOIN);
#endif

    while (!DMS_FIRST_REFORM_FINISH) {
        DMS_REFORM_SHORT_SLEEP;
        if (reform_info->last_fail) {
            if (DMS_FIRST_REFORM_FINISH) {
                return CM_TRUE;
            }
            return CM_FALSE;
        }
    }

    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_IN);
    return CM_TRUE;
}

int dms_wait_reform_finish(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    while (!DMS_FIRST_REFORM_FINISH) {
        if (reform_info->last_fail) {
            if (DMS_FIRST_REFORM_FINISH) {
                return CM_TRUE;
            }
            return CM_FALSE;
        }
        DMS_REFORM_SHORT_SLEEP;
    }

    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_IN);
    return CM_TRUE;
}

char *dms_reform_phase_desc(uint8 reform_phase)
{
    switch (reform_phase) {
        case DMS_PHASE_START:
            return "START";
        case DMS_PHASE_AFTER_DRC_ACCESS:
            return "DRC ACCESS";
        case DMS_PHASE_AFTER_RECOVERY:
            return "RECOVERY";
        case DMS_PHASE_AFTER_TXN_DEPOSIT:
            return "AFTER TXN DEPOSIT";
        case DMS_PHASE_BEFORE_ROLLBACK:
            return "BEFORE ROLLBACK";
        case DMS_PHASE_END:
            return "END";
        default:
            return "UNKNOWN PHASE";
    }
}

int dms_wait_reform_phase(unsigned char reform_phase)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_INF("[DMS REFORM] wait reform phase %s start", dms_reform_phase_desc(reform_phase));
    while (CM_TRUE) {
        if (reform_info->last_fail) {
            LOG_RUN_ERR("[DMS REFORM] wait reform phase %s error", dms_reform_phase_desc(reform_phase));
            return CM_FALSE;
        }
        if (reform_info->reform_phase >= reform_phase) {
            LOG_RUN_INF("[DMS REFORM] wait reform phase %s finish", dms_reform_phase_desc(reform_phase));
            return CM_TRUE;
        }
        DMS_REFORM_SHORT_SLEEP;
    }
}

void dms_set_reform_continue(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->reform_pause = CM_FALSE;
}

int dms_reform_failed(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    return reform_info->reform_fail;
}

int dms_is_recovery_session(unsigned int sid)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;

    if (reform_context->sess_proc == sid) {
        return (int)DMS_SESSION_RECOVER;
    } else {
        return (int)DMS_SESSION_NORMAL;
    }
}

int dms_switchover(unsigned int sess_id)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    dms_reform_req_switchover_t req;
    uint8 reformer_id = reform_info->reformer_id;
    uint64 start_time = 0;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_switchover(&req, reformer_id, (uint16)sess_id);

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_switchover SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_switchover_wait(req.head.ruid, &start_time);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_switchover WAIT overtime, dst_id: %d", req.head.dst_inst);
            continue;
        } else if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_switchover protocol version not match, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }
    DMS_RETURN_IF_ERROR(ret);

    cm_spin_lock(&switchover_info->lock, NULL);
    // record reformer version, if reformer changed or restart, send error to stop the session which has run switchover
    switchover_info->reformer_version.inst_id = reformer_id;
    switchover_info->reformer_version.start_time = start_time;
    switchover_info->switch_start = CM_TRUE;
    cm_spin_unlock(&switchover_info->lock);

    return DMS_SUCCESS;
}

int dms_az_failover(unsigned int sess_id)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    az_switchover_info_t *failover_info = DMS_AZ_SWITCHOVER_INFO;
    dms_reform_req_az_failover_t req = { 0 };
    uint8 reformer_id = reform_info->reformer_id;
    uint64 start_time = 0;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (DMS_IS_REFORMER) {
            cm_spin_lock(&failover_info->lock, NULL);
            if (failover_info->switch_req) {
                cm_spin_unlock(&failover_info->lock);
                LOG_DEBUG_ERR("[DMS REFORM]dms_az_failover SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
                return DMS_ERROR;
            }
            cm_spin_unlock(&failover_info->lock);
            break;
        }

        dms_reform_init_req_az_failover(&req, reformer_id, (uint16)sess_id);
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_az_failover SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_az_failover_wait(req.head.ruid, &start_time);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_failover WAIT overtime, dst_id: %d", req.head.dst_inst);
            continue;
        } else if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_failover protocol version not match, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }
    DMS_RETURN_IF_ERROR(ret);

    cm_spin_lock(&failover_info->lock, NULL);
    // record reformer version, if reformer changed or restart, send error to stop the session which has run switchover
    failover_info->switch_req = CM_TRUE;
    failover_info->reformer_version.inst_id = reformer_id;
    failover_info->reformer_version.start_time = reform_info->start_time;
    failover_info->switch_start = CM_TRUE;
    failover_info->switch_type = AZ_FAILOVER;
    failover_info->inst_id = reformer_id;
    failover_info->sess_id = sess_id;
    cm_spin_unlock(&failover_info->lock);

    return DMS_SUCCESS;
}

int dms_az_switchover_demote(unsigned int sess_id)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
    dms_reform_req_az_switchover_t req = { 0 };
    uint8 reformer_id = reform_info->reformer_id;
    uint64 start_time = 0;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (DMS_IS_REFORMER) {
            cm_spin_lock(&switchover_info->lock, NULL);
            if (switchover_info->switch_req) {
                cm_spin_unlock(&switchover_info->lock);
                LOG_DEBUG_ERR("[DMS REFORM] dms_az_switchover_demote SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
                return DMS_ERROR;
            }
            cm_spin_unlock(&switchover_info->lock);
            break;
        }

        dms_reform_init_req_az_switchover_demote(&req, reformer_id, (uint16)sess_id);

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM] dms_az_switchover_demote SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_az_switchover_wait(req.head.ruid, &start_time);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_switchover_demote WAIT overtime, dst_id: %d", req.head.dst_inst);
            continue;
        } else if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_switchover_demote protocol version not match, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }
    DMS_RETURN_IF_ERROR(ret);

    cm_spin_lock(&switchover_info->lock, NULL);
    // record reformer version, if reformer changed or restart, send error to stop the session which has run switchover
    switchover_info->switch_req = CM_TRUE;
    switchover_info->reformer_version.inst_id = reformer_id;
    switchover_info->reformer_version.start_time = start_time;
    switchover_info->switch_start = CM_TRUE;
    switchover_info->switch_type = AZ_SWITCHOVER;
    switchover_info->inst_id = reformer_id;
    switchover_info->sess_id = sess_id;
    cm_spin_unlock(&switchover_info->lock);

    return DMS_SUCCESS;
}

int dms_az_switchover_promote(unsigned int sess_id)
{
    dms_reset_error();
    reform_info_t *reform_info = DMS_REFORM_INFO;
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
    dms_reform_req_az_switchover_t req = { 0 };
    uint8 reformer_id = reform_info->reformer_id;
    uint64 start_time = 0;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (DMS_IS_REFORMER) {
            cm_spin_lock(&switchover_info->lock, NULL);
            if (switchover_info->switch_req) {
                cm_spin_unlock(&switchover_info->lock);
                LOG_DEBUG_ERR("[DMS REFORM] dms_az_switchover_promote SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
                return DMS_ERROR;
            }
            cm_spin_unlock(&switchover_info->lock);
            break;
        }

        dms_reform_init_req_az_switchover_demote(&req, reformer_id, (uint16)sess_id);

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM] dms_az_switchover_promote SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_az_switchover_wait(req.head.ruid, &start_time);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_switchover_promote WAIT overtime, dst_id: %d", req.head.dst_inst);
            continue;
        } else if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_az_switchover_promote protocol version not match, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }
    DMS_RETURN_IF_ERROR(ret);

    cm_spin_lock(&switchover_info->lock, NULL);
    // record reformer version, if reformer changed or restart, send error to stop the session which has run switchover
    switchover_info->switch_req = CM_TRUE;
    switchover_info->reformer_version.inst_id = reformer_id;
    switchover_info->reformer_version.start_time = start_time;
    switchover_info->switch_start = CM_TRUE;
    switchover_info->switch_type = AZ_SWITCHOVER;
    switchover_info->inst_id = reformer_id;
    switchover_info->sess_id = sess_id;
    cm_spin_unlock(&switchover_info->lock);

    return DMS_SUCCESS;
}

int dms_get_version(void)
{
    return DMS_LOCAL_MAJOR_VERSION * DMS_LOCAL_MAJOR_VER_WEIGHT +
        DMS_LOCAL_MINOR_VERSION * DMS_LOCAL_MINOR_VER_WEIGHT +
        DMS_LOCAL_VERSION;
}

bool8 dms_reform_type_is(dms_reform_type_t type)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return share_info->reform_type == type;
}

void dms_show_version(char *version)
{
    int ret = strcpy_s(version, DMS_VERSION_MAX_LEN, (char *)DEF_DMS_VERSION);
    DMS_SECUREC_CHECK(ret);
}

int dms_reform_last_failed(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    return reform_info->last_fail;
}

int dms_is_reformer(void)
{
    return DMS_IS_REFORMER ? CM_TRUE : CM_FALSE;
}

int dms_is_share_reformer(void)
{
    return DMS_IS_SHARE_REFORMER ? CM_TRUE : CM_FALSE;
}

void dms_file_enter(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    cm_latch_s(&reform_info->file_latch, 0, CM_FALSE, NULL);
    while (reform_info->file_unable) {
        cm_unlatch(&reform_info->file_latch, NULL);
        DMS_REFORM_SHORT_SLEEP;
        cm_latch_s(&reform_info->file_latch, 0, CM_FALSE, NULL);
    }
}

void dms_file_leave(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    cm_unlatch(&reform_info->file_latch, NULL);
}

static bool8 dms_no_need_wait_sync(reform_step_t step)
{
    if (step != DMS_REFORM_STEP_SYNC_WAIT) {
        return CM_FALSE;
    }
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_BUILD) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_MAINTAIN) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_RST_RECOVER)) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

void dms_reform_add_step(reform_step_t step)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    // BUILD and MAINTAIN no need to SYNC_WAIT, there is only one instance
    if (dms_no_need_wait_sync(step)) {
        return;
    }

    // ignore consecutive SYNC_WAIT
    if (step == DMS_REFORM_STEP_SYNC_WAIT && share_info->reform_step_count > 0 &&
        share_info->reform_step[share_info->reform_step_count - 1] == DMS_REFORM_STEP_SYNC_WAIT) {
        return;
    }

    share_info->reform_step[share_info->reform_step_count++] = step;
    CM_ASSERT(share_info->reform_step_count < DMS_REFORM_STEP_TOTAL_COUNT);
}

#ifndef OPENGAUSS
void dms_reform_list_remove(instance_list_t *list, int index)
{
    CM_ASSERT(list != NULL);
    CM_ASSERT(index < list->inst_id_count);

    list->inst_id_count--;
    for (int i = index; i < list->inst_id_count; i++) {
        list->inst_id_list[i] = list->inst_id_list[i + 1];
    }
}
#endif

void dms_reform_list_init(instance_list_t *list)
{
    list->inst_id_count = 0;
}

void dms_reform_list_add(instance_list_t *list_dst, uint8 inst_id)
{
    CM_ASSERT(list_dst != NULL);
    list_dst->inst_id_list[list_dst->inst_id_count++] = inst_id;
}

void dms_reform_inst_list_add(instance_list_t *inst_lists, uint8 list_index, uint8 inst_id)
{
    instance_list_t *inst_list = &inst_lists[list_index];
    inst_list->inst_id_list[inst_list->inst_id_count++] = inst_id;
}

void dms_reform_list_add_all(instance_list_t *list_dst)
{
    CM_ASSERT(list_dst != NULL);
    for (uint8 i = 0; i < g_dms.inst_cnt; i++) {
        list_dst->inst_id_list[list_dst->inst_id_count++] = i;
    }
}

void dms_reform_list_cancat(instance_list_t *list_dst, instance_list_t *list_src)
{
    CM_ASSERT(list_dst != NULL);
    CM_ASSERT(list_src != NULL);

    for (uint8 i = 0; i < list_src->inst_id_count; i++) {
        list_dst->inst_id_list[list_dst->inst_id_count++] = list_src->inst_id_list[i];
    }
}

void dms_reform_list_minus(instance_list_t *list_dst, instance_list_t *list_src)
{
    CM_ASSERT(list_dst != NULL);
    CM_ASSERT(list_src != NULL);

    instance_list_t list_result;
    dms_reform_list_init(&list_result);
    for (uint8 i = 0; i < list_dst->inst_id_count; i++) {
        if (!dms_reform_list_exist(list_src, list_dst->inst_id_list[i])) {
            dms_reform_list_add(&list_result, list_dst->inst_id_list[i]);
        }
    }
    *list_dst = list_result;
}