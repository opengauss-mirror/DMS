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
#include "dms_log.h"
#include "cm_timer.h"
#include "dms_reform_health.h"
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
#ifdef OPENGAUSS
    if (!g_dms.enable_reform) {
        return CM_TRUE;
    }
#endif
    drc_global_res_map_t *res_map = DRC_GLOBAL_RES_MAP(res_type);
    if (res_type == (uint8)DRC_RES_LOCK_TYPE) {
        return (int)res_map->drc_access;
    } else {
        return (int)res_map->data_access;
    }
}

static void dms_reform_proc_set_running(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    while (CM_TRUE) {
        if (reform_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            reform_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            break;
        }
        DMS_REFORM_LONG_SLEEP;
    }
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc running");
    reform_info->thread_status = DMS_THREAD_STATUS_RUNNING;
}

void dms_reform_set_start(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_INF("[DMS REFORM]dms_reform_set_start");
    reform_info->true_start = CM_FALSE;
    reform_info->reform_done = CM_FALSE;
    reform_info->err_code = DMS_SUCCESS;
    reform_info->reform_step_index = 0;
    reform_info->reform_phase_index = 0;
    reform_info->reform_phase = 0;
    reform_info->reform_pause = CM_FALSE;
    reform_info->current_step = (uint8)share_info->reform_step[reform_info->reform_step_index++];
    reform_info->proc_time = (uint64)g_timer()->now;
    dms_reform_health_set_running();
    dms_reform_proc_set_running();
    LOG_DEBUG_FUNC_SUCCESS;
}

static int dms_reform_init_thread(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    int ret = DMS_SUCCESS;

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
    char *dms_maintain = getenv(DMS_MAINTAIN_ENV);

    if (dms_maintain == NULL) {
        LOG_RUN_INF("[DMS REFORM]DMS_MAINTAIN is NULL");
        return CM_FALSE;
    }

    if (cm_strcmpi(dms_maintain, "TRUE") == 0) {
        LOG_RUN_INF("[DMS REFORM]DMS_MAINTAIN is TRUE");
        return CM_TRUE;
    }

    LOG_RUN_INF("[DMS REFORM]DMS_MAINTAIN is not TRUE");
    return CM_FALSE;
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

    ctx->global_lock_res.drc_access = CM_TRUE;
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

int dms_reform_init(dms_profile_t *dms_profile)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;
    g_dms.cluster_ver = 0;

#ifdef OPENGAUSS
    if (!dms_profile->enable_reform) {
        drc_res_ctx_t *ctx = DRC_RES_CTX;
        ctx->global_buf_res.drc_access = CM_TRUE;
        ctx->global_buf_res.data_access = CM_TRUE;
        ctx->global_lock_res.drc_access = CM_TRUE;
        ctx->global_lock_res.data_access = CM_TRUE;
        return DMS_SUCCESS;
    }
#endif

    if (g_dms.scrlock_ctx.enable) {
        int ret;
        ret = memcpy_s(reform_context->scrlock_reinit_ctx.log_path, DMS_OCK_LOG_PATH_LEN, dms_profile->ock_log_path, DMS_OCK_LOG_PATH_LEN);
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

    reform_context->catalog_centralized = (bool8)dms_profile->resource_catalog_centralized;
    reform_context->primary_standby = (bool8)dms_profile->load_balance_mode;
    reform_context->channel_cnt = dms_profile->channel_cnt;
    reform_context->mes_has_init = (bool8)dms_profile->conn_created_during_init;
    reform_context->share_info_lock = 0;

    reform_context->handle_proc = g_dms.callback.get_db_handle(&reform_context->sess_proc);
    if (reform_context->handle_proc == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_judge = g_dms.callback.get_db_handle(&reform_context->sess_judge);
    if (reform_context->handle_judge == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_normal = g_dms.callback.get_db_handle(&reform_context->sess_normal);
    if (reform_context->handle_normal == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    reform_context->handle_health = g_dms.callback.get_db_handle(&reform_context->sess_health);
    if (reform_context->handle_health == NULL) {
        LOG_RUN_ERR("[DMS REFORM]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
#if defined(OPENGAUSS) || defined(UT_TEST)
    reform_info->build_complete = CM_TRUE;
    reform_info->maintain = CM_FALSE;
#else
    bool32 build_complete = CM_FALSE;
    // Notice: judgement thread does not work at this moment, so handle_judge can be used here
    g_dms.callback.check_if_build_complete(g_dms.reform_ctx.handle_judge, &build_complete);
    reform_info->build_complete = (bool8)build_complete;
    reform_info->maintain = dms_reform_get_maintain();
    reform_info->bcast_unable = CM_TRUE;
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

    ret = dms_reform_init_thread();
    DMS_RETURN_IF_ERROR(ret);
    dms_reform_init_for_maintain();

    reform_context->init_success = CM_TRUE;
    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_OUT);
    LOG_RUN_INF("[DMS REFORM] dms reform init success. time: %llu", reform_info->start_time);
    return DMS_SUCCESS;
}

void dms_reform_uninit(void)
{
    reform_context_t *reform_context = DMS_REFORM_CONTEXT;
    if (!reform_context->init_success) {
        return;
    }

#ifdef DMS_TEST
    dms_reform_cm_simulation_uninit();
#endif
    cm_close_thread(&reform_context->thread_judgement);
    cm_close_thread(&reform_context->thread_reformer);
    cm_close_thread(&reform_context->thread_reform);
    cm_close_thread(&reform_context->thread_health);
    reform_context->init_success = CM_FALSE;
}

int dms_wait_reform(unsigned int *has_offline)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

#ifndef OPENGAUSS
    g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_JOIN);
#endif

    while (!DMS_FIRST_REFORM_FINISH) {
        DMS_REFORM_LONG_SLEEP;
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
        DMS_REFORM_LONG_SLEEP;
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
        case DMS_PHASE_BEFORE_DC_INIT:
            return "BEFORE DC INIT";
        case DMS_PHASE_BEFORE_ROLLBACK:
            return "REFORE ROLLBACK";
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
        DMS_REFORM_LONG_SLEEP;
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
    dms_reform_req_switchover_t req;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_switchover(&req, (uint16)sess_id);
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_switchover SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_switchover_wait((uint16)sess_id);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_switchover WAIT overtime, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }

    return ret;
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

#ifndef WIN32
void dms_show_version(char *version)
{
    int ret = strcpy_s(version, DMS_VERSION_MAX_LEN, (char *)DEF_DMS_VERSION);
    DMS_SECUREC_CHECK(ret);
}
#endif

int dms_reform_last_failed(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    return reform_info->last_fail;
}

void dms_reform_set_fail(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->reform_fail = CM_TRUE;
}

int dms_is_reformer(void)
{
    return DMS_IS_REFORMER ? CM_TRUE : CM_FALSE;
}

int dms_is_share_reformer(void)
{
    return DMS_IS_SHARE_REFORMER ? CM_TRUE : CM_FALSE;
}

void dms_ddl_enter(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    cm_latch_s(&reform_info->ddl_latch, 0, CM_FALSE, NULL);
    while (reform_info->ddl_unable) {
        cm_unlatch(&reform_info->ddl_latch, NULL);
        DMS_REFORM_SHORT_SLEEP;
        cm_latch_s(&reform_info->ddl_latch, 0, CM_FALSE, NULL);
    }
}

void dms_ddl_leave(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    cm_unlatch(&reform_info->ddl_latch, NULL);
}
