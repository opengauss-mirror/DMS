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
 * dms_reform_drc_migrate.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_migrate.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc.h"
#include "dms_reform_msg.h"
#include "drc_res_mgr.h"
#include "dms_error.h"
#include "drc_page.h"
#include "dms_reform_judge.h"
#include "dcs_page.h"
#include "dms_reform_health.h"
#include "cm_timer.h"
#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_xa.h"
#include "dms_reform_fault_inject.h"

static void dms_reform_part_info_print_single(int inst_id, char *buffer)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[inst_id];
    char temp_desc[DMS_TEMP_DESC_LEN] = { 0 };
    errno_t err;

    if (inst_part->count == 0) {
        return;
    }

    err = sprintf_s(temp_desc, DMS_TEMP_DESC_LEN, " [%d:%d]", inst_id, (int32)inst_part->count);
    DMS_SECUREC_CHECK_SS(err);
    err = strcat_s(buffer, DMS_INFO_DESC_LEN, temp_desc);
    DMS_SECUREC_CHECK(err);
}

static void dms_reform_part_info_print(void)
{
    char buffer[DMS_INFO_DESC_LEN] = { 0 };

    for (int i = 0; i < DMS_MAX_INSTANCES; i++) {
        dms_reform_part_info_print_single(i, buffer);
    }

    LOG_RUN_INF("[DMS REFORM]instance part info: %s", buffer);
}

static void dms_reform_remaster_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;

    dms_reform_part_info_print();
    uint32 size = (uint32)(sizeof(drc_inst_part_t) * DMS_MAX_INSTANCES);
    errno_t err = memcpy_s(part_mngr->inst_part_tbl, size, remaster_info->inst_part_tbl, size);
    DMS_SECUREC_CHECK(err);

    size = (uint32)(sizeof(drc_part_t) * DRC_MAX_PART_NUM);
    err = memcpy_s(part_mngr->part_map, size, remaster_info->part_map, size);
    DMS_SECUREC_CHECK(err);
    dms_reform_part_info_print();
}

int dms_reform_remaster(void)
{
    LOG_RUN_FUNC_ENTER;
    dms_reform_remaster_inner();
    if (g_dms.scrlock_ctx.enable) {
        reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
        share_info_t *share_info = DMS_SHARE_INFO;
        uint8 server_id;
        if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
            server_id = share_info->promote_id;
        }else {
            server_id = share_info->reformer_id;
        }
        reform_ctx->scrlock_reinit_ctx.scrlock_server_id = server_id;
        reform_ctx->scrlock_reinit_ctx.recovery_node_num = share_info->list_online.inst_id_count;
        dms_scrlock_reinit();
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

void dms_reform_migrate_collect_local_task(migrate_info_t *local_migrate_info)
{
    migrate_info_t *global_migrate_info = DMS_MIGRATE_INFO;
    migrate_task_t *migrate_task = NULL;

    local_migrate_info->migrate_task_num = 0;
    for (uint8 i = 0; i < global_migrate_info->migrate_task_num; i++) {
        migrate_task = &global_migrate_info->migrate_task[i];
        if (dms_dst_id_is_self(migrate_task->export_inst)) {
            local_migrate_info->migrate_task[local_migrate_info->migrate_task_num++] = *migrate_task;
        }
    }
}

int dms_reform_migrate_inner(migrate_task_t *migrate_task, void *handle, uint32 sess_id)
{
    drc_part_list_t *part = NULL;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    int ret = DMS_SUCCESS;

    LOG_DEBUG_INF("[DMS REFORM]dms_reform_migrate_inner, part_id: %d, inst: %d -> inst: %d",
        migrate_task->part_id, migrate_task->export_inst, migrate_task->import_inst);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_PAGE_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    part = &ctx->global_buf_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part, DRC_RES_PAGE_TYPE);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_LOCK_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part = &ctx->global_lock_res.res_parts[migrate_task->part_id];
    drc_release_buf_res_by_part(part, DRC_RES_LOCK_TYPE);
    
    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_GLOBAL_XA_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part = &ctx->global_xa_res.res_parts[migrate_task->part_id];
    drc_release_xa_by_part(part);
    return DMS_SUCCESS;
}

int dms_reform_migrate(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    migrate_info_t local_migrate_info = { 0 };
    migrate_task_t *migrate_task = NULL;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    dms_reform_migrate_collect_local_task(&local_migrate_info);
    for (uint8 i = 0; i < local_migrate_info.migrate_task_num; i++) {
        migrate_task = &local_migrate_info.migrate_task[i];
        ret = dms_reform_migrate_inner(migrate_task, reform_ctx->handle_proc, reform_ctx->sess_proc);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}