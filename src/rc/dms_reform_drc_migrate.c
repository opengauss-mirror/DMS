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
#include "drc_page.h"

static void dms_reform_part_info_print(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_part_t *part = &part_mngr->part_map[0];
    uint8 master = part->inst_id;
    uint16 part_id = 0;
    errno_t err;
    char buffer[DMS_INFO_DESC_LEN] = { 0 };
    char part_buffer[DMS_TEMP_DESC_LEN] = { 0 };

    for (int i = 1; i < DRC_MAX_PART_NUM; i++) {
        part = &part_mngr->part_map[i];
        if (part->inst_id == master) {
            continue;
        }
        err = sprintf_s(part_buffer, DMS_TEMP_DESC_LEN, "[%d,%d]:inst%d", part_id, i - 1, master);
        DMS_SECUREC_CHECK_SS(err);
        err = strcat_s(buffer, DMS_INFO_DESC_LEN, part_buffer);
        DMS_SECUREC_CHECK(err);
        part_id = i;
        master = part->inst_id;
    }
    err = sprintf_s(part_buffer, DMS_TEMP_DESC_LEN, "[%d,%d]:inst%d", part_id, DRC_MAX_PART_NUM - 1, master);
    DMS_SECUREC_CHECK_SS(err);
    err = strcat_s(buffer, DMS_INFO_DESC_LEN, part_buffer);
    DMS_SECUREC_CHECK(err);

    LOG_RUN_INF("[DMS REFORM]part info: %s", buffer);
}

void dms_reform_remaster_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    remaster_info_t *new_master_info = DMS_REMASTER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *old_master_info = DMS_OLD_MASTER_INFO;

    dms_reform_part_info_print();
    dms_reform_part_copy_inner(part_mngr->inst_part_tbl, new_master_info->inst_part_tbl,
        part_mngr->part_map, new_master_info->part_map);
    if (share_info->drm_trigger) {
        dms_reform_part_copy_inner(part_mngr->old_inst_part_tbl, old_master_info->inst_part_tbl,
            part_mngr->old_part_map, old_master_info->part_map);
        drm_trigger();
    } else {
        dms_reform_part_copy_inner(part_mngr->old_inst_part_tbl, new_master_info->inst_part_tbl,
            part_mngr->old_part_map, new_master_info->part_map);
    }
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
        } else {
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
    drc_release_by_part(part, DRC_RES_PAGE_TYPE);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_LOCK_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part = &ctx->global_lock_res.res_parts[migrate_task->part_id];
    drc_release_by_part(part, DRC_RES_LOCK_TYPE);

    ret = dms_reform_req_migrate_res(migrate_task, DRC_RES_ALOCK_TYPE, handle, sess_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }
    part = &ctx->global_alock_res.res_parts[migrate_task->part_id];
    drc_release_by_part(part, DRC_RES_ALOCK_TYPE);

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
    if (local_migrate_info.migrate_task_num == 0) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    drc_enter_buf_res_set_blocked();
    for (uint8 i = 0; i < local_migrate_info.migrate_task_num; i++) {
        migrate_task = &local_migrate_info.migrate_task[i];
        ret = dms_reform_migrate_inner(migrate_task, reform_ctx->handle_proc, reform_ctx->sess_proc);
        DMS_BREAK_IF(ret != DMS_SUCCESS);
    }
    drc_enter_buf_res_set_unblocked();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}