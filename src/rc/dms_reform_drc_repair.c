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
 * dms_reform_drc_repair.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_repair.c
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
#include "dms_msg_protocol.h"

static int dms_reform_may_need_flush(drc_buf_res_t *buf_res, uint32 sess_id, uint8 dst_id, bool8 *is_edp)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    uint64 lsn;

    if (buf_res->type != DRC_RES_PAGE_TYPE) {
        return DMS_SUCCESS;
    }

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, dst_id, DMS_REQ_NEED_FLUSH, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_may_need_flush SEND error: %d, dst_id: %d", ret, dst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            dms_reform_proc_stat_times(DRPS_DRC_REPAIR_TIMEOUT);
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_may_need_flush WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }

    // if dst version less than VER_2, the value of is_edp can not be trusted
    if (dms_get_node_proto_version(dst_id) < DMS_PROTO_VER_2) {
        *is_edp = CM_FALSE;
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_may_need_flush result: %d, dst_id: %d", result, dst_id);
        return result;
    }

    return ret;
}

static void dms_reform_repair_proc_stat_times(uint8 res_type, reform_repair_stat_t stat)
{
    CM_ASSERT(stat < DRPS_DRC_REPAIR_COUNT);
    if (res_type == DRC_RES_PAGE_TYPE) {
        dms_reform_proc_stat_times((uint32)(DRPS_DRC_REPAIR_PAGE + stat));
    } else if (res_type == DRC_RES_LOCK_TYPE) {
        dms_reform_proc_stat_times((uint32)(DRPS_DRC_REPAIR_LOCK + stat));
    }
}

static void dms_reform_repair_proc_stat_start(uint8 res_type, reform_repair_stat_t stat)
{
    CM_ASSERT(stat < DRPS_DRC_REPAIR_COUNT);
    if (res_type == DRC_RES_PAGE_TYPE) {
        dms_reform_proc_stat_start((uint32)(DRPS_DRC_REPAIR_PAGE + stat));
    } else if (res_type == DRC_RES_LOCK_TYPE) {
        dms_reform_proc_stat_start((uint32)(DRPS_DRC_REPAIR_LOCK + stat));
    }
}

static void dms_reform_repair_proc_stat_end(uint8 res_type, reform_repair_stat_t stat)
{
    CM_ASSERT(stat < DRPS_DRC_REPAIR_COUNT);
    if (res_type == DRC_RES_PAGE_TYPE) {
        dms_reform_proc_stat_end((uint32)(DRPS_DRC_REPAIR_PAGE + stat));
    } else if (res_type == DRC_RES_LOCK_TYPE) {
        dms_reform_proc_stat_end((uint32)(DRPS_DRC_REPAIR_LOCK + stat));
    }
}

static int dms_reform_repair_with_copy_insts_inner(drc_buf_res_t *buf_res, uint32 sess_id, bool32 *exists_owner,
    uint64 insts)
{
    bool8 is_edp = CM_FALSE;

    *exists_owner = CM_FALSE;
    if (insts == 0) {
        return DMS_SUCCESS;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; ++i) {
        if (!bitmap64_exist(&insts, i)) {
            continue;
        }
        // confirm page exist or not and set need_flush for edp
        dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH);
        int ret = dms_reform_may_need_flush(buf_res, sess_id, i, &is_edp);
        dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_WITH_COPY_NEED_FLUSH);
        if (ret == ERRNO_DMS_DRC_INVALID) {
            bitmap64_clear(&buf_res->copy_insts, i);
            continue;
        }
        DMS_RETURN_IF_ERROR(ret);
        bitmap64_clear(&buf_res->copy_insts, i);
        buf_res->claimed_owner = i;
        *exists_owner = CM_TRUE;
        if (!is_edp && buf_res->type == DRC_RES_PAGE_TYPE) {
            // edp no need to set promote because it is in ckpt queue already, but edp_map may be incorrect
            buf_res->copy_promote = DMS_COPY_PROMOTE_NORMAL;
        }
        return DMS_SUCCESS;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_copy_insts(drc_buf_res_t *buf_res, uint32 sess_id, bool32 *exists_owner)
{
    uint64 edp_copyinsts = bitmap64_intersect(buf_res->copy_insts, buf_res->edp_map);
    int ret = dms_reform_repair_with_copy_insts_inner(buf_res, sess_id, exists_owner, edp_copyinsts);
    DMS_RETURN_IF_ERROR(ret);
    if (*exists_owner) {
        return DMS_SUCCESS;
    }
    return dms_reform_repair_with_copy_insts_inner(buf_res, sess_id, exists_owner, buf_res->copy_insts);
}

static int dms_reform_repair_with_last_edp(drc_buf_res_t *buf_res, void *handle)
{
    uint64 disk_lsn = 0;
    int ret = DMS_SUCCESS;

    ret = g_dms.callback.disk_lsn(handle, buf_res->data, &disk_lsn);
    DMS_RETURN_IF_ERROR(ret);

    if (disk_lsn >= buf_res->lsn) {
        buf_res->last_edp = CM_INVALID_ID8;
        buf_res->lsn = 0;
        buf_res->edp_map = 0;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_with_edp_map_inner(drc_buf_res_t *buf_res, uint8 inst_id, uint32 sess_id)
{
    dms_reform_req_res_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    int result;
    uint8 lock_mode;
    bool8 is_edp;
    uint64 lsn;

    while (CM_TRUE) {
        dms_reform_init_req_res(&req, buf_res->type, buf_res->data, inst_id, DMS_REQ_EDP_LSN, sess_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_repair_with_edp_map_inner SEND error: %d, dst_id: %d", ret, inst_id);
            return ret;
        }

        ret = dms_reform_req_page_wait(&result, &lock_mode, &is_edp, &lsn, req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            dms_reform_proc_stat_times(DRPS_DRC_REPAIR_TIMEOUT);
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_repair_with_edp_map_inner WAIT timeout, dst_id: %d", inst_id);
            continue;
        } else {
            break;
        }
    }

    if (result != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS REFORM]dms_reform_repair_with_edp_map_inner result: %d, dst_id: %d", result, inst_id);
        return result;
    }

    if (ret != DMS_SUCCESS) {
        return ret;
    }

    drc_add_edp_map(buf_res, inst_id, lsn);
    return DMS_SUCCESS;
}

static int dms_reform_repair_with_edp_map(drc_buf_res_t *buf_res, void *handle, uint32 sess_id)
{
    int ret = DMS_SUCCESS;
    uint64 disk_lsn = 0;

    buf_res->lsn = 0;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (!bitmap64_exist(&buf_res->edp_map, i)) {
            continue;
        }
        ret = dms_reform_repair_with_edp_map_inner(buf_res, i, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_WITH_EDP_MAP_GET_LSN);
    ret = g_dms.callback.disk_lsn(handle, buf_res->data, &disk_lsn);
    dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_WITH_EDP_MAP_GET_LSN);
    DMS_RETURN_IF_ERROR(ret);

    if (disk_lsn >= buf_res->lsn) {
        buf_res->last_edp = CM_INVALID_ID8;
        buf_res->lsn = 0;
        buf_res->edp_map = 0;
    }

    return DMS_SUCCESS;
}

static int dms_reform_repair_by_part_inner(drc_buf_res_t *buf_res, void *handle, uint32 sess_id)
{
    int ret;
    DRC_DISPLAY(buf_res, "repair");

    if (buf_res->claimed_owner != CM_INVALID_ID8) {
        // set need_flush flag for pages which has been set edp flag.Otherwise ckpt will skip the pages
        if (bitmap64_exist(&buf_res->edp_map, buf_res->claimed_owner)) {
            bool8 is_edp;
            dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_NEED_FLUSH);
            ret = dms_reform_may_need_flush(buf_res, sess_id, buf_res->claimed_owner, &is_edp);
            dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_NEED_FLUSH);
            return ret;
        }
        dms_reform_repair_proc_stat_times(buf_res->type, DRPS_DRC_REPAIR_NEED_NOT_FLUSH);
        return DMS_SUCCESS;
    }

    if (buf_res->copy_insts != 0) {
        bool32 exists_owner = CM_FALSE;
        dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_WITH_COPY);
        ret = dms_reform_repair_with_copy_insts(buf_res, sess_id, &exists_owner);
        dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_WITH_COPY);
        if (ret != DMS_SUCCESS || exists_owner) {
            return ret;
        }
    }

    if (buf_res->last_edp != CM_INVALID_ID8) {
        dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_WITH_LAST_EDP);
        ret = dms_reform_repair_with_last_edp(buf_res, handle);
        dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_WITH_LAST_EDP);
        return ret;
    }

    if (buf_res->edp_map != 0) {
        dms_reform_repair_proc_stat_start(buf_res->type, DRPS_DRC_REPAIR_WITH_EDP_MAP);
        ret = dms_reform_repair_with_edp_map(buf_res, handle, sess_id);
        dms_reform_repair_proc_stat_end(buf_res->type, DRPS_DRC_REPAIR_WITH_EDP_MAP);
        return ret;
    }

    return DMS_SUCCESS;
}

int dms_reform_repair_by_part(drc_part_list_t *part, void *handle, uint32 sess_id)
{
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_buf_res_t *buf_res;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, part_node);
        node = BINODE_NEXT(node);
        ret = dms_reform_repair_by_part_inner(buf_res, handle, sess_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return ret;
}

int dms_reform_repair_by_partid(uint16 part_id, void *handle, uint32 sess_id)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_list_t *part = NULL;
    int ret = DMS_SUCCESS;

    part = &ctx->global_lock_res.res_parts[part_id];
    dms_reform_proc_stat_start(DRPS_DRC_REPAIR_LOCK);
    ret = dms_reform_repair_by_part(part, handle, sess_id);
    dms_reform_proc_stat_end(DRPS_DRC_REPAIR_LOCK);
    DMS_RETURN_IF_ERROR(ret);

    part = &ctx->global_buf_res.res_parts[part_id];
    dms_reform_proc_stat_start(DRPS_DRC_REPAIR_PAGE);
    ret = dms_reform_repair_by_part(part, handle, sess_id);
    dms_reform_proc_stat_end(DRPS_DRC_REPAIR_PAGE);
    DMS_RETURN_IF_ERROR(ret);

    return DMS_SUCCESS;
}

static int dms_reform_repair_inner(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < inst_part->count; i++) {
        ret = dms_reform_repair_by_partid(part_id, reform_ctx->handle_proc, reform_ctx->sess_proc);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }
    return DMS_SUCCESS;
}

int dms_reform_repair(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_repair_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}
