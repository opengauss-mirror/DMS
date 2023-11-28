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
 * dms_reform_proc.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_proc.c
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

static void inline dms_reform_collect_xa_owner_by_bucket(drc_res_bucket_t *bucket, uint64 *bitmap_has_xa)
{
    drc_global_xa_res_t *xa_res = NULL;
    bilist_node_t *iter_node = cm_bilist_head(&bucket->bucket_list);
    while (iter_node != NULL) {
        xa_res = (drc_global_xa_res_t *)iter_node;
        if (xa_res->owner_id != CM_INVALID_ID8) {
            bitmap64_set(bitmap_has_xa, xa_res->undo_set_id);
        }

        iter_node = iter_node->next;
    }
}

void dms_reform_proc_xa_merge(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_sync_xa_owners_t), CM_TRUE, CM_TRUE);
    dms_reform_req_sync_xa_owners_t *req = (dms_reform_req_sync_xa_owners_t *)receive_msg->buffer;
    if (!dms_reform_check_judge_time(&req->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        dms_release_recv_message(receive_msg);
        return;
    }

    cm_spin_lock(&reform_info->xa_bitmap_lock, NULL);
    bitmap64_union(&reform_info->bitmap_has_xa, req->bitmap_has_xa);
    cm_spin_unlock(&reform_info->xa_bitmap_lock);

    dms_reform_ack_common_t ack_comm;
    dms_init_ack_head(&req->head, &ack_comm.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_comm.result = DMS_SUCCESS;
    int ret = mfc_send_data(&ack_comm.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }

    dms_release_recv_message(receive_msg);
}

int dms_reform_merge_xa_owners(void)
{
    dms_reform_req_sync_xa_owners_t req = { 0 };
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;

    LOG_RUN_FUNC_ENTER;
    if (reform_info->bitmap_has_xa == 0 || share_info->promote_id == g_dms.inst_id) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DMS REFORM]dms_reform_merge_xa_owners, src id: %u,  bitmap_has_xa: %llu, dst id: %u",
        g_dms.inst_id, reform_info->bitmap_has_xa, share_info->promote_id);
    
    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_MERGE_XA_OWNERS, 0, g_dms.inst_id, share_info->promote_id,
        reform_ctx->sess_proc, CM_INVALID_ID16);
    dms_reform_set_judge_time(&req.head);
    req.bitmap_has_xa = reform_info->bitmap_has_xa;
    req.head.size = sizeof(dms_reform_req_sync_xa_owners_t);
    int ret = dms_reform_send_data(&req.head, reform_ctx->sess_proc);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

void dms_reform_proc_req_xaowners(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_message_head_t), CM_TRUE, CM_TRUE);
    if (!dms_reform_check_judge_time(receive_msg->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        dms_release_recv_message(receive_msg);
        return;
    }
    dms_reform_ack_common_t ack_comm;
    dms_init_ack_head(receive_msg->head, &ack_comm.head, MSG_ACK_REFORM_COMMON, sizeof(dms_reform_ack_common_t),
        process_ctx->sess_id);
    ack_comm.result = DMS_SUCCESS;
    ack_comm.bitmap_has_xa = reform_info->bitmap_has_xa;
    int ret = mfc_send_data(&ack_comm.head);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_FUNC_FAIL;
    }

    dms_release_recv_message(receive_msg);
}

static int dms_reform_req_xa_owners(void)
{
    dms_message_head_t req = { 0 };
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;

    LOG_DEBUG_INF("[DMS REFORM]dms_reform_req_xa_owners, src id: %u, dst id: %u", g_dms.inst_id,
        share_info->promote_id);

    while (CM_TRUE) {
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        DMS_INIT_MESSAGE_HEAD(&req, MSG_REQ_XA_OWNERS, 0, g_dms.inst_id, share_info->promote_id, reform_ctx->sess_proc,
            CM_INVALID_ID16);
        dms_reform_set_judge_time(&req);
        req.size = sizeof(dms_message_head_t);
        req.cluster_ver = DMS_GLOBAL_CLUSTER_VER;
        int ret = mfc_send_data(&req);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_req_xa_owners send error: %d, dst_id: %d", ret, share_info->promote_id);
            return ret;
        }

        dms_message_t res = { 0 };
        ret = mfc_get_response(req.ruid, &res, DMS_REFORM_LONG_TIMEOUT);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_req_xa_owners wait timeout, dst_id: %d", share_info->promote_id);
            continue;
        }

        if (ret != DMS_SUCCESS) {
            return ret;
        }

        dms_reform_ack_common_t *ack_comm = (dms_reform_ack_common_t *)res.buffer;
        ret = ack_comm->result;
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_req_xa_owners result: %d, dst_id: %d", ret, share_info->promote_id);
            dms_release_recv_message(&res);
            return ret;
        }

        reform_info->bitmap_has_xa = ack_comm->bitmap_has_xa;
        dms_release_recv_message(&res);
        break;
    }

    return DMS_SUCCESS;
}

int dms_reform_collect_xa_owner(void)
{
    drc_res_bucket_t *res_bucket = NULL;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_map_t *res_map = &global_res_map->res_map;

    LOG_RUN_FUNC_ENTER;
    reform_info->bitmap_has_xa = 0;
    if (DMS_CATALOG_IS_CENTRALIZED && share_info->promote_id != g_dms.inst_id) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
        return DMS_SUCCESS;
    }

    for (uint32 bucket_id = 0; bucket_id < res_map->bucket_num; bucket_id++) {
        res_bucket = &res_map->buckets[bucket_id];
        cm_spin_lock(&res_bucket->lock, NULL);
        dms_reform_collect_xa_owner_by_bucket(res_bucket, &reform_info->bitmap_has_xa);
        cm_spin_unlock(&res_bucket->lock);
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static void dms_reform_refresh_xa_owner()
{
    bilist_node_t *iter_node = NULL;
    drc_global_xa_res_t *xa_res = NULL;
    drc_res_bucket_t *res_bucket = NULL;
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_global_res_map_t *global_res_map = drc_get_global_res_map(DRC_RES_GLOBAL_XA_TYPE);
    drc_res_map_t *res_map = &global_res_map->res_map;

    LOG_RUN_FUNC_ENTER;
    if (DMS_CATALOG_IS_CENTRALIZED) {
        LOG_RUN_FUNC_SUCCESS;
        return;
    }

    for (uint32 bucket_id = 0; bucket_id < res_map->bucket_num; bucket_id++) {
        res_bucket = &res_map->buckets[bucket_id];
        cm_spin_lock(&res_bucket->lock, NULL);
        iter_node = cm_bilist_head(&res_bucket->bucket_list);
        while (iter_node != NULL) {
            xa_res = (drc_global_xa_res_t *)iter_node;
            xa_res->owner_id = share_info->promote_id;
            iter_node = iter_node->next;
        }
        cm_spin_unlock(&res_bucket->lock);
    }

    LOG_RUN_FUNC_SUCCESS;
}

int dms_reform_recovery_xa(void)
{
    int ret = DMS_SUCCESS;
    instance_list_t list_has_xa;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_FUNC_ENTER;
    if (share_info->promote_id != g_dms.inst_id) {
        ret = dms_reform_req_xa_owners();
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }

    dms_reform_refresh_xa_owner();
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (bitmap64_exist(&reform_info->bitmap_has_xa, i)) {
            // node which has xa should be deposite by reformer
            g_drc_res_ctx.deposit_map[i] = share_info->promote_id;
        } else {
            g_drc_res_ctx.deposit_map[i] = i;
        }
    }

    if (share_info->promote_id != g_dms.inst_id) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
        return DMS_SUCCESS;
    }

    dms_reform_bitmap_to_list(&list_has_xa, reform_info->bitmap_has_xa);
    ret = dms_reform_undo_init(&list_has_xa);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_init(&list_has_xa);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_load(&list_has_xa);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

int dms_reform_req_migrate_xa(drc_global_xa_res_t *xa_res, dms_reform_req_migrate_t *req, uint32 *offset,
    uint32 sess_id)
{
    int ret = DMS_SUCCESS;
    drc_global_xid_t *xid = &xa_res->xid;
    /* fmt_id + gtrid_len + bqual_len + unso_set_id + gtrid + bqual 
     * 3 * sizeof(uint8): undo_set_id + gtrid_len + bqual_len
     */
    uint32 append_size = (uint32)(sizeof(uint64) + xid->bqual_len + xid->gtrid_len + 3 * sizeof(uint8));
    if ((*offset + append_size) > DMS_REFORM_MSG_MAX_LENGTH) {
        // send current msg, then reset the msg pack
        req->head.size = (uint16)(*offset);
        ret = dms_reform_send_data(&req->head, sess_id);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_FUNC_FAIL;
            return ret;
        }
        *offset = (uint32)sizeof(dms_reform_req_migrate_t);
        req->res_num = 0;
    }

    *(uint64 *)((char *)req + *offset) = xid->fmt_id;
    *offset += sizeof(uint64);
    *(uint8 *)((char *)req + *offset) = xid->gtrid_len;
    *offset += sizeof(uint8);
    *(uint8 *)((char *)req + *offset) = xid->bqual_len;
    *offset += sizeof(uint8);
    *(uint64 *)((char *)req + *offset) = xa_res->undo_set_id;
    *offset += sizeof(uint8);
    ret = memcpy_sp((char *)req + *offset, xid->gtrid_len, xid->gtrid, xid->gtrid_len);
    if (ret != EOK) {
        return ret;
    }
    *offset += xid->gtrid_len;
    if (xid->bqual_len > 0) {
        ret = memcpy_sp((char *)req + *offset, xid->bqual_len, xid->bqual, xid->bqual_len);
        if (ret != EOK) {
            return ret;
        }
        *offset += xid->bqual_len;
    }
    
    req->res_num++;
    return DMS_SUCCESS;
}

void dms_reform_proc_req_xa_migrate(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_migrate_t), CM_TRUE, CM_TRUE);
    dms_reform_req_migrate_t *req = (dms_reform_req_migrate_t *)receive_msg->buffer;

    int ret = DMS_SUCCESS;
    drc_global_xid_t xid = { 0 };
    uint32 owner_id = req->head.dst_inst;
    uint32 offset = (uint32)sizeof(dms_reform_req_migrate_t);
    for (uint32 i = 0; i < req->res_num; i++) {
        CM_ASSERT(offset <= req->head.size);
        xid.fmt_id = *(uint64 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint64);
        xid.gtrid_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        xid.bqual_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        uint8 undo_set_id = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        ret = memcpy_sp(xid.gtrid, DMS_MAX_XA_BASE16_GTRID_LEN, (uint8 *)receive_msg->buffer + offset, xid.gtrid_len);
        DMS_SECUREC_CHECK(ret);
        offset += xid.gtrid_len;
        if (xid.bqual_len > 0) {
            ret = memcpy_sp(xid.bqual, DMS_MAX_XA_BASE16_BQUAL_LEN, (uint8 *)receive_msg->buffer + offset, xid.bqual_len);
            DMS_SECUREC_CHECK(ret);
            offset += xid.bqual_len;
        }
        

        ret = drc_create_xa_res(process_ctx->db_handle, process_ctx->sess_id, &xid, owner_id, undo_set_id, CM_FALSE);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DRC][%s]dms_reform_proc_req_xa_migrate", cm_display_resid((char *)&xid,
                DRC_RES_GLOBAL_XA_TYPE));
            break;
        }
    }

    dms_reform_ack_req_migrate(process_ctx, receive_msg, ret);
    dms_release_recv_message(receive_msg);
}

static int32 dms_reform_rebuild_append_xid(dms_reform_req_rebuild_t *req_rebuild, drc_global_xid_t *xid,
    uint8 master_id, uint8 undo_set_id)
{
    /* fmt_id + gtrid_len + bqual_len + unso_set_id + gtrid + bqual 
     * 3 * sizeof(uint8): undo_set_id + gtrid_len + bqual_len
     */
    uint32 append_size = (uint32)(sizeof(uint64) + xid->bqual_len + xid->gtrid_len + 3 * sizeof(uint8));

    int ret = DMS_SUCCESS;
    if (req_rebuild->offset + append_size > DMS_REFORM_MSG_MAX_LENGTH) {
        ret = dms_reform_send_data(&req_rebuild->head, g_dms.reform_ctx.sess_proc);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS][%s] send data failed when rebuilding xa res while reforming", cm_display_resid((char *)xid,
                DRC_RES_GLOBAL_XA_TYPE));
            return ret;
        }
        req_rebuild->offset += (uint32)sizeof(dms_reform_req_rebuild_t);
    }

    *(uint64 *)((char *)req_rebuild + req_rebuild->offset) = xid->fmt_id;
    req_rebuild->offset += sizeof(uint64);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = xid->gtrid_len;
    req_rebuild->offset += sizeof(uint8);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = xid->bqual_len;
    req_rebuild->offset += sizeof(uint8);
    *(uint8 *)((char *)req_rebuild + req_rebuild->offset) = undo_set_id;
    req_rebuild->offset += sizeof(uint8);

    ret = memcpy_sp((char *)req_rebuild + req_rebuild->offset, xid->gtrid_len, xid->gtrid, xid->gtrid_len);
    if (ret != EOK) {
        return ret;
    }
    req_rebuild->offset += xid->gtrid_len;
    if (xid->bqual_len > 0) {
        ret = memcpy_sp((char *)req_rebuild + req_rebuild->offset, xid->bqual_len, xid->bqual, xid->bqual_len);
        if (ret != EOK) {
            return ret;
        }
        req_rebuild->offset += xid->bqual_len;
    }
     
    return DMS_SUCCESS;
}

static int32 dms_reform_req_xa_rebuild(dms_context_t *dms_ctx, drc_global_xid_t *xid, uint8 undo_set_id,
    uint8 master_id, uint8 thread_index)
{
    dms_reform_req_rebuild_t *req_rebuild = NULL;
    rebuild_info_t *rebuild_info = DMS_REBUILD_INFO;
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = &parallel_info->parallel[thread_index];

    if (thread_index == CM_INVALID_ID8) {
        req_rebuild = (dms_reform_req_rebuild_t *)rebuild_info->rebuild_data[master_id];
    } else {
        req_rebuild = (dms_reform_req_rebuild_t *)parallel->data[master_id];
    }
    
    if (req_rebuild == NULL) {
        if (thread_index == CM_INVALID_ID8) {
            req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
                DMS_REFORM_MSG_MAX_LENGTH);
        } else {
            req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(parallel->handle, 
                DMS_REFORM_MSG_MAX_LENGTH);
        }
        req_rebuild = (dms_reform_req_rebuild_t *)g_dms.callback.mem_alloc(g_dms.reform_ctx.handle_proc,
            DMS_REFORM_MSG_MAX_LENGTH);
        if (req_rebuild == NULL) {
            DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
            return ERRNO_DMS_ALLOC_FAILED;
        }
        
        if (thread_index == CM_INVALID_ID8) {
            rebuild_info->rebuild_data[master_id] = req_rebuild;
        } else {
            parallel->data[master_id] = req_rebuild;
        }

        DMS_INIT_MESSAGE_HEAD(&req_rebuild->head, MSG_REQ_XA_REBUILD, 0, g_dms.inst_id, master_id,
            g_dms.reform_ctx.sess_proc, CM_INVALID_ID16);
        dms_reform_set_judge_time(&req_rebuild->head);
        req_rebuild->offset = (uint32)sizeof(dms_reform_req_rebuild_t);
        req_rebuild->head.size = DMS_REFORM_MSG_MAX_LENGTH;
    }
    
    return dms_reform_rebuild_append_xid(req_rebuild, xid, master_id, undo_set_id);
}

int dms_reform_rebuild_one_xa(dms_context_t *dms_ctx, unsigned char undo_set_id, unsigned char thread_index)
{
    dms_reset_error();
    uint8 master_id = CM_INVALID_ID8;
    share_info_t *share_info = DMS_SHARE_INFO;
    drc_global_xid_t *xid = &dms_ctx->global_xid;

    int ret = drc_get_master_id((char *)xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s] dms_reform_rebuild_one_xa, fail to get master id", cm_display_resid((char *)xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    if (!share_info->full_clean && !dms_reform_list_exist(&share_info->list_rebuild, master_id)) {
        return DMS_SUCCESS;
    }

    LOG_DEBUG_INF("[DMS][%s] dms_reform_rebuild_xa_res, remaster to node %u", cm_display_resid((char *)xid,
        DRC_RES_GLOBAL_XA_TYPE), master_id);
    if (master_id == g_dms.inst_id) {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_LOCAL);
        ret = drc_create_xa_res(dms_ctx->db_handle, dms_ctx->sess_id, xid, g_dms.inst_id, undo_set_id, CM_FALSE);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_LOCAL);
    } else {
        dms_reform_proc_stat_start(DRPS_DRC_REBUILD_REMOTE);
        ret = dms_reform_req_xa_rebuild(dms_ctx, xid, undo_set_id, master_id, thread_index);
        dms_reform_proc_stat_end(DRPS_DRC_REBUILD_REMOTE);
    }
    return ret;
}

void dms_reform_proc_xa_rebuild(dms_process_context_t *ctx, dms_message_t *receive_msg)
{
    int32 ret = DMS_SUCCESS;
    drc_global_xid_t xid = { 0 };
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_reform_req_rebuild_t), CM_TRUE, CM_TRUE);
    dms_reform_req_rebuild_t *req_rebuild = (dms_reform_req_rebuild_t *)receive_msg->buffer;
    CM_CHK_RECV_MSG_SIZE_NO_ERR(receive_msg, req_rebuild->offset, CM_TRUE, CM_TRUE);
    if (!dms_reform_check_judge_time(&req_rebuild->head)) {
        LOG_DEBUG_ERR("[DMS REFORM]%s, fail to check judge time", __FUNCTION__);
        dms_release_recv_message(receive_msg);
        return;
    }
    uint8 owner_id = req_rebuild->head.src_inst;
    uint32 offset = (uint32)sizeof(dms_reform_req_rebuild_t);

    while (offset < req_rebuild->offset) {
        xid.fmt_id = *(uint64 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint64);
        xid.gtrid_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        xid.bqual_len = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        uint8 undo_set_id = *(uint8 *)((uint8 *)receive_msg->buffer + offset);
        offset += sizeof(uint8);
        ret = memcpy_sp(xid.gtrid, DMS_MAX_XA_BASE16_GTRID_LEN, (uint8 *)receive_msg->buffer + offset, xid.gtrid_len);
        DMS_SECUREC_CHECK(ret);
        offset += xid.gtrid_len;
        if (xid.bqual_len > 0) {
            ret = memcpy_sp(xid.bqual, DMS_MAX_XA_BASE16_BQUAL_LEN, (uint8 *)receive_msg->buffer + offset, xid.bqual_len);
            DMS_SECUREC_CHECK(ret);
            offset += xid.bqual_len;
        }
        

        ret = drc_create_xa_res(ctx->db_handle, ctx->sess_id, &xid, owner_id, undo_set_id, CM_FALSE);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DRC][%s] dms_reform_proc_xa_rebuild", cm_display_resid((char *)&xid, DRC_RES_GLOBAL_XA_TYPE));
            break;
        }
    }

    dms_reform_ack_req_rebuild(ctx, receive_msg, ret);
    dms_release_recv_message(receive_msg);
}

void dms_reform_clean_xa_res_by_part(bilist_t *part_list)
{
    drc_global_xa_res_t *xa_res = NULL;
    share_info_t *share_info = DMS_SHARE_INFO;
    bilist_node_t *node = cm_bilist_head(part_list);

    while (node != NULL) {
        xa_res = DRC_RES_NODE_OF(drc_global_xa_res_t, node, part_node);
        if (bitmap64_exist(&share_info->bitmap_clean, xa_res->owner_id)) {
            (void)drc_delete_xa_res(&xa_res->xid, CM_FALSE);
        }

        node = BINODE_NEXT(node);
    }
}

void dms_reform_delete_xa_rms(uint8 undo_set_id)
{
    g_dms.callback.dms_shrink_xa_rms(undo_set_id);
}

int dms_reform_xa_drc_access(void)
{
    LOG_RUN_FUNC_ENTER;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_xa_res.drc_access = CM_TRUE;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}