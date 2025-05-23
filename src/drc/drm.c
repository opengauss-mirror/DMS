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
 * drm.c
 *
 *
 * IDENTIFICATION
 *    src/drc/drm.c
 *
 * -------------------------------------------------------------------------
 */

#include "drm.h"
#include "drc_res_mgr.h"
#include "cm_timer.h"

void dms_notify_old_master_release(drc_head_t *drc, uint8 old_master, uint8 options)
{
    dms_notify_old_master_t notify;

    notify.len = drc->len;
    notify.type = drc->type;
    notify.options = options;
    errno_t err = memcpy_s(notify.data, DRM_RESID_LEN, DRC_DATA(drc), drc->len);
    DMS_SECUREC_CHECK(err);

    DMS_INIT_MESSAGE_HEAD(&notify.head, MSG_REQ_DRC_RELEASE, 0, g_dms.inst_id, old_master, 0, 0);
    notify.head.size = (uint16)sizeof(dms_notify_old_master_t);

    if (mfc_send_data_async(&notify.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRM][%s]notify_old_master_release, send failed", cm_display_resid(DRC_DATA(drc), drc->type));
    } else {
        LOG_DEBUG_INF("[DRM][%s]notify_old_master_release, success", cm_display_resid(DRC_DATA(drc), drc->type));
    }
}

int dms_req_drc_migrate(dms_ack_drc_migrate_t *ack, char *resid, uint16 len, uint8 type, uint8 options, uint8 master)
{
    dms_req_drc_migrate_t req;

    req.len = len;
    req.type = type;
    req.options = options;
    errno_t err = memcpy_s(req.data, DRM_RESID_LEN, resid, len);
    DMS_SECUREC_CHECK(err);

    DMS_INIT_MESSAGE_HEAD(&req.head, MSG_REQ_DRC_MIGRATE, 0, g_dms.inst_id, master, 0, 0);
    req.head.size = (uint16)sizeof(dms_req_drc_migrate_t);

    int32 ret = mfc_send_data(&req.head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRM][%s]send failed, dst_inst:%d", cm_display_resid(resid, type), master);
        return ret;
    }

    dms_message_t message = { 0 };
    ret = mfc_get_response(req.head.ruid, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRM][%s]recv failed, dst_inst:%d", cm_display_resid(resid, type), master);
        return ret;
    }

    dms_ack_drc_migrate_t *temp = (dms_ack_drc_migrate_t *)message.head;
    if (temp->ret != DMS_SUCCESS) {
        mfc_release_response(&message);
        LOG_DEBUG_ERR("[DRM][%s]fail to enter drc, dst_inst:%d", cm_display_resid(resid, type), master);
        return DMS_ERROR;
    }

    if (!temp->exist) {
        mfc_release_response(&message);
        ack->exist = CM_FALSE;
        return DMS_SUCCESS;
    }

    err = memcpy_s(ack, sizeof(dms_ack_drc_migrate_t), message.buffer, sizeof(dms_ack_drc_migrate_t));
    DMS_SECUREC_CHECK(err);
    mfc_release_response(&message);
    return DMS_SUCCESS;
}

void dms_proc_drc_migrate_inner(dms_ack_drc_migrate_t *ack, dms_req_drc_migrate_t *req, dms_process_context_t *proc)
{
    dms_init_ack_head(&req->head, &ack->head, MSG_ACK_DRC_MIGRATE, sizeof(dms_ack_drc_migrate_t), proc->sess_id);
    uint8 options = (req->options | DRC_RES_CHECK_OLD_MASTER) & ~DRC_RES_CHECK_MASTER & ~DRC_ALLOC;
    drc_head_t *drc = NULL;
    ack->ret = drc_enter(req->data, req->len, req->type, options, &drc);
    if (ack->ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRP][%s]fail to enter drc", cm_display_resid(req->data, req->type));
        return;
    }
    if (drc == NULL) {
        LOG_DEBUG_INF("[DRP][%s]drc not exists", cm_display_resid(req->data, req->type));
        ack->exist = CM_FALSE;
        return;
    }

    ack->exist = CM_TRUE;
    ack->owner = drc->owner;
    ack->lock_mode = drc->lock_mode;
    ack->copy_insts = drc->copy_insts;
    ack->converting = drc->converting;
    if (drc->type == DRC_RES_PAGE_TYPE) {
        drc_page_t *drc_page = (drc_page_t *)drc;
        ack->last_edp = drc_page->last_edp;
        ack->edp_map = drc_page->edp_map;
        ack->last_edp_lsn = drc_page->last_edp_lsn;
        ack->seq = drc_page->seq;
    }
    DRC_DISPLAY(drc, "DRP");
    drc_leave(drc, options);
}

void dms_proc_drc_migrate(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_req_drc_migrate_t), CM_TRUE);
    dms_req_drc_migrate_t *req = (dms_req_drc_migrate_t *)(receive_msg->buffer);
    if (SECUREC_UNLIKELY(req->type >= DRC_RES_TYPE_MAX_COUNT || req->len > DRM_RESID_LEN)) {
        LOG_DEBUG_ERR("[DRP]dms_proc_drc_migrate invalid message type:%d len:%d", req->type, req->len);
        return;
    }
    LOG_DEBUG_INF("[DRP][%s]migrate start, src_inst:%d", cm_display_resid(req->data, req->type), req->head.src_inst);

    dms_ack_drc_migrate_t ack;
    dms_proc_drc_migrate_inner(&ack, req, proc_ctx);

    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRP][%s]fail to send ack", cm_display_resid(req->data, req->type));
        return;
    }

    LOG_DEBUG_INF("[DRP][%s]success to send ack", cm_display_resid(req->data, req->type));
}

void dms_proc_drc_release(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_notify_old_master_t), CM_TRUE);
    dms_notify_old_master_t *req = (dms_notify_old_master_t *)(receive_msg->buffer);
    if (SECUREC_UNLIKELY(req->type >= DRC_RES_TYPE_MAX_COUNT || req->len > DRM_RESID_LEN)) {
        LOG_DEBUG_ERR("[DRP]dms_proc_drc_release invalid message type:%d len:%d", req->type, req->len);
        return;
    }
    LOG_DEBUG_INF("[DRP][%s]release start, src_inst:%d", cm_display_resid(req->data, req->type), req->head.src_inst);
    drm_release_drc(req->data, req->len, req->type, req->options);
}

void drm_req_group_data_init(drm_req_data_t *req, drm_data_t *drm_data)
{
    DMS_INIT_MESSAGE_HEAD(&req->head, MSG_REQ_DRM, 0, g_dms.inst_id, drm_data->inst_id, 0, 0);
    req->head.size = (uint16)(sizeof(drm_req_data_t) + drm_data->data_len);
    req->inst_id = (uint8)g_dms.inst_id;
    req->res_len = drm_data->res_len;
    req->res_type = drm_data->res_type;
    req->data_len = drm_data->data_len;
    req->data_type = drm_data->data_type;
}

void drm_send_data(drm_data_t *drm_data)
{
    if (drm_data->data_len == 0) {
        return;
    }

    char *desc = drm_data->data_type == DRM_DATA_MIGRATE ? "migrate" : "release";
    drm_req_data_t req;
    drm_req_group_data_init(&req, drm_data);

    int32 ret = mfc_send_data2_async(&req.head, sizeof(drm_req_data_t), drm_data->data, drm_data->data_len);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRM SMON][%s]fail to send req to inst:%d res_type:%d data_type:%d data_len:%u",
            desc, drm_data->inst_id, drm_data->res_type, drm_data->data_type, drm_data->data_len);
    } else {
        LOG_DEBUG_INF("[DRM SMON][%s]success to send req to inst:%d res_type:%d data_type:%d data_len:%u",
            desc, drm_data->inst_id, drm_data->res_type, drm_data->data_type, drm_data->data_len);
    }
}

void dms_proc_drm(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    drm_t *drm = DRM_CTX;
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(drm_req_data_t), CM_TRUE);
    drm_req_data_t *req = (drm_req_data_t *)receive_msg->buffer;
    if (SECUREC_UNLIKELY(req->inst_id >= DMS_MAX_INSTANCES ||
        req->res_type >= DRC_RES_TYPE_MAX_COUNT ||
        req->res_len > DRM_RESID_LEN ||
        req->data_len > DRM_BUFFER_SIZE ||
        req->data_type >= DRM_DATA_TYPE_COUNT)) {
        LOG_DEBUG_ERR("[DRP]dms_proc_drm invalid message");
        return;
    }
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(drm_req_data_t) + req->data_len, CM_TRUE);

    drm_group_t *drm_group = NULL;
    if (req->data_type == DRM_DATA_MIGRATE) {
        drm_group = &drm->migrate;
    } else {
        CM_ASSERT(req->data_type == DRM_DATA_RELEASE);
        drm_group = &drm->release;
    }

    if (drm_group->received) { // received data but not yet processed, discard current message
        return;
    }

    cm_spin_lock(&drm_group->lock, NULL);
    if (drm_group->received) { // received data but not yet processed, discard current message
        cm_spin_unlock(&drm_group->lock);
        return;
    }
    drm_data_t *data = &drm_group->data[drm_group->wid]; // get buffer to cache message
    data->inst_id = req->inst_id;
    data->res_len = req->res_len;
    data->res_type = req->res_type;
    data->data_type = req->data_type;
    data->data_len = req->data_len;
    errno_t err = memcpy_s(data->data, DRM_BUFFER_SIZE, (char *)req + sizeof(drm_req_data_t), req->data_len);
    DMS_SECUREC_CHECK(err);
    drm_group->received = CM_TRUE;
    cm_spin_unlock(&drm_group->lock);
    cm_event_notify(&drm->event);
}

int drm_req_finish(uint8 dst_id, bool32 *trigger)
{
    dms_message_head_t head;
    DMS_INIT_MESSAGE_HEAD(&head, MSG_REQ_DRM_FINISH, 0, g_dms.inst_id, dst_id, 0, 0);
    head.size = (uint16)(sizeof(dms_message_head_t));

    int32 ret = mfc_send_data(&head);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRM SMON][drm_req_finish]send failed, dst_inst:%d", dst_id);
        return ret;
    }

    dms_message_t message = { 0 };
    ret = mfc_get_response(head.ruid, &message, DMS_WAIT_MAX_TIME);
    if (ret != CM_SUCCESS) {
        LOG_DEBUG_ERR("[DRM SMON][drm_req_finish]receive failed, dst_inst:%d", dst_id);
        return ret;
    }

    drm_ack_finish_t *ack = (drm_ack_finish_t *)message.buffer;
    *trigger = ack->trigger;
    mfc_release_response(&message);
    return DMS_SUCCESS;
}

void dms_proc_drm_finish(dms_process_context_t *proc_ctx, dms_message_t *receive_msg)
{
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, (uint32)sizeof(dms_message_head_t), CM_TRUE);
    dms_message_head_t *req_head = (dms_message_head_t *)receive_msg->buffer;

    drm_t *drm = DRM_CTX;
    drm_ack_finish_t ack;
    dms_init_ack_head(req_head, &ack.head, MSG_ACK_DRM_FINISH, sizeof(drm_ack_finish_t), proc_ctx->sess_id);
    ack.trigger = drm->trigger;
    if (mfc_send_data(&ack.head) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRM][dms_proc_drm_finish]fail to send ack");
        return;
    }
    LOG_DEBUG_INF("[DRM][dms_proc_drm_finish]success to send ack");
}

bool8 drc_cmp_part_info(void)
{
    for (uint8 i = 0; i < DRC_MAX_PART_NUM; i++) {
        if (DRC_PART_MASTER_ID(i) != DRC_PART_OLD_MASTER_ID(i)) {
            return CM_FALSE;
        }
    }
    return CM_TRUE;
}

void drm_release_drc(char *data, uint16 len, uint8 type, uint8 options)
{
    drc_global_res_map_t *global_res = drc_get_global_res_map(type);
    drc_res_bucket_t *bucket = drc_res_map_get_bucket(&global_res->res_map, data, len);
    uint8 new_options = (options | DRC_RES_CHECK_OLD_MASTER) & ~DRC_RES_CHECK_MASTER & ~DRC_ALLOC;
    drc_head_t *drc = NULL;
    if (drc_enter(data, len, type, new_options, &drc) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DRP][%s]fail to enter drc", cm_display_resid(data, type));
        return;
    }
    if (drc == NULL) {
        LOG_DEBUG_INF("[DRP][%s]drc not exists", cm_display_resid(data, type));
        return;
    }
    cm_spin_lock(&bucket->lock, NULL);
    if (drc->ref_count > 1) {
        cm_spin_unlock(&bucket->lock);
        drc_leave(drc, new_options);
        LOG_DEBUG_INF("[DRP][%s]fail to release because of ref_count > 1", cm_display_resid(data, type));
        return;
    }
    drc_release(drc, &global_res->res_map, bucket);
    cm_spin_unlock(&bucket->lock);
    drc_unlatch(type, new_options);
    LOG_DEBUG_INF("[DRP][%s]release success", cm_display_resid(data, type));
}

// old master, release drc after receive release message
void drm_release(void)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;
    drm_group_t *release = &drm->release;

    uint64 start_time = g_timer()->monotonic_now;
    cm_spin_lock(&release->lock, NULL);
    if (!release->received) {
        cm_spin_unlock(&release->lock);
        stat->time_release += g_timer()->monotonic_now - start_time;
        return;
    }
    drm_data_t *drm_data = &release->data[release->wid];
    release->wid = !release->wid;
    release->received = CM_FALSE;
    cm_spin_unlock(&release->lock);

    LOG_DEBUG_INF("[DRM SMON][release]receive from current master:%d res_type:%d data_len:%u",
        drm_data->inst_id, drm_data->res_type, drm_data->data_len);
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_BIZ_SESSION, CM_FALSE);
    for (uint32 offset = 0; offset < drm_data->data_len; offset += drm_data->res_len) {
        drm_release_drc(drm_data->data + offset, drm_data->res_len, drm_data->res_type, options);
        stat->count_release++;
    }
    stat->time_release += g_timer()->monotonic_now - start_time;
}

void drm_data_init(drm_data_t *drm_data, uint8 inst_id, uint8 res_type, uint16 res_len, uint32 data_type)
{
    drm_data->inst_id = inst_id;
    drm_data->res_type = res_type;
    drm_data->res_len = res_len;
    drm_data->data_type = data_type;
    drm_data->data_len = 0;
}

uint32 drm_get_migrate_res_len(uint8 type)
{
    switch (type) {
        case DRC_RES_PAGE_TYPE:
            return sizeof(drm_migrate_page_t);

        case DRC_RES_LOCK_TYPE:
            return sizeof(drm_migrate_lock_t);

        case DRC_RES_ALOCK_TYPE:
            return sizeof(drm_migrate_alock_t);

        case DRC_RES_GLOBAL_XA_TYPE:
            return sizeof(drm_migrate_xa_t);

        default:
            CM_ASSERT(0);
            return 0;
    }
}

void drm_collect_drc(drm_data_t *drm_data, uint32 offset, drc_head_t *drc)
{
    switch (drc->type) {
        case DRC_RES_PAGE_TYPE: {
            drm_migrate_page_t *migrate_page = (drm_migrate_page_t *)(drm_data->data + offset);
            drc_page_t *drc_page = (drc_page_t *)drc;
            errno_t err = memcpy_s(migrate_page->resid, drc->len, DRC_DATA(drc), drc->len);
            DMS_SECUREC_CHECK(err);
            err = memcpy_s(&migrate_page->converting, sizeof(drc_cvt_item_t), &drc->converting, sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            migrate_page->owner = drc->owner;
            migrate_page->lock_mode = drc->lock_mode;
            migrate_page->copy_insts = drc->copy_insts;
            migrate_page->edp_map = drc_page->edp_map;
            migrate_page->last_edp = drc_page->last_edp;
            migrate_page->last_edp_lsn = drc_page->last_edp_lsn;
            migrate_page->seq = drc_page->seq;
            break;
        }

        case DRC_RES_LOCK_TYPE: {
            drm_migrate_lock_t *migrate_lock = (drm_migrate_lock_t *)(drm_data->data + offset);
            errno_t err = memcpy_s(migrate_lock->resid, drc->len, DRC_DATA(drc), drc->len);
            DMS_SECUREC_CHECK(err);
            err = memcpy_s(&migrate_lock->converting, sizeof(drc_cvt_item_t), &drc->converting, sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            migrate_lock->owner = drc->owner;
            migrate_lock->lock_mode = drc->lock_mode;
            migrate_lock->copy_insts = drc->copy_insts;
            break;
        }

        case DRC_RES_ALOCK_TYPE: {
            drm_migrate_alock_t *migrate_alock = (drm_migrate_alock_t *)(drm_data->data + offset);
            errno_t err = memcpy_s(migrate_alock->resid, drc->len, DRC_DATA(drc), drc->len);
            DMS_SECUREC_CHECK(err);
            err = memcpy_s(&migrate_alock->converting, sizeof(drc_cvt_item_t), &drc->converting,
                sizeof(drc_cvt_item_t));
            DMS_SECUREC_CHECK(err);
            migrate_alock->owner = drc->owner;
            migrate_alock->lock_mode = drc->lock_mode;
            migrate_alock->copy_insts = drc->copy_insts;
            break;
        }

        case DRC_RES_GLOBAL_XA_TYPE: {
            drm_migrate_xa_t *migrate_xa = (drm_migrate_xa_t *)(drm_data->data + offset);
            errno_t err = memcpy_s(migrate_xa->resid, drc->len, DRC_DATA(drc), drc->len);
            DMS_SECUREC_CHECK(err);
            migrate_xa->owner = drc->owner;
            break;
        }

        default:
            CM_ASSERT(0);
            break;
    }
}

bool8 drm_collect_part_inner(uint8 master, uint16 part_id, uint8 type, uint16 len)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;
    drc_global_res_map_t *res_map = drc_get_global_res_map(type);
    drc_part_list_t *part = &res_map->res_parts[part_id];
    uint32 migrate_res_len = drm_get_migrate_res_len(type);

    if (part->list.count == 0) {
        return CM_FALSE;
    }

    drm_data_t *migrate_data = &drm->send_data;
    drm_data_init(migrate_data, master, type, len, DRM_DATA_MIGRATE);

    cm_spin_lock(&part->lock, NULL);
    bilist_node_t *node = cm_bilist_head(&part->list);
    uint32 offset = 0;
    while (node != NULL && (offset + migrate_res_len) <= DRM_BUFFER_SIZE) {
        drc_head_t *drc = DRC_RES_NODE_OF(drc_head_t, node, part_node);
        drm_collect_drc(migrate_data, offset, drc);
        node = BINODE_NEXT(node);
        offset += migrate_res_len;
        stat->count_collect++;
    }
    migrate_data->data_len = offset;
    cm_spin_unlock(&part->lock);

    drm_send_data(migrate_data);
    return CM_TRUE;
}

bool8 drm_collect_part(uint8 curr_master, uint16 part_id)
{
    if (drm_collect_part_inner(curr_master, part_id, DRC_RES_PAGE_TYPE, DMS_PAGEID_SIZE) ||
        drm_collect_part_inner(curr_master, part_id, DRC_RES_LOCK_TYPE, DMS_DRID_SIZE) ||
        drm_collect_part_inner(curr_master, part_id, DRC_RES_ALOCK_TYPE, DMS_ALOCKID_SIZE) ||
        drm_collect_part_inner(curr_master, part_id, DRC_RES_GLOBAL_XA_TYPE, DMS_XA_SIZE)) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

// if the master fails to migrate DRC in time. duplicate DRC may be sent. so choose the next part as beginning
void drm_collect(void)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;

    uint64 start_time = g_timer()->monotonic_now;
    for (uint16 part_id = drm->part_id; part_id < drm->part_id + DRC_MAX_PART_NUM; part_id++) {
        uint16 partid = part_id % DRC_MAX_PART_NUM;
        uint8 curr_master = DRC_PART_MASTER_ID(partid);
        uint8 old_master = DRC_PART_OLD_MASTER_ID(partid);
        if (curr_master == old_master || dms_dst_id_is_self(curr_master) || !dms_dst_id_is_self(old_master)) {
            continue;
        }
        if (drm_collect_part(curr_master, partid)) {
            stat->time_collect += g_timer()->monotonic_now - start_time;
            drm->part_id = (partid + 1) % DRC_MAX_PART_NUM;
            return;
        }
    }

    drm->trigger = CM_FALSE;
    stat->time_collect += g_timer()->monotonic_now - start_time;
}

void drm_migrate(void)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;
    drm_group_t *migrate = &drm->migrate;

    uint64 start_time = g_timer()->monotonic_now;
    cm_spin_lock(&migrate->lock, NULL);
    if (!migrate->received) {
        cm_spin_unlock(&migrate->lock);
        stat->time_migrate += g_timer()->monotonic_now - start_time;
        return;
    }

    drm_data_t *migrate_data = &migrate->data[migrate->wid];
    migrate->wid = !migrate->wid;
    migrate->received = CM_FALSE;
    cm_spin_unlock(&migrate->lock);

    LOG_DEBUG_INF("[DRM SMON][migrate]receive from old master:%d res_type:%d data_len:%u",
        migrate_data->inst_id, migrate_data->res_type, migrate_data->data_len);

    drm_data_t *release_data = &drm->send_data;
    drm_data_init(release_data, migrate_data->inst_id, migrate_data->res_type, migrate_data->res_len,
        DRM_DATA_RELEASE);

    uint32 offset_migrate = 0;
    uint32 offset_release = 0;
    uint32 migrate_res_len = drm_get_migrate_res_len(migrate_data->res_type);
    while (offset_migrate < migrate_data->data_len) {
        char *resid = migrate_data->data + offset_migrate;
        if (drm_create(resid, migrate_data->res_len, migrate_data->res_type)) {
            stat->count_migrate++;
            errno_t err = memcpy_s(release_data->data + offset_release, DRM_BUFFER_SIZE - offset_release,
                resid, migrate_data->res_len);
            DMS_SECUREC_CHECK(err);
            offset_release += migrate_data->res_len;
        }
        offset_migrate += migrate_res_len;
    }
    release_data->data_len = offset_release;
    drm_send_data(release_data);
    stat->time_migrate += g_timer()->monotonic_now - start_time;
}

void drm_thread_set_pause(void)
{
    drm_t *drm = DRM_CTX;
    drm->status = THREAD_STATUS_ENDING;
    cm_event_notify(&drm->event);
    while (drm->status != THREAD_STATUS_ENDED) {
        cm_sleep(1);
    }
    LOG_RUN_INF("[DRM SMON]drm_thread pause");
}

void drm_thread_set_running(void)
{
    drm_t *drm = DRM_CTX;
    drm->status = THREAD_STATUS_PROCESSSING;
    cm_event_notify(&drm->event);
    LOG_RUN_INF("[DRM SMON]drm_thread run");
}

void drm_trigger(void)
{
    drm_t *drm = DRM_CTX;
    drm->trigger = CM_TRUE;
    drm->part_id = 0;
    drm->migrate.received = CM_FALSE;
    drm->migrate.wid = 0;
    drm->release.received = CM_FALSE;
    drm->release.wid = 0;

    drm_stat_t *stat = DRM_STAT;
    DMS_SECUREC_CHECK(memset_s(stat, sizeof(drm_stat_t), 0, sizeof(drm_stat_t)));
}

void drm_finish(void)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (drm->trigger || drc_cmp_part_info()) {
        return;
    }

    bool32 trigger = CM_TRUE;
    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (dms_dst_id_is_self(i)) {
            continue;
        }
        if (!bitmap64_exist(&reform_info->bitmap_in, i)) {
            continue;
        }
        if (drm_req_finish(i, &trigger) != DMS_SUCCESS) {
            return;
        }
        if (trigger) {
            return;
        }
    }

    // overwrite old master map with current master map
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    dms_reform_part_copy_inner(part_mngr->old_inst_part_tbl, part_mngr->inst_part_tbl,
        part_mngr->old_part_map, part_mngr->part_map);

    LOG_RUN_INF("[DRM SMON]time_total:%llu time_release:%llu time_collect:%llu time_migrate:%llu count_wait:%u "
        "count_release:%u count_collect:%u count_migrate:%u", stat->time_total, stat->time_release, stat->time_collect,
        stat->time_migrate, stat->count_wait, stat->count_release, stat->count_collect, stat->count_migrate);
}

void drm_sleep(void)
{
    drm_t *drm = DRM_CTX;
    drm_stat_t *stat = DRM_STAT;
    drm_group_t *release = &drm->release;
    drm_group_t *migrate = &drm->migrate;

    if (migrate->received || release->received) {
        return;
    }

    // considering the slow speed of DRC migrate, in order to avoid wasting network, sleep 10ms here
    (void)cm_event_timedwait(&drm->event, DRM_SLEEP_TIME);
    stat->count_wait++;
}

// Due to the constraints of the re-master algorithm
// drm_collect and drm_migrate can not be executed simultaneously at the same node
void drm_inner(void)
{
    drm_t *drm = DRM_CTX;

    if (drc_cmp_part_info()) {
        (void)cm_event_timedwait(&drm->event, DMS_REFORM_SHORT_TIMEOUT);
        return;
    }

    drm_stat_t *stat = DRM_STAT;
    uint64 time_start = g_timer()->monotonic_now;
    drm_release();
    drm_collect();
    drm_migrate();
    drm_finish();
    drm_sleep();
    stat->time_total += g_timer()->monotonic_now - time_start;
}

void drm_thread(thread_t *thread)
{
#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif
    drm_t *drm = DRM_CTX;

    LOG_RUN_INF("[DRM SMON]drm_thread start");
    while (!thread->closed) {
        if (drm->status == THREAD_STATUS_PROCESSSING) {
            drm_inner();
            continue;
        }
        if (drm->status == THREAD_STATUS_IDLE || drm->status == THREAD_STATUS_ENDING) {
            drm->status = THREAD_STATUS_ENDED;
        }
        (void)cm_event_timedwait(&drm->event, DMS_REFORM_SHORT_TIMEOUT);
    }
    LOG_RUN_INF("[DRM SMON]drm_thread close");
}

int drm_thread_init(void)
{
    drm_t *drm = DRM_CTX;

    cm_event_init(&drm->event);
    int ret = cm_create_thread(drm_thread, 0, NULL, &drm->thread);
    if (ret != CM_SUCCESS) {
        cm_event_destory(&drm->event);
        return ret;
    }

    drm->inited = CM_TRUE;
    return DMS_SUCCESS;
}

void drm_thread_deinit(void)
{
    drm_t *drm = DRM_CTX;

    if (!drm->inited) {
        return;
    }

    cm_close_thread_with_event(&drm->thread, &drm->event);
    cm_event_destory(&drm->event);
    drm->inited = CM_FALSE;
}