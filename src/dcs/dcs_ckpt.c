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
 * dcs_ckpt.c
 *
 *
 * IDENTIFICATION
 *    src/dcs/dcs_ckpt.c
 *
 * -------------------------------------------------------------------------
 */

#include "dcs_ckpt.h"
#include "cm_defs.h"
#include "dms.h"
#include "dms_cm.h"
#include "dms_error.h"
#include "dms_msg_command.h"
#include "dms_msg_protocol.h"
#include "drc.h"
#include "drc_res_mgr.h"
#include "mes_interface.h"
#include "dcs_page.h"

static int32 dcs_send_edp(dms_context_t *dms_ctx, uint8 dest_id, uint32 cmd, dms_edp_info_t *pages, uint32 count)
{
    int32 ret;
    dms_message_head_t head;
    DMS_INIT_MESSAGE_HEAD(&head, cmd, 0, dms_ctx->inst_id, dest_id, dms_ctx->sess_id, CM_INVALID_ID16);
    uint32 left_cnt = count;
    uint32 max_send_cnt = (uint32)(((DMS_MESSAGE_BUFFER_SIZE - sizeof(dms_message_head_t)) - sizeof(unsigned int)) /
        sizeof(dms_edp_info_t));

    while (left_cnt > 0) {
        uint32 send_cnt = MIN(max_send_cnt, left_cnt);
        uint32 size = (uint32)(sizeof(dms_message_head_t) + sizeof(unsigned int) + send_cnt * sizeof(dms_edp_info_t));
        head.size = (uint16)size;

        if ((ret = mfc_send_data4_async(&head, sizeof(dms_message_head_t), &send_cnt, (uint32)sizeof(unsigned int),
            pages, send_cnt * (uint32)sizeof(dms_edp_info_t))) != CM_SUCCESS) {
            LOG_DEBUG_ERR("[DMS]send edp failed, errno = %d", ret);
            DMS_THROW_ERROR(ERRNO_DMS_DCS_SEND_EDP_FAILED);
            return ERRNO_DMS_DCS_SEND_EDP_FAILED;
        }
        pages += send_cnt;
        left_cnt = left_cnt - send_cnt;
    }
    return DMS_SUCCESS;
}

static int32 dcs_send_edp_to_master_ckpt(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count)
{
    DMS_FAULT_INJECTION_CALL(DMS_FI_REQ_MASTER_CKPT_EDP, MSG_REQ_MASTER_CKPT_EDP);
    return dcs_send_edp(dms_ctx, inst_id, MSG_REQ_MASTER_CKPT_EDP, pages, count);
}

static int32 dcs_send_edp_to_owner_ckpt(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count)
{
    DMS_FAULT_INJECTION_CALL(DMS_FI_REQ_OWNER_CKPT_EDP, MSG_REQ_OWNER_CKPT_EDP);
    return dcs_send_edp(dms_ctx, inst_id, MSG_REQ_OWNER_CKPT_EDP, pages, count);
}

static int32 dcs_send_edp_to_master_clean(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count)
{
    DMS_FAULT_INJECTION_CALL(DMS_FI_REQ_MASTER_CLEAN_EDP, MSG_REQ_MASTER_CLEAN_EDP);
    return dcs_send_edp(dms_ctx, inst_id, MSG_REQ_MASTER_CLEAN_EDP, pages, count);
}

static int32 dcs_send_edp_to_owner_clean(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count)
{
    DMS_FAULT_INJECTION_CALL(DMS_FI_REQ_OWNER_CLEAN_EDP, MSG_REQ_OWNER_CLEAN_EDP);
    return dcs_send_edp(dms_ctx, inst_id, MSG_REQ_OWNER_CLEAN_EDP, pages, count);
}

static int32 cmp_edp_by_id(const void *pa, const void *pb)
{
    const dms_edp_info_t *a = (const dms_edp_info_t *)pa;
    const dms_edp_info_t *b = (const dms_edp_info_t *)pb;
    if (a->id == b->id) {
        return 0;
    } else if (a->id < b->id) {
        return -1;
    } else {
        return 1;
    }
}

static void sort_edp_by_id(dms_edp_info_t *pages, uint32 count)
{
    if (count <= 1) {
        return;
    }
    qsort(pages, count, sizeof(dms_edp_info_t), cmp_edp_by_id);
}

static int dcs_get_page_master_id(dms_context_t *dms_ctx, char pageid[DMS_PAGEID_SIZE], unsigned char *master_id)
{
    return drc_get_page_master_id(pageid, master_id);
}

// only used for ckpt
static int dcs_ckpt_get_page_owner(dms_context_t *dms_ctx, char pageid[DMS_PAGEID_SIZE], unsigned char *owner_id)
{
    return dcs_ckpt_get_page_owner_inner(dms_ctx->db_handle, dms_ctx->edp_inst, pageid, owner_id);
}

typedef int32(*cb_calc_edp)(dms_context_t *dms_ctx, char pageid[DMS_PAGEID_SIZE], uint8 *inst_id);
typedef int32(*cb_process_edp)(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count);
typedef int32(*cb_send_edp)(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count);

static int32 dcs_notify_process_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count, uint32 *rest_begin,
    cb_calc_edp calc_edp, cb_process_edp process_edp, cb_send_edp send_edp)
{
    int32 ret;
    uint32 begin = 0;
    uint32 end = 0;
    uint32 tmp_count = count;

    for (uint32 i = 0; i < tmp_count; i++) {
        if (calc_edp(dms_ctx, pages[i].page, &pages[i].id) != DMS_SUCCESS || pages[i].id == CM_INVALID_ID8) {
            /* get master id or owner id failed, move it to array's tail */
            SWAP(dms_edp_info_t, pages[i], pages[tmp_count - 1]);
            tmp_count--;
        }
    }
    if (rest_begin != NULL) {
        *rest_begin = tmp_count;
    }
    sort_edp_by_id(pages, tmp_count);

    while (end < tmp_count) {
        begin = end;
        if (begin >= tmp_count) {
            break;
        }

        while (end < tmp_count) {
            end++;
            if (end == tmp_count || pages[end - 1].id != pages[end].id) {
                break;
            }
        }

        if (pages[begin].id == g_dms.inst_id) {
            /* local instance */
            ret = process_edp(dms_ctx, pages + begin, end - begin);
        } else {
            /* remote instance */
            ret = send_edp(dms_ctx, pages[begin].id, pages + begin, end - begin);
        }

        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    return DMS_SUCCESS;
}

static int32 dcs_owner_ckpt_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count)
{
    if (g_dms.callback.ckpt_session(dms_ctx->db_handle)) {
        return DMS_SUCCESS;
    }
    return g_dms.callback.ckpt_edp(dms_ctx->db_handle, pages, count);
}

static int32 dcs_owner_clean_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count)
{
    return g_dms.callback.clean_edp(dms_ctx->db_handle, pages, count);
}

static bool32 get_and_clean_edp_map(dms_context_t *dms_ctx, dms_edp_info_t *edp)
{
    drc_buf_res_t *buf_res = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_NORMAL, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter_buf_res(edp->page, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &buf_res);
    if (ret != DMS_SUCCESS) {
        return CM_FALSE;
    }
    if (buf_res == NULL) {
        return CM_FALSE;
    }
    if (buf_res->need_recover) {
        drc_leave_buf_res(buf_res);
        return CM_FALSE;
    }

    if (buf_res->claimed_owner == CM_INVALID_ID8) {
        edp->edp_map = buf_res->edp_map != 0 ? buf_res->edp_map : CM_INVALID_ID64;
        buf_res->edp_map = 0;
        drc_leave_buf_res(buf_res);
        return CM_TRUE;
    }

    if (buf_res->lsn > edp->lsn || buf_res->edp_map == 0) {
        drc_leave_buf_res(buf_res);
        return CM_FALSE;
    }

    edp->edp_map = buf_res->edp_map;

    /* cleanup edp map */
    buf_res->edp_map = 0;
    buf_res->lsn = edp->lsn;
    buf_res->last_edp = CM_INVALID_ID8;
    drc_leave_buf_res(buf_res);
    return CM_TRUE;
}

static int32 pickout_and_send_edp(dms_context_t *dms_ctx, uint8 inst_id, dms_edp_info_t *pages, uint32 count)
{
    int32 ret;
    uint32 i;
    uint32 tmp_count = count;
    uint64 bit_map = 1ULL << inst_id;

    i = 0;
    while (i < tmp_count) {
        if ((pages[i].edp_map & bit_map) != 0) {
            SWAP(dms_edp_info_t, pages[i], pages[tmp_count - 1]);
            tmp_count--;
            continue;
        }
        i++;
    }

    if (tmp_count >= count) {
        return DMS_SUCCESS;
    }

    if (inst_id == g_dms.inst_id && !g_dms.callback.ckpt_session(dms_ctx->db_handle)) {
        ret = dcs_owner_clean_edp(dms_ctx, pages + tmp_count, count - tmp_count);
    } else {
        ret = dcs_send_edp_to_owner_clean(dms_ctx, inst_id, pages + tmp_count, count - tmp_count);
    }
    return ret;
}

static int32 dcs_master_clean_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count)
{
    uint32 i = 0;
    uint64 inst_map = 0;
    int32 ret;

    if (count == 0) {
        return DMS_SUCCESS;
    }

    while (i < count) {
        if (!get_and_clean_edp_map(dms_ctx, pages + i)) {
            SWAP(dms_edp_info_t, pages[i], pages[count - 1]);
            count--;
            continue;
        }
        inst_map = inst_map | pages[i].edp_map;
        i++;
    }

    if (count == 0) {
        return DMS_SUCCESS;
    }

    for (i = 0; i < g_dms.inst_cnt; i++) {
        if ((inst_map & (1ULL << i)) == 0) {
            continue;
        }
        if ((ret = pickout_and_send_edp(dms_ctx, (uint8)i, pages, count)) != DMS_SUCCESS) {
            return ret;
        }
    }

    return DMS_SUCCESS;
}

/*
  [rest_begin, tmp_count]: owner does not really exist, should clean edp
  [tmp_count, count]: fail to get owner or owner exists, ignore
*/
static void dcs_master_clean_ownerless_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count, uint32 begin)
{
    uint32 tmp_count = count;
    for (uint32 i = begin; i < tmp_count; i++) {
        if ((dcs_ckpt_get_page_owner(dms_ctx, pages[i].page, &pages[i].id)) != DMS_SUCCESS ||
            pages[i].id != CM_INVALID_ID8) {
            /* owner exists or get owner id failed because fail to get disk lsn */
            SWAP(dms_edp_info_t, pages[i], pages[tmp_count - 1]);
            tmp_count--;
        }
    }
    (void)dcs_master_clean_edp(dms_ctx, pages + begin, tmp_count - begin);
}

/*
  [0, rest_begin]: owner exists, send to owner to do checkpoint
  [rest_begin, count]: owner not exists or fail to get owner, should re-check
*/
static int32 dcs_master_ckpt_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, uint32 count)
{
    uint32 rest_begin = count;
    int ret = dcs_notify_process_edp(dms_ctx, pages, count, &rest_begin,
        dcs_ckpt_get_page_owner, dcs_owner_ckpt_edp, dcs_send_edp_to_owner_ckpt);
    dcs_master_clean_ownerless_edp(dms_ctx, pages, count, rest_begin);
    return ret;
}

int dms_ckpt_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, unsigned int count)
{
    dms_reset_error();
    return dcs_notify_process_edp(dms_ctx, pages, count, NULL,
        dcs_get_page_master_id, dcs_master_ckpt_edp, dcs_send_edp_to_master_ckpt);
}

int dms_clean_edp(dms_context_t *dms_ctx, dms_edp_info_t *pages, unsigned int count)
{
    dms_reset_error();
    return dcs_notify_process_edp(dms_ctx, pages, count, NULL,
        dcs_get_page_master_id, dcs_master_clean_edp, dcs_send_edp_to_master_clean);
}

void dcs_proc_master_ckpt_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifndef OPENGAUSS
    dms_context_t dms_ctx;
    dms_ctx.inst_id = process_ctx->inst_id;
    dms_ctx.sess_id = process_ctx->sess_id;
    dms_ctx.db_handle = process_ctx->db_handle;
    dms_ctx.edp_inst = receive_msg->head->src_inst;

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    uint32 count = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    total_size += (uint32)(count * sizeof(dms_edp_info_t));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    char *pages = receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32);
    (void)dcs_master_ckpt_edp(&dms_ctx, (dms_edp_info_t *)pages, count);
#endif
    /* There is no ack message. */
    return;
}

void dcs_proc_owner_ckpt_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifndef OPENGAUSS
    dms_context_t dms_ctx;
    dms_ctx.inst_id = process_ctx->inst_id;
    dms_ctx.sess_id = process_ctx->sess_id;
    dms_ctx.db_handle = process_ctx->db_handle;

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    uint32 count = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    total_size += (uint32)(count * sizeof(dms_edp_info_t));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    char *pages = receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32);
    (void)dcs_owner_ckpt_edp(&dms_ctx, (dms_edp_info_t *)pages, count);
#endif
    /* There is no ack message. */
    return;
}

void dcs_proc_master_clean_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifndef OPENGAUSS
    dms_context_t dms_ctx;
    dms_ctx.inst_id = process_ctx->inst_id;
    dms_ctx.sess_id = process_ctx->sess_id;
    dms_ctx.db_handle = process_ctx->db_handle;

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    uint32 count = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    total_size += (uint32)(count * sizeof(dms_edp_info_t));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    char *pages = receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32);
    (void)dcs_master_clean_edp(&dms_ctx, (dms_edp_info_t *)pages, count);
#endif
    /* There is no ack message. */
    return;
}

void dcs_proc_owner_clean_edp_req(dms_process_context_t *process_ctx, dms_message_t *receive_msg)
{
#ifndef OPENGAUSS
    dms_context_t dms_ctx;
    dms_ctx.inst_id = process_ctx->inst_id;
    dms_ctx.sess_id = process_ctx->sess_id;
    dms_ctx.db_handle = process_ctx->db_handle;

    uint32 total_size = (uint32)(sizeof(dms_message_head_t) + sizeof(uint32));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    uint32 count = *(uint32 *)(receive_msg->buffer + sizeof(dms_message_head_t));
    total_size += (uint32)(count * sizeof(dms_edp_info_t));
    CM_CHK_PROC_MSG_SIZE_NO_ERR(receive_msg, total_size, CM_FALSE);
    char *pages = receive_msg->buffer + sizeof(dms_message_head_t) + sizeof(uint32);
    (void)dcs_owner_clean_edp(&dms_ctx, (dms_edp_info_t *)pages, count);
#endif
    /* There is no ack message. */
    return;
}
