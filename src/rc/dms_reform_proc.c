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
#include "dms_reform_judge_switch.h"
#include "dcs_page.h"
#include "dms_reform_health.h"
#include "cm_timer.h"
#include "dms_reform_proc_parallel.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_xa.h"
#include "dms_reform_fault_inject.h"
#include "dms_dynamic_trace.h"
#include "dms.h"

static void dms_reform_set_next_step(uint8 step)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    health_info_t *health_info = DMS_HEALTH_INFO;
    dms_reform_proc_stat_end(reform_info->current_step);
    dms_reform_proc_stat_start(step);
    reform_info->current_step = step;
    health_info->dyn_log_time = cm_clock_monotonic_now(); // record time for trigger dyn log
}

void dms_reform_next_step(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 step = (uint8)share_info->reform_step[reform_info->reform_step_index++];

    if (step == DMS_REFORM_STEP_SYNC_WAIT) {
        reform_info->last_step = reform_info->current_step;
        reform_info->next_step = (uint8)share_info->reform_step[reform_info->reform_step_index];
        reform_info->sync_step = CM_INVALID_ID8;
        reform_info->sync_send_success = CM_FALSE;
    }
    dms_reform_set_next_step(step);
}

static int dms_reform_db_prepare(void)
{
#ifdef OPENGAUSS
    return DMS_SUCCESS;
#else
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = g_dms.callback.db_prepare(g_dms.reform_ctx.handle_proc);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    if (g_dms.callback.get_inst_cnt != NULL) {
        uint32 inst_cnt = g_dms.inst_cnt;
        uint64 inst_map = g_dms.inst_map;
        g_dms.callback.get_inst_cnt(g_dms.reform_ctx.handle_proc, &inst_cnt, &inst_map);
        if (inst_cnt != g_dms.inst_cnt || inst_map != g_dms.inst_map) {
            LOG_RUN_INF("[DMS REFORM] change dms inst_cnt from %u to %u, and inst_map from %llu to %llu",
                g_dms.inst_cnt, inst_cnt, g_dms.inst_map, inst_map);
            g_dms.inst_cnt = inst_cnt;
            g_dms.inst_map = inst_map;
        }
    }

    if (share_info->inst_bitmap[INST_LIST_NEW_JOIN] != 0) {
        uint64 bitmap_saved = share_info->bitmap_stable;
        bitmap64_union(&bitmap_saved, share_info->inst_bitmap[INST_LIST_NEW_JOIN]);

        ret = g_dms.callback.save_list_stable(g_dms.reform_ctx.handle_proc, bitmap_saved,
            share_info->reformer_id, share_info->bitmap_in, DMS_IS_SHARE_REFORMER);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]list_stable fail to save in ctrl");
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED);
            return ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED;
        }
    }

    return DMS_SUCCESS;

#endif
}

static int dms_reform_prepare(void)
{
    dms_reform_proc_stat_start(DRPS_REFORM);
    dms_reform_proc_stat_start(DMS_REFORM_STEP_PREPARE);
    LOG_RUN_FUNC_ENTER;
    dms_scrlock_stop_server();
    int ret = dms_reform_db_prepare();
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_start(void)
{
    LOG_RUN_FUNC_ENTER;
    if (!DMS_FIRST_REFORM_FINISH) {
        g_dms.callback.set_dms_status(g_dms.reform_ctx.handle_proc, (int)DMS_STATUS_REFORM);
    }
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->true_start = CM_TRUE;
#ifdef OPENGAUSS
    share_info_t* share_info = DMS_SHARE_INFO;
    dms_reform_start_context_t rs_cxt = {
        .role = reform_info->dms_role,
        .reform_type = share_info->reform_type,
        .bitmap_participated = share_info->bitmap_online,
        .bitmap_reconnect = share_info->bitmap_reconnect,
    };
    g_dms.callback.reform_start_notify(g_dms.reform_ctx.handle_proc, &rs_cxt);
#endif
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_reconnect_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    int ret = mfc_add_instance_batch(list_online->inst_id_list, list_online->inst_id_count, CM_FALSE);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    reform_info->bitmap_connect = share_info->bitmap_online;
    reform_info->bitmap_in = share_info->bitmap_in;
    return DMS_SUCCESS;
}

static int dms_reform_disconnect(void)
{
    LOG_RUN_FUNC_ENTER;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_proc_stat_start(DRPS_DISCONNECT_GET_LOCK);
    cm_spin_lock(&reform_info->mes_lock, NULL);
    dms_reform_proc_stat_end(DRPS_DISCONNECT_GET_LOCK);
    bitmap64_minus(&reform_info->bitmap_mes, share_info->bitmap_disconnect);
    cm_spin_unlock(&reform_info->mes_lock);
    reform_info->bitmap_connect = share_info->bitmap_online;
    reform_info->bitmap_in = share_info->bitmap_in;

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;

    return DMS_SUCCESS;
}

static int dms_reform_reconnect(void)
{
    LOG_RUN_FUNC_ENTER;

    int ret = dms_reform_reconnect_inner();
    if (ret == DMS_SUCCESS) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
    } else {
        LOG_RUN_FUNC_FAIL;
    }

    return ret;
}

#ifdef OPENGAUSS
void dms_validate_drc(dms_context_t *dms_ctx, dms_buf_ctrl_t *ctrl, unsigned long long lsn, unsigned char is_dirty)
{
    if (ctrl->lock_mode == DMS_LOCK_NULL) {
        return;
    }
    drc_head_t *drc = NULL;
    uint8 options = drc_build_options(CM_FALSE, DMS_SESSION_REFORM, DMS_RES_INTERCEPT_TYPE_NONE, CM_TRUE);
    int ret = drc_enter(dms_ctx->resid, DMS_PAGEID_SIZE, DRC_RES_PAGE_TYPE, options, &drc);
    if (ret != DMS_SUCCESS || drc == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH);
        return;
    }

    LOG_DEBUG_INF("[DRC][%s]dms_validate_drc check", cm_display_pageid(dms_ctx->resid));

    cm_panic_log(memcmp(DRC_DATA(drc), dms_ctx->resid, DMS_PAGEID_SIZE) == 0,
        "[DRC validate]pageid unmatch(DRC:%s, buf:%s)", cm_display_pageid(DRC_DATA(drc)),
        cm_display_pageid(dms_ctx->resid));

    drc_request_info_t *req_info = &drc->converting.req_info;
    if (drc->owner == g_dms.inst_id) {
        if (req_info->inst_id != CM_INVALID_ID8) {
            /*
             * If lock modes unmatch, then cvt matches ctrl.
             * If lock modes match, then the ack message of cvt request must be lost,
             * no need to check connverting info.
             */
            if (ctrl->lock_mode != drc->lock_mode) {
                cm_panic_log(req_info->req_mode == ctrl->lock_mode,
                    "[DRC validate][%s]lock mode unmatch with converting info(DRC:%d, buf:%d, cvt:%d)",
                    cm_display_pageid(dms_ctx->resid), drc->lock_mode, ctrl->lock_mode, req_info->req_mode);
            }
        } else {
            cm_panic_log(drc->lock_mode == ctrl->lock_mode, "[DRC validate][%s]lock mode unmatch(DRC:%d, buf:%d)",
                cm_display_pageid(dms_ctx->resid), drc->lock_mode, ctrl->lock_mode);
        }
    } else {
        bool in_cvt = req_info->inst_id == g_dms.inst_id && ctrl->lock_mode == req_info->req_mode;
        bool in_copy_insts = bitmap64_exist(&drc->copy_insts, g_dms.inst_id) && ctrl->lock_mode == DMS_LOCK_SHARE;
        bool first_load = ctrl->lock_mode == DMS_LOCK_EXCLUSIVE && req_info->req_mode != DMS_LOCK_NULL &&
            drc->copy_insts == 0 && drc->owner == CM_INVALID_ID8;
        cm_panic_log(in_cvt || in_copy_insts || first_load,
            "[DRC validate][%s]lock mode unmatch(buf:%d, copy_insts:%lld, inst_id:%d, claimed_owner:%d)",
            cm_display_pageid(dms_ctx->resid), ctrl->lock_mode, drc->copy_insts, g_dms.inst_id,
            (int)drc->owner);
    }

    drc_leave(drc, options);
}
#endif

static int dms_reform_recovery_analyse_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.recovery_analyse(g_dms.reform_ctx.handle_proc, (void *)&share_info->list_recovery,
        DMS_IS_SHARE_REFORMER);
}

static int dms_reform_recovery_analyse(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_analyse_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.recovery(g_dms.reform_ctx.handle_proc, (void *)&share_info->list_recovery,
        share_info->reform_type, DMS_IS_SHARE_REFORMER);
}

static int dms_reform_dw_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.dw_recovery(g_dms.reform_ctx.handle_proc, (void *)&share_info->dw_recovery_info,
        share_info->bitmap_in, DMS_IS_SHARE_REFORMER);
}

static int dms_reform_df_recovery_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    if (DMS_IS_SHARE_REFORMER) {
        return g_dms.callback.df_recovery(g_dms.reform_ctx.handle_proc,
            share_info->bitmap_in, (void *)&share_info->list_recovery);
    }
    return DMS_SUCCESS;
}

static int dms_reform_space_reload_inner(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    return g_dms.callback.space_reload(g_dms.reform_ctx.handle_normal, share_info->bitmap_in);
}

static void dms_reform_recovery_set_flag_by_part_inner(drc_page_t *drc_page)
{
    DRC_DISPLAY(&drc_page->head, "rcy_clean");
    drc_page->need_recover = CM_FALSE;
    drc_page->need_flush = CM_FALSE;
}

void dms_reform_recovery_set_flag_by_part(drc_part_list_t *part)
{
    bilist_node_t *node = cm_bilist_head(&part->list);
    drc_page_t *drc_page = NULL;

    while (node != NULL) {
        drc_page = (drc_page_t *)DRC_RES_NODE_OF(drc_head_t, node, part_node);
        node = BINODE_NEXT(node);
        dms_reform_recovery_set_flag_by_part_inner(drc_page);
    }
}

static int dms_reform_switch_lock(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    dms_reform_cm_res_trans_lock(share_info->promote_id);

    // wait reform_info->reformer_id change to share_info->promote_id and DMS_ROLE change to correct role
    // otherwise, dms_reform_sync_wait may get error role
    if (reform_info->reformer_id != share_info->promote_id) {
        DMS_REFORM_SHORT_SLEEP;
        return DMS_SUCCESS;
    }

    if ((dms_dst_id_is_self(share_info->promote_id) && DMS_IS_REFORMER) ||
        (!dms_dst_id_is_self(share_info->promote_id) && DMS_IS_PARTNER)) {
        share_info->reformer_id = share_info->promote_id;
#ifdef OPENGAUSS
        g_dms.callback.reform_set_dms_role(g_dms.reform_ctx.handle_normal, share_info->promote_id);
#endif
        LOG_RUN_FUNC_SUCCESS;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    DMS_REFORM_SHORT_SLEEP;
    return DMS_SUCCESS;
}

static int dms_reform_switchover_demote(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->demote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.switchover_demote(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    dms_scrlock_stop_server();
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_switchover_promote_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;
    unsigned char orig_primary_id = share_info->demote_id;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->promote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.switchover_promote_opengauss(g_dms.reform_ctx.handle_proc, orig_primary_id);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_failover_promote_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    if (!dms_dst_id_is_self(share_info->promote_id)) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    ret = g_dms.callback.failover_promote_opengauss(g_dms.reform_ctx.handle_proc);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switchover_promote_prepare(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_promote_prepare(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switchover_promote_phase1(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_promote_phase1(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switchover_promote_switch_log(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_promote_switch_log(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switchover_promote_phase2(void)
{
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_promote_phase2(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    g_dms.callback.reset_link(g_dms.reform_ctx.handle_normal);

    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_tx_rollback_start(list_rollback);
    } else {
        instance_list_t list;
        list.inst_id_count = 0;
        list.inst_id_list[list.inst_id_count++] = g_dms.inst_id;
        ret = dms_reform_tx_rollback_start(&list);
    }

    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_promote_success(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_promote_success(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switch_demote_phase1(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_demote_phase1(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switch_demote_stop_ckpt(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_demote_stop_ckpt(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switch_demote_change_role(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_demote_change_role(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switch_demote_approve(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;

    ret = g_dms.callback.az_switchover_demote_approve(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_switch_demote_phase2(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_switchover_demote_phase2(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_failover_promote_phase1(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_failover_promote_phase1(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_failover_promote_resetlog(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_failover_promote_resetlog(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_az_failover_promote_phase2(void)
{
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;

    LOG_RUN_FUNC_ENTER;
    ret = g_dms.callback.az_failover_promote_phase2(g_dms.reform_ctx.handle_normal);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_tx_rollback_start(list_rollback);
    } else {
        instance_list_t list;
        list.inst_id_count = 0;
        list.inst_id_list[list.inst_id_count++] = g_dms.inst_id;
        ret = dms_reform_tx_rollback_start(&list);
    }

    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_recovery_inner_opengauss(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 self_id = (uint8)g_dms.inst_id;

    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_FAILOVER_OPENGAUSS)) {
        if (DMS_IS_SHARE_REFORMER) {
            return g_dms.callback.opengauss_recovery_primary(g_dms.reform_ctx.handle_proc, share_info->last_reformer);
        }

        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_standby(g_dms.reform_ctx.handle_proc, self_id);
        }
        return DMS_SUCCESS;
    }

    if (DMS_IS_SHARE_REFORMER) {
        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_primary(g_dms.reform_ctx.handle_proc, self_id);
        }
    } else {
        if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
            return g_dms.callback.opengauss_recovery_standby(g_dms.reform_ctx.handle_proc, self_id);
        }
    }
    return DMS_SUCCESS;
}

static int dms_reform_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_recovery_opengauss(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_recovery_inner_opengauss();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_drc_rcy_clean(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    drc_part_list_t *part = NULL;
    uint16 part_id = inst_part->first;

    LOG_RUN_FUNC_ENTER;
    for (uint8 i = 0; i < inst_part->count; i++) {
        part = &ctx->global_buf_res.res_parts[part_id];
        dms_reform_recovery_set_flag_by_part(part);
        part_id = part_mngr->part_map[part_id].next;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_ctl_rcy_clean(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;

    LOG_RUN_FUNC_ENTER;
    dms_reform_proc_stat_start(DRPS_CTL_RCY_CLEAN_WAIT_LATCH);
    cm_latch_x(&reform_ctx->res_ctrl_latch, CM_INVALID_INT32, NULL);
    dms_reform_proc_stat_end(DRPS_CTL_RCY_CLEAN_WAIT_LATCH);
    g_dms.callback.dms_ctl_rcy_clean_parallel(reform_ctx->handle_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    cm_unlatch(&reform_ctx->res_ctrl_latch, NULL);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static bool32 dms_reform_wait_rollback(uint8 inst_id)
{
    uint8 deposit_id = drc_get_deposit_id(inst_id);
    // if current instance has deposit other instance txn, should wait rollback finish
    if (dms_dst_id_is_self(deposit_id) && inst_id != deposit_id) {
        return (bool32)g_dms.callback.tx_rollback_finish(g_dms.reform_ctx.handle_proc, inst_id);
    }
    return CM_TRUE;
}

static int dms_reform_txn_deposit(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    instance_list_t *list_withdraw = &share_info->list_withdraw;
    uint8 inst_id = CM_INVALID_ID8;

    for (uint8 i = 0; i < list_withdraw->inst_id_count; i++) {
        inst_id = list_withdraw->inst_id_list[i];
        if (!dms_reform_wait_rollback(inst_id)) {
            return DMS_SUCCESS;
        }

        dms_reform_proc_stat_start(DRPS_TXN_DEPOSIT_DELETE_XA);
        dms_reform_delete_xa_rms(reform_ctx->handle_normal, inst_id);
        dms_reform_proc_stat_end(DRPS_TXN_DEPOSIT_DELETE_XA);
    }

    int ret = memcpy_s(ctx->deposit_map, DMS_MAX_INSTANCES, remaster_info->deposit_map, DMS_MAX_INSTANCES);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_SECUREC_CHECK_FAIL);
        return ERRNO_DMS_SECUREC_CHECK_FAIL;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

int dms_reform_undo_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.undo_init(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_UNDO_INIT);
            return ERRNO_DMS_CALLBACK_RC_UNDO_INIT;
        }
    }
    return DMS_SUCCESS;
}

int dms_reform_tx_area_init(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_init(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT);
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT;
        }
    }
    return DMS_SUCCESS;
}

int dms_reform_tx_area_load(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_area_load(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD);
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD;
        }
    }
    return DMS_SUCCESS;
}

int dms_reform_tx_rollback_start(instance_list_t *list)
{
    for (uint8 i = 0; i < list->inst_id_count; i++) {
        if (g_dms.callback.tx_rollback_start(g_dms.reform_ctx.handle_normal, list->inst_id_list[i]) != DMS_SUCCESS) {
            DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD);
            return ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD;
        }
    }

    return DMS_SUCCESS;
}


static int dms_reform_convert_to_readwrite(void)
{
#ifndef OPENGAUSS
    if (dms_reform_type_is(DMS_REFORM_TYPE_FOR_STANDBY_MAINTAIN) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_STANDBY) ||
        /* if primary in maintain starts with readonly, we should not convert to readwrite */
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_MAINTAIN) ||
        dms_reform_type_is(DMS_REFORM_TYPE_FOR_AZ_SWITCHOVER_DEMOTE)) {
        return DMS_SUCCESS;
    }
    return g_dms.callback.convert_to_readwrite(g_dms.reform_ctx.handle_normal);
#else
    return DMS_SUCCESS;
#endif
}

static int dms_reform_rollback_prepare(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;

    DDES_FAULT_INJECTION_CALL(DMS_FI_ROLLBACK_PREPARE);

    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_PARTNER || list_rollback->inst_id_count == 0) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    dms_reform_proc_stat_start(DRPS_ROLLBACK_UNDO_INIT);
    int ret = dms_reform_undo_init(list_rollback);
    dms_reform_proc_stat_end(DRPS_ROLLBACK_UNDO_INIT);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_ROLLBACK_TX_AREA_INIT);
    ret = dms_reform_tx_area_init(list_rollback);
    dms_reform_proc_stat_end(DRPS_ROLLBACK_TX_AREA_INIT);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_ROLLBACK_TX_AREA_LOAD);
    ret = dms_reform_tx_area_load(list_rollback);
    dms_reform_proc_stat_end(DRPS_ROLLBACK_TX_AREA_LOAD);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_proc_stat_start(DRPS_ROLLBACK_CVT_TO_RW);
    ret = dms_reform_convert_to_readwrite();
    dms_reform_proc_stat_end(DRPS_ROLLBACK_CVT_TO_RW);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_rollback_start(void)
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_rollback = &share_info->list_rollback;
    if (DMS_IS_SHARE_PARTNER || list_rollback->inst_id_count == 0) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    int ret = dms_reform_tx_rollback_start(list_rollback);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return ret;
}

static int dms_reform_reload_txn(void)
{
    remaster_info_t *remaster_info = DMS_REMASTER_INFO;

    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER || remaster_info->deposit_map[g_dms.inst_id] != g_dms.inst_id) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    instance_list_t list;
    list.inst_id_count = 0;
    list.inst_id_list[list.inst_id_count++] = g_dms.inst_id;

    int ret = dms_reform_undo_init(&list);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_init(&list);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    ret = dms_reform_tx_area_load(&list);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_sync_node_lfn(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;

    LOG_RUN_FUNC_ENTER;
    int ret = g_dms.callback.sync_node_lfn(g_dms.reform_ctx.handle_normal, share_info->reform_type,
        share_info->bitmap_online);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

// set sync wait before done
static int dms_reform_success(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    LOG_RUN_FUNC_ENTER;
    reform_info->reform_success = CM_TRUE;
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static void dms_reform_proc_set_pause(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    CM_ASSERT(reform_info->thread_status == DMS_THREAD_STATUS_RUNNING);
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc pausing");
    reform_info->thread_status = DMS_THREAD_STATUS_PAUSING;
}

static void dms_reform_set_switchover_result(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    switchover_info_t *switchover_info = DMS_SWITCHOVER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    // if current reform is SWITCHOVER, should set switchover result for the new primary
    // clean switchover request in the original primary
    // if current reform is OTHERS, should set switchover result for the session which has request switchover
    if (REFORM_TYPE_IS_SWITCHOVER(share_info->reform_type)) {
        LOG_RUN_INF("[DMS REFORM]dms_reform_set_switchover_result, reform_type: %u, promote_id: %d, current_id: %u",
            share_info->reform_type, share_info->promote_id, g_dms.inst_id);
        if (dms_dst_id_is_self(share_info->promote_id)) {
            cm_spin_lock(&switchover_info->lock, NULL);
            switchover_info->switch_start = CM_FALSE;
            cm_spin_unlock(&switchover_info->lock);
            g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, reform_info->err_code);
        }
        if (dms_dst_id_is_self(share_info->demote_id)) {
            // only clean switchover request in the original primary,
            // because the new primary may have receive new switchover request
            cm_spin_lock(&switchover_info->lock, NULL);
            switchover_info->switch_req = CM_FALSE;
            switchover_info->inst_id = CM_INVALID_ID8;
            switchover_info->sess_id = CM_INVALID_ID16;
            cm_spin_unlock(&switchover_info->lock);
        }
    } else {
        cm_spin_lock(&switchover_info->lock, NULL);
        if (switchover_info->switch_start) {
            if (!dms_reform_version_same(&switchover_info->reformer_version, &reform_info->reformer_version)) {
                switchover_info->switch_start = CM_FALSE;
                g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, ERRNO_DMS_REFORM_FAIL);
            }
        }
        cm_spin_unlock(&switchover_info->lock);
    }
}

#ifndef OPENGAUSS
static void dms_reform_set_az_switchover_result(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    az_switchover_info_t *switchover_info = DMS_AZ_SWITCHOVER_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    // if current reform is SWITCHOVER,should set switchover result for the new primary
    // clean switchover request in the original primary
    // if current reform is OTHERS, should set switchover result for the session which has request switchover
    if (REFORM_TYPE_IS_AZ_SWITCHOVER(share_info->reform_type)) {
        LOG_RUN_INF("[DMS REFORM]dms_reform_set_az_switchover_result, reform_type: %u, promote_id: %d, current_id: %u",
            share_info->reform_type, share_info->promote_id, g_dms.inst_id);
            dms_reform_judgement_az_switchover_info_reset();
            g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, reform_info->err_code);
    } else {
        cm_spin_lock(&switchover_info->lock, NULL);
        if (switchover_info->switch_start) {
            if (!dms_reform_version_same(&switchover_info->reformer_version, &reform_info->reformer_version)) {
                LOG_RUN_INF("[DMS REFORM]dms_reform_set_last_az_switchover_result, curr reform_type: %u,"
                    "promote_id: %d, current_id: %u", share_info->reform_type, share_info->promote_id, g_dms.inst_id);
                switchover_info->switch_start = CM_FALSE;
                switchover_info->inst_id = CM_INVALID_ID8;
                switchover_info->sess_id = CM_INVALID_ID16;
                switchover_info->switch_req = CM_FALSE;
                switchover_info->switch_type = AZ_IDLE;
                g_dms.callback.set_switchover_result(g_dms.reform_ctx.handle_proc, ERRNO_DMS_REFORM_FAIL);
            }
        }
        cm_spin_unlock(&switchover_info->lock);
    }
}
#endif

static inline void dms_reform_mark_locking(bool8 is_locking)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->is_locking = is_locking;
}

static inline void dms_reform_instance_lock_reset()
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_mark_locking(CM_FALSE);
    /* mes workers might be latching S, so be precise here and only unlatch X by reform proc */
    cm_unlatch_x(&reform_info->instance_lock, NULL);
}

static void dms_reform_end(void)
{
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t share_info;

    dms_reform_set_switchover_result();
#ifndef OPENGAUSS
    dms_reform_set_az_switchover_result();
#endif
    // health check should pause before clear share info
    dms_reform_health_set_pause();
    dms_reform_proc_set_pause();
    drm_thread_set_running();
    dms_reform_instance_lock_reset();

#ifdef OPENGAUSS
    dms_reform_handle_fail_in_special_scenario();
#endif
    int ret = memset_s(&share_info, sizeof(share_info_t), 0, sizeof(share_info_t));
    DMS_SECUREC_CHECK(ret);

    reform_info->file_unable = CM_FALSE;
    reform_info->reform_done = CM_TRUE;
    reform_info->reform_fail =  CM_FALSE;
    reform_info->reform_phase =  CM_FALSE;
    reform_ctx->last_reform_info = reform_ctx->reform_info;
    reform_ctx->last_share_info = reform_ctx->share_info;
    reform_ctx->share_info = share_info;
}

#ifndef OPENGAUSS
static void dms_reform_set_idle_behavior(void)
{
    g_dms.callback.set_inst_behavior(g_dms.reform_ctx.handle_proc, DMS_INST_BEHAVIOR_IN_IDLE);
}
#endif

static int dms_reform_standby_update_remove_node_ctrl(void)
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    if (DMS_IS_SHARE_REFORMER) {
        g_dms.callback.standby_update_remove_node_ctrl(g_dms.reform_ctx.handle_normal, share_info->bitmap_online);
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_standby_stop_thread(void)
{
    LOG_DEBUG_INF("[DMS REFORM] dms_reform_standby_stop_thread enter");
    int ret = g_dms.callback.standby_stop_thread(g_dms.reform_ctx.handle_normal);
    if (ret == DMS_SUCCESS) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
    }
    return DMS_SUCCESS;
}

static int dms_reform_standby_reload_node_ctrl(void)
{
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.standby_reload_node_ctrl(g_dms.reform_ctx.handle_normal);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_standby_set_online_list(void)
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    g_dms.callback.set_online_list(g_dms.reform_ctx.handle_normal, share_info->bitmap_online, share_info->reformer_id);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_reformer_update_node_ctrl(void)
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    if (DMS_IS_SHARE_REFORMER) {
        g_dms.callback.az_switchover_demote_update_node_ctrl(g_dms.reform_ctx.handle_normal, share_info->bitmap_online);
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_stop_server(void)
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    if (share_info->list_rollback.inst_id_count != 0) {
        g_dms.callback.standby_stop_server(g_dms.reform_ctx.handle_normal);
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_resume_server_for_reformer(void)
{
    int ret = DMS_SUCCESS;
    if (DMS_IS_SHARE_REFORMER) {
        ret = g_dms.callback.standby_resume_server(g_dms.reform_ctx.handle_normal);
    }
    if (ret == DMS_SUCCESS) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SUCCESS;
    }
    return DMS_SUCCESS;
}

static int dms_reform_resume_server_for_partner(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_PARTNER) {
        g_dms.callback.standby_resume_server(g_dms.reform_ctx.handle_normal);
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_start_lrpl(void)
{
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.start_lrpl(g_dms.reform_ctx.handle_normal, DMS_IS_SHARE_REFORMER);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_stop_lrpl(void)
{
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.stop_lrpl(g_dms.reform_ctx.handle_normal, DMS_IS_SHARE_REFORMER);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_calibrate_log_file(void)
{
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.calibrate_log_file(g_dms.reform_ctx.handle_normal);
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_done(void)
{
    int ret = DMS_SUCCESS;
    share_info_t *share_info = DMS_SHARE_INFO;
    LOG_RUN_FUNC_ENTER;
    bool32 save_ctrl = CM_FALSE;
    if (DMS_IS_SHARE_REFORMER) {
        save_ctrl = CM_TRUE;
    }

#ifndef OPENGAUSS
    g_dms.callback.ckpt_unblock_rcy_local(g_dms.reform_ctx.handle_proc, share_info->bitmap_in);
#endif

    ret = g_dms.callback.save_list_stable(g_dms.reform_ctx.handle_proc, share_info->bitmap_online,
        share_info->reformer_id, share_info->bitmap_in, save_ctrl);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS REFORM]list_stable fail to save in ctrl");
        DMS_THROW_ERROR(ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED);
        return ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED;
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_done_check()
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;
    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_check_reform_done();
        // for ERRNO_DMS_REFORM_NOT_FINISHED, just return DMS_SUCCESS for enter this method again
        if (ret == ERRNO_DMS_REFORM_NOT_FINISHED) {
            return DMS_SUCCESS;
        } else if (ret != DMS_SUCCESS) {
            return ret;
        }
    }
    
    share_info_t *share_info = DMS_SHARE_INFO;
    if (!REFORM_TYPE_IS_AZ_SWITCHOVER(share_info->reform_type)) {
        g_dms.callback.reform_done_notify(g_dms.reform_ctx.handle_proc);
    }

    dms_reform_end();
    reform_info->last_fail = CM_FALSE;
    reform_info->first_reform_finish = CM_TRUE;
    if (!reform_info->rst_recover) { // maintain reeform after rst recover
        reform_info->first_reform_finish = CM_TRUE;
    }
#ifndef OPENGAUSS
    dms_reform_set_idle_behavior();
#endif
    LOG_RUN_FUNC_SUCCESS;
    return ret;
}

static int dms_reform_set_phase(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_FIRST_REFORM_FINISH) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    reform_info->reform_pause = CM_TRUE;
    CM_MFENCE;
    reform_info->reform_phase = (uint8)share_info->reform_phase[reform_info->reform_phase_index++];
    LOG_RUN_INF("[DMS REFORM]dms_reform_set_phase: %s", dms_reform_phase_desc(reform_info->reform_phase));
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_wait_db(void)
{
    if (DMS_FIRST_REFORM_FINISH) {
        dms_reform_next_step();
        LOG_RUN_FUNC_SKIP;
        return DMS_SUCCESS;
    }

    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (reform_info->reform_pause) {
        return DMS_SUCCESS;
    }

    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_file_unblocked(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    LOG_RUN_FUNC_ENTER;
    reform_info->bitmap_in = share_info->bitmap_online;
    reform_info->file_unable = CM_FALSE;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_file_blocked(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    LOG_RUN_FUNC_ENTER;
    dms_reform_proc_stat_start(DRPS_FILE_BLOCKED_WAIT_LATCH);
    cm_latch_x(&reform_info->file_latch, g_dms.reform_ctx.sess_proc, NULL);
    dms_reform_proc_stat_end(DRPS_FILE_BLOCKED_WAIT_LATCH);
    reform_info->file_unable = CM_TRUE;
    cm_unlatch(&reform_info->file_latch, NULL);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_update_scn(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.update_global_scn(g_dms.reform_ctx.handle_proc, reform_info->max_scn);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_wait_ckpt(void)
{
    if ((bool8)g_dms.callback.wait_ckpt(g_dms.reform_ctx.handle_proc)) {
        LOG_RUN_FUNC_SUCCESS;
        dms_reform_next_step();
    }
    return DMS_SUCCESS;
}

// if has not run step dms_reform_start, no need to set last fail
static void dms_reform_set_last_fail(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (reform_info->true_start) {
        reform_info->last_fail = CM_TRUE;
    }

#ifndef OPENGAUSS
    if (!DMS_FIRST_REFORM_FINISH) {
        LOG_RUN_ERR("[DMS REFORM]dms reform fail in first reform, abort");
        cm_exit(0);
    }
#endif
}

static int dms_reform_sync_step_send(void)
{
    dms_reform_req_sync_step_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        dms_reform_init_req_sync_step(&req);
        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS REFORM]dms_reform_sync_step SEND error: %d, dst_id: %d", ret, req.head.dst_inst);
            return ret;
        }

        ret = dms_reform_req_sync_step_wait(req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_sync_step WAIT timeout, dst_id: %d", req.head.dst_inst);
            continue;
        } else {
            break;
        }
    }

    if (ret == DMS_SUCCESS) {
        reform_info->sync_send_success = CM_TRUE;
    }

    return ret;
}

static void dms_reform_sync_fail_r(uint8 dst_id)
{
    dms_reform_req_sync_step_t req;
    dms_reform_init_req_sync_next_step(&req, dst_id);
    (void)mfc_send_data(&req.head); // try to notify partner set reform fail
}

static void dms_reform_remote_fail(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 inst_id = CM_INVALID_ID8;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        inst_id = list_online->inst_id_list[i];
        if (!dms_dst_id_is_self(inst_id)) {
            dms_reform_sync_fail_r(inst_id);
        }
    }
}

// reform fail cause by self
static int dms_reform_self_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    } else {
        (void)dms_reform_sync_step_send();
    }
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_info->reform_fail = CM_TRUE;
    dms_reform_set_last_fail();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

// reform fail cause by notification from reformer
static int dms_reform_fail(void)
{
    LOG_RUN_FUNC_ENTER;
    if (DMS_IS_SHARE_REFORMER) {
        dms_reform_remote_fail();
    }
    dms_reform_set_last_fail();
    dms_reform_end();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}

static int dms_reform_sync_next_step_r(uint8 dst_id)
{
    dms_reform_req_sync_step_t req;
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    while (CM_TRUE) {
        dms_reform_init_req_sync_next_step(&req, dst_id);
        if (reform_info->reform_fail) {
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "reform fail flag has been set");
            return ERRNO_DMS_REFORM_FAIL;
        }

        ret = mfc_send_data(&req.head);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_ERR("[DMS REFORM]dms_reform_sync_next_step_r send error: %d, dst_id: %d", ret, dst_id);
            break;
        }

        ret = dms_reform_req_sync_next_step_wait(req.head.ruid);
        if (ret == ERR_MES_WAIT_OVERTIME) {
            LOG_DEBUG_WAR("[DMS REFORM]dms_reform_sync_next_step_r WAIT timeout, dst_id: %d", dst_id);
            continue;
        } else {
            break;
        }
    }
    return ret;
}

static int dms_reform_sync_next_step(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t *list_online = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    int ret = DMS_SUCCESS;

    for (uint8 i = 0; i < list_online->inst_id_count; i++) {
        dst_id = list_online->inst_id_list[i];
        if (dms_dst_id_is_self(dst_id)) {
            continue;
        }
        ret = dms_reform_sync_next_step_r(dst_id);
        DMS_RETURN_IF_ERROR(ret);
    }

    return DMS_SUCCESS;
}

static int dms_reform_sync_wait_reformer(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;
    instance_list_t *list_onlie = &share_info->list_online;
    uint8 dst_id = CM_INVALID_ID8;
    uint8 ret_flag = CM_FALSE;
    int ret = DMS_SUCCESS;
#ifndef OPENGAUSS
    uint64 scn = g_dms.callback.get_global_scn(g_dms.reform_ctx.handle_proc);
    reform_info->max_scn = MAX(reform_info->max_scn, scn);
#endif
    reformer_ctrl->instance_step[g_dms.inst_id] = reform_info->last_step;
    for (uint8 i = 0; i < list_onlie->inst_id_count; i++) {
        dst_id = list_onlie->inst_id_list[i];
        // can not wait here, return the function, sleep thread and check fail flag at the upper-layer function
        if (reformer_ctrl->instance_step[dst_id] != reform_info->last_step) {
            ret_flag = CM_TRUE;
        }
        if (reformer_ctrl->instance_fail[dst_id]) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait_reformer receive partner(%d) fail", dst_id);
            DMS_THROW_ERROR(ERRNO_DMS_REFORM_FAIL, "receive fail reform partner");
            return ERRNO_DMS_REFORM_FAIL;
        }
    }

    if (ret_flag) {
        return DMS_SUCCESS;
    }

    ret = dms_reform_sync_next_step();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    dms_reform_next_step();
    LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait reformer success");
    return DMS_SUCCESS;
}

static int dms_reform_sync_step_wait(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    if (reform_info->sync_step == reform_info->next_step) {
        dms_reform_next_step();
        LOG_RUN_INF("[DMS REFORM]dms_reform_sync_wait partner success");
    }
    return DMS_SUCCESS;
}

static int dms_reform_sync_wait_partner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    if (!reform_info->sync_send_success) {
        ret = dms_reform_sync_step_send();
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }

    return dms_reform_sync_step_wait();
}

static int dms_reform_sync_wait(void)
{
    int ret = DMS_SUCCESS;

    if (DMS_IS_SHARE_REFORMER) {
        ret = dms_reform_sync_wait_reformer();
    } else {
        ret = dms_reform_sync_wait_partner();
    }

    return ret;
}

static int dms_reform_page_access(void)
{
    LOG_RUN_FUNC_ENTER;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_buf_res.drc_accessible_stage = DRC_ACCESS_STAGE_ALL_ACCESS;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_drc_access(void)
{
    LOG_RUN_FUNC_ENTER;

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_lock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_alock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_buf_res.drc_accessible_stage = PAGE_ACCESS_STAGE_REALESE_ACCESS;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_ddl_2phase_drc_access(void)
{
    LOG_RUN_FUNC_ENTER;

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_lock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_NON_BIZ_SESSION_ACCESS;
    ctx->global_buf_res.drc_accessible_stage = PAGE_ACCESS_STAGE_REALESE_ACCESS;
    ctx->global_alock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_ALL_ACCESS;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_drc_lock_all_access(void)
{
    LOG_RUN_FUNC_ENTER;

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ctx->global_lock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_ALL_ACCESS;
    ctx->global_alock_res.drc_accessible_stage = LOCK_ACCESS_STAGE_ALL_ACCESS;
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_dw_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_dw_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_df_recovery(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_df_recovery_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_space_reload(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_space_reload_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_drc_inaccess(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    share_info_t *share_info = DMS_SHARE_INFO;

    switch (share_info->reform_type) {
        case DMS_REFORM_TYPE_FOR_NEW_JOIN:
            drc_buf_res_set_inaccess(&ctx->global_xa_res);
            if (!share_info->catalog_centralized) {
                drc_buf_res_set_inaccess(&ctx->global_lock_res);
                drc_buf_res_set_inaccess(&ctx->global_alock_res);
                drc_buf_res_set_inaccess(&ctx->global_buf_res);
            }
            break;

        case DMS_REFORM_TYPE_FOR_NORMAL:
        case DMS_REFORM_TYPE_FOR_OLD_REMOVE:
        case DMS_REFORM_TYPE_FOR_SHUTDOWN_CONSISTENCY:
            drc_buf_res_set_inaccess(&ctx->global_xa_res);
            drc_buf_res_set_inaccess(&ctx->global_lock_res);
            drc_buf_res_set_inaccess(&ctx->global_alock_res);
            drc_buf_res_set_inaccess(&ctx->global_buf_res);
            break;

        default:
            drc_buf_res_set_inaccess(&ctx->global_lock_res);
            drc_buf_res_set_inaccess(&ctx->global_alock_res);
            drc_buf_res_set_inaccess(&ctx->global_buf_res);
            break;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();

    return DMS_SUCCESS;
}

static int dms_reform_drc_validate()
{
    LOG_RUN_FUNC_ENTER;
#ifdef OPENGAUSS
    g_dms.callback.drc_validate(g_dms.reform_ctx.handle_proc);
#else
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
    dms_reform_rebuild_buffer_init(CM_INVALID_ID8);
    (void)dms_reform_rebuild_buf_res(reform_ctx->handle_proc, reform_ctx->sess_proc, CM_INVALID_ID8, CM_INVALID_ID8);
    dms_reform_rebuild_buffer_free(reform_ctx->handle_proc, CM_INVALID_ID8);
#endif

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();

    return DMS_SUCCESS;
}

static bool32 dms_reform_check_partner_fail(void)
{
    reformer_ctrl_t *reformer_ctrl = DMS_REFORMER_CTRL;

    if (DMS_IS_SHARE_PARTNER) {
        return CM_FALSE;
    }

    for (uint8 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (reformer_ctrl->instance_fail[i]) {
            return CM_TRUE;
        }
    }

    return CM_FALSE;
}

bool32 dms_reform_version_same(version_info_t *v1, version_info_t *v2)
{
    return (v1->inst_id == v2->inst_id) && (v1->start_time == v2->start_time);
}

static int dms_reform_startup_opengauss(void)
{
    int ret = DMS_SUCCESS;
    LOG_RUN_FUNC_ENTER;

    share_info_t *share_info = DMS_SHARE_INFO;
    uint8 self_id = (uint8)g_dms.inst_id;

    // for failover: startup thread will init in promote pharse
    if (bitmap64_exist(&share_info->bitmap_recovery, self_id)) {
        if (DMS_IS_SHARE_REFORMER && dms_reform_type_is(DMS_REFORM_TYPE_FOR_NORMAL_OPENGAUSS)) {
            LOG_DEBUG_INF("[DMS REFORM] init startup");
            ret = g_dms.callback.opengauss_startup(g_dms.reform_ctx.handle_proc);
        } else if (DMS_IS_SHARE_PARTNER) {
            LOG_DEBUG_INF("[DMS REFORM] init startup");
            ret = g_dms.callback.opengauss_startup(g_dms.reform_ctx.handle_proc);
        }
    }

    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

/*
 * Put X on instance lock to push GCV. Partner needs lock too, to prevent concurrent iusses
 * such as DRC rebuild and invalidate msg happens at the same time. The timed lock
 * waits max_wait_time since we need preserve reform RTO. Usually it latches instantly.
 * SS_DMS_MSG_MAX_WAIT_TIME from DB is < 30s, ticks with uint32 can handle ~40000s, hence no overflow
 * Important: if panicked here, look for dms_process_message stacks in coredump that caused timeout
 */
static int dms_reform_lock_instance(void)
{
    LOG_RUN_FUNC_ENTER;
    uint64 curr_time;
    uint64 begin_time = cm_clock_monotonic_now();
    uint32 ticks = (DMS_REFORM_LOCK_INST_TIMEOUT / MICROSECS_PER_MILLISEC * DMS_TICKS_PER_MILLISEC);
    uint32 sess_pid = g_dms.reform_ctx.sess_proc;

    reform_info_t *reform_info = DMS_REFORM_INFO;
    latch_t *latch = &reform_info->instance_lock;

    LOG_RUN_INF("[DMS REFORM][GCV PUSH]dms_reform_lock_instance, gcv:%d", DMS_GLOBAL_CLUSTER_VER);
    dms_reform_mark_locking(CM_TRUE);

    if (cm_latch_timed_x(latch, sess_pid, ticks, NULL) == CM_FALSE) {
        curr_time = cm_clock_monotonic_now();
        LOG_RUN_ERR("[DMS REFORM][GCV PUSH]lock timeout error, curr holder sid=%hu, moded=%hu, "
            "shared count=%hu, time:%llu, inst:%d exits now", latch->sid, latch->stat,
            latch->shared_count, curr_time - begin_time, g_dms.inst_id);
        cm_exit(0);
    }

    LOG_RUN_INF("[DMS REFORM][GCV PUSH]dms_reform_lock_instance lock success");
    dms_reform_mark_locking(CM_FALSE);

    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_push_gcv_and_unlock(void)
{
    LOG_RUN_FUNC_ENTER;
    reform_info_t *reform_info = DMS_REFORM_INFO;

    /* push reform version here; if wrapped, reset to zero */
    if (DMS_GLOBAL_CLUSTER_VER == CM_INVALID_ID32) {
        g_dms.cluster_ver = 0;
    }
    g_dms.cluster_ver++;

    cm_unlatch(&reform_info->instance_lock, NULL);
    LOG_RUN_INF("[DMS REFORM][GCV PUSH]GCV++:%u, inst_id:%u; lock_instance unlock",
        DMS_GLOBAL_CLUSTER_VER, g_dms.inst_id);

    LOG_RUN_FUNC_SUCCESS;
#ifndef OPENGAUSS
    share_info_t *share_info = DMS_SHARE_INFO;
    if (!REFORM_TYPE_IS_AZ_SWITCHOVER(share_info->reform_type)) {
        g_dms.callback.reform_event_notify(g_dms.reform_ctx.handle_proc, DMS_REFORM_EVENT_AFTER_PUSH_GCV);
    }
#endif
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_reset_user()
{
    LOG_RUN_FUNC_ENTER;
    share_info_t *share_info = DMS_SHARE_INFO;
    g_dms.callback.reset_user(g_dms.reform_ctx.handle_proc, share_info->bitmap_in);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_set_remove_point(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    instance_list_t inst_list;
    int ret = DMS_SUCCESS;

    if (!DMS_IS_SHARE_REFORMER) {
        LOG_RUN_FUNC_SKIP;
        dms_reform_next_step();
        return DMS_SUCCESS;
    }

    LOG_RUN_FUNC_ENTER;
    dms_reform_bitmap_to_list(&inst_list, share_info->bitmap_remove);
    for (uint32 i = 0; i < inst_list.inst_id_count; i++) {
        uint32 inst = (uint32)inst_list.inst_id_list[i];
        ret = g_dms.callback.set_remove_point(g_dms.reform_ctx.handle_proc, inst, &reform_info->curr_points[inst]);
        if (ret != DMS_SUCCESS) {
            LOG_RUN_FUNC_FAIL;
            return ret;
        }
    }
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_ddl_2phase_rcy(void)
{
    share_info_t *share_info = DMS_SHARE_INFO;
    g_dms.callback.ddl_2phase_rcy(g_dms.reform_ctx.handle_normal,
        share_info->inst_bitmap[INST_LIST_OLD_REMOVE] | share_info->inst_bitmap[INST_LIST_OLD_JOIN]);

    dms_reform_next_step();
    return DMS_SUCCESS;
}

static int dms_reform_set_current_point(void)
{
    LOG_RUN_FUNC_ENTER;
    g_dms.callback.set_current_point(g_dms.reform_ctx.handle_proc);
    LOG_RUN_FUNC_SUCCESS;
    dms_reform_next_step();
    return DMS_SUCCESS;
}

dms_reform_proc_t g_dms_reform_procs[DMS_REFORM_STEP_COUNT] = {
    [DMS_REFORM_STEP_DONE] = { "DONE", dms_reform_done, NULL, CM_FALSE },
    [DMS_REFORM_STEP_PREPARE] = { "PREPARE", dms_reform_prepare, NULL, CM_FALSE },
    [DMS_REFORM_STEP_START] = { "START", dms_reform_start, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DISCONNECT] = { "DISCONN", dms_reform_disconnect, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RECONNECT] = { "RECONN", dms_reform_reconnect, dms_reform_reconnect_parallel, CM_FALSE },
    [DMS_REFORM_STEP_FULL_CLEAN] = { "FULL_CLEAN", dms_reform_full_clean, NULL, CM_TRUE },
    [DMS_REFORM_STEP_MIGRATE] = { "MIGRATE", dms_reform_migrate, dms_reform_migrate_parallel, CM_FALSE },
    [DMS_REFORM_STEP_REBUILD] = { "REBUILD", dms_reform_rebuild, dms_reform_rebuild_parallel, CM_FALSE },
    [DMS_REFORM_STEP_REMASTER] = { "REMASTER", dms_reform_remaster, NULL, CM_TRUE },
#ifdef OPENGAUSS
    [DMS_REFORM_STEP_REPAIR] = { "REPAIR", dms_reform_repair, dms_reform_repair_parallel, CM_FALSE },
#else
    [DMS_REFORM_STEP_REPAIR] = { "REPAIR", dms_reform_repair, dms_reform_repair_parallel, CM_TRUE },
#endif
    [DMS_REFORM_STEP_RECOVERY_ANALYSE] = { "RECOVERY_ANALYSE", dms_reform_recovery_analyse, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SWITCH_LOCK] = { "SWITCH_LOCK", dms_reform_switch_lock, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SWITCHOVER_DEMOTE] = { "DEMOTE", dms_reform_switchover_demote, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RECOVERY] = { "RECOVERY", dms_reform_recovery, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RECOVERY_OPENGAUSS] = { "RECOVERY_OPENGAUSS", dms_reform_recovery_opengauss, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DRC_RCY_CLEAN] = { "DRC_RCY_CLEAN", dms_reform_drc_rcy_clean,
        dms_reform_drc_rcy_clean_parallel, CM_TRUE },
    [DMS_REFORM_STEP_CTL_RCY_CLEAN] = { "CTL_RCY_CLEAN", dms_reform_ctl_rcy_clean,
        dms_reform_ctl_rcy_clean_parallel, CM_FALSE },
    [DMS_REFORM_STEP_TXN_DEPOSIT] = { "TXN_DEPOSIT", dms_reform_txn_deposit, NULL, CM_FALSE },
    [DMS_REFORM_STEP_ROLLBACK_PREPARE] = { "ROLLBACK_PREPARE", dms_reform_rollback_prepare, NULL, CM_FALSE },
    [DMS_REFORM_STEP_ROLLBACK_START] = { "ROLLBACK_START", dms_reform_rollback_start, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SUCCESS] = { "SUCCESS", dms_reform_success, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SELF_FAIL] = { "SELF_FAIL", dms_reform_self_fail, NULL, CM_FALSE },
    [DMS_REFORM_STEP_REFORM_FAIL] = { "REFORM_FAIL", dms_reform_fail, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SYNC_WAIT] = { "SYNC_WAIT", dms_reform_sync_wait, NULL, CM_FALSE },
    [DMS_REFORM_STEP_PAGE_ACCESS] = { "PAGE_ACCESS", dms_reform_page_access, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DW_RECOVERY] = { "DW_RECOVERY", dms_reform_dw_recovery, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DF_RECOVERY] = { "DF_RECOVERY", dms_reform_df_recovery, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SPACE_RELOAD] = { "SPACE_RELOAD", dms_reform_space_reload, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DRC_ACCESS] = { "DRC_ACCESS", dms_reform_drc_access, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DRC_INACCESS] = { "DRC_INACCESS", dms_reform_drc_inaccess, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SWITCHOVER_PROMOTE_OPENGAUSS] = { "S_PROMOTE",
        dms_reform_switchover_promote_opengauss, NULL, CM_FALSE },
    [DMS_REFORM_STEP_FAILOVER_PROMOTE_OPENGAUSS] = { "F_PROMOTE",
        dms_reform_failover_promote_opengauss, NULL, CM_FALSE },
    [DMS_REFORM_STEP_STARTUP_OPENGAUSS] = { "STARTUP", dms_reform_startup_opengauss, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DONE_CHECK] = { "DONE_CHECK", dms_reform_done_check, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SET_PHASE] = { "SET_PHASE", dms_reform_set_phase, NULL, CM_FALSE },
    [DMS_REFORM_STEP_WAIT_DB] = { "WAIT_DB", dms_reform_wait_db, NULL, CM_FALSE },
    [DMS_REFORM_STEP_FILE_UNBLOCKED] = { "FILE_UNBLOCKED", dms_reform_file_unblocked, NULL, CM_FALSE },
    [DMS_REFORM_STEP_FILE_BLOCKED] = { "FILE_BLOCKED", dms_reform_file_blocked, NULL, CM_FALSE },
    [DMS_REFORM_STEP_UPDATE_SCN] = { "UPDATE_SCN", dms_reform_update_scn, NULL, CM_FALSE },
    [DMS_REFORM_STEP_WAIT_CKPT] = { "WAIT_CKPT", dms_reform_wait_ckpt, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DRC_VALIDATE] = { "DRC_VALIDATE", dms_reform_drc_validate, NULL, CM_FALSE },
    [DMS_REFORM_STEP_LOCK_INSTANCE] = { "LOCK_INSTANCE", dms_reform_lock_instance, NULL, CM_FALSE },
    [DMS_REFORM_STEP_PUSH_GCV_AND_UNLOCK] = { "PUSH_GCV_AND_UNLOCK", dms_reform_push_gcv_and_unlock, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SET_REMOVE_POINT] = { "SET_REMOVE_POINT", dms_reform_set_remove_point, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RESET_USER] = { "RESET_USER", dms_reform_reset_user, NULL, CM_FALSE },
    [DMS_REFORM_STEP_XA_DRC_ACCESS] = { "XA_DRC_ACCESS", dms_reform_xa_drc_access, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DDL_2PHASE_DRC_ACCESS] = { "DDL_2PHASE_DRC_ACCESS",
        dms_reform_ddl_2phase_drc_access, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DDL_2PHASE_RCY] = { "DDL_2PHASE_RCY", dms_reform_ddl_2phase_rcy, NULL, CM_FALSE },
    [DMS_REFORM_STEP_DRC_LOCK_ALL_ACCESS] = { "DRC_LOCK_ACCESS", dms_reform_drc_lock_all_access, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SET_CURRENT_POINT] = { "SET_CURR_POINT", dms_reform_set_current_point, NULL, CM_FALSE },
    [DMS_REFORM_STEP_STANDBY_UPDATE_REMOVE_NODE_CTRL] = { "UPDATE_REMOVE_NODE_CTRL",
        dms_reform_standby_update_remove_node_ctrl, NULL, CM_FALSE },
    [DMS_REFORM_STEP_STANDBY_STOP_THREAD] = { "STANDBY_STOP_THREAD", dms_reform_standby_stop_thread, NULL, CM_FALSE },
    [DMS_REFORM_STEP_STANDBY_RELOAD_NODE_CTRL] = { "RELOAD_NODE_CTRL", dms_reform_standby_reload_node_ctrl,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_STANDBY_SET_ONLINE_LIST] = { "STANDBY_SET_ONLINE_LIST", dms_reform_standby_set_online_list,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_STOP_SERVER] = { "STOP_SERVER", dms_reform_stop_server, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RESUME_SERVER_FOR_REFORMER] = { "RESUME_SERVER_REFORMER", dms_reform_resume_server_for_reformer,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_RESUME_SERVER_FOR_PARTNER] = { "RESUME_SERVER_PARTNER", dms_reform_resume_server_for_partner,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_START_LRPL] = { "START_LRPL", dms_reform_start_lrpl, NULL, CM_FALSE },
    [DMS_REFORM_STEP_STOP_LRPL] = { "STOP_LRPL", dms_reform_stop_lrpl, NULL, CM_FALSE },
    [DMS_REFORM_STEP_CALIBRATE_LOG_FILE] = { "CALIBRATE_LOG_FILE", dms_reform_calibrate_log_file, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE1] = { "AZ_SWITCH_DEMOTE_PHASE1", dms_reform_az_switch_demote_phase1,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_STOP_CKPT] = { "AZ_SWITCH_DEMOTE_STOP_CKPT",
        dms_reform_az_switch_demote_stop_ckpt, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_UPDATE_NODE_CTRL] = { "AZ_SWITCH_DEMOTE_UPDATE_CTRL",
        dms_reform_reformer_update_node_ctrl, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_CHANGE_ROLE] = { "AZ_SWITCH_DEMOTE_CHANGE_ROLE",
        dms_reform_az_switch_demote_change_role, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_APPROVE] = { "AZ_SWITCH_DEMOTE_APPROVE", dms_reform_az_switch_demote_approve,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_DEMOTE_PHASE2] = { "AZ_SWITCH_DEMOTE_PHASE2", dms_reform_az_switch_demote_phase2,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PREPARE] = { "AZ_SWITCH_PROMOTE_PREPARE",
        dms_reform_az_switchover_promote_prepare, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE1] = { "AZ_SWITCH_PROMOTE_PHASE1", dms_reform_az_switchover_promote_phase1,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_PHASE2] = { "AZ_SWITCH_PROMOTE_PHASE2", dms_reform_az_switchover_promote_phase2,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_PROMOTE_SUCCESS] = { "AZ_PROMOTE_SUCCESS", dms_reform_az_promote_success,
        NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE1] = { "AZ_FAILOVER_PROMOTE_PHASE1",
        dms_reform_az_failover_promote_phase1, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_RESETLOG] = { "AZ_FAILOVER_PROMOTE_RESETLOG",
        dms_reform_az_failover_promote_resetlog, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_FAILOVER_PROMOTE_PHASE2] = { "AZ_FAILOVER_PROMOTE_PHASE2",
        dms_reform_az_failover_promote_phase2, NULL, CM_FALSE },
    [DMS_REFORM_STEP_RELOAD_TXN] = { "RELOAD_TXN", dms_reform_reload_txn, NULL, CM_FALSE },
    [DMS_REFORM_STEP_SYNC_NODE_LFN] = { "SYNC_NODE_LFN", dms_reform_sync_node_lfn, NULL, CM_FALSE },
    [DMS_REFORM_STEP_AZ_SWITCH_PROMOTE_SWITCH_LOG] = { "AZ_SWITCH_PROMOTE_SWITCH_LOG",
        dms_reform_az_switchover_promote_switch_log, NULL, CM_FALSE },
};

static int dms_reform_proc_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    dms_reform_proc_t *reform_proc = &g_dms_reform_procs[reform_info->current_step];
    int ret = DMS_SUCCESS;

    DMS_RFI_BEFORE_STEP(reform_proc);
    if (reform_proc->drc_block) {
        dms_reform_proc_stat_start(DRPS_DRC_BLOCK);
        drc_recycle_buf_res_set_pause();
        drc_enter_buf_res_set_blocked();
        dms_reform_proc_stat_end(DRPS_DRC_BLOCK);
    }

    if (reform_info->parallel_enable && reform_proc->proc_parallel != NULL) {
        ret = reform_proc->proc_parallel();
    } else {
        ret = reform_proc->proc();
    }

    if (reform_proc->drc_block) {
        drc_enter_buf_res_set_unblocked();
        drc_recycle_buf_res_set_running();
    }

    DMS_RFI_AFTER_STEP(reform_proc);
    return ret;
}

static void dms_reform_inner(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    int ret = DMS_SUCCESS;

    reform_info->proc_time = (uint64)g_timer()->now; // record time for check if dms_reform_proc is active
    if (reform_info->current_step >= DMS_REFORM_STEP_COUNT) {
        LOG_RUN_ERR("dms_reform_inner, error step: %d", reform_info->current_step);
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
    }

    ret = dms_reform_proc_inner();

    if (reform_info->reform_done) {
        return;
    }

    if (reform_info->reform_fail) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_REFORM_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }

    if (ret != DMS_SUCCESS) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ret;
        return;
    }

    if (dms_reform_check_partner_fail()) {
        dms_reform_set_next_step((uint8)DMS_REFORM_STEP_SELF_FAIL);
        reform_info->err_code = ERRNO_DMS_REFORM_FAIL;
        return;
    }
}

void dms_reform_proc_thread(thread_t *thread)
{
    dms_set_is_reform_thrd(CM_TRUE);
    cm_set_thread_name(DMS_REFORM_PROC_THRD_NAME);
    reform_info_t *reform_info = DMS_REFORM_INFO;
    reform_context_t *reform_ctx = DMS_REFORM_CONTEXT;
#ifdef OPENGAUSS
    // this thread will invoke startup method in opengauss
    // need_startup flag need set to be true
    g_dms.callback.dms_thread_init(CM_TRUE, (char **)&thread->reg_data);
#endif

    mes_block_sighup_signal();
    dms_reform_proc_stat_bind_proc();
    dms_set_tls_sid(reform_ctx->sess_proc);
    LOG_RUN_INF("[DMS REFORM]dms_reform_proc thread started");
    while (!thread->closed) {
        if (reform_info->thread_status == DMS_THREAD_STATUS_RUNNING) {
            dms_reform_inner();
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_IDLE ||
            reform_info->thread_status == DMS_THREAD_STATUS_PAUSED) {
            cm_sem_wait(&reform_ctx->sem_proc);
            continue;
        }
        if (reform_info->thread_status == DMS_THREAD_STATUS_PAUSING) {
            LOG_RUN_INF("[DMS REFORM]dms_reform_proc paused");
            reform_info->thread_status = DMS_THREAD_STATUS_PAUSED;
            dms_reform_proc_stat_end(reform_info->current_step);
            dms_reform_proc_stat_end(DRPS_REFORM);
            dms_reform_proc_stat_collect_current();
            dms_reform_proc_stat_collect_total();
            dms_reform_proc_stat_log_current();
            continue;
        }
    }
}

char *dms_reform_get_step_desc(uint32 step)
{
    if (step >= DMS_REFORM_STEP_COUNT) {
        return "UNKNOWN STEP";
    } else {
        return g_dms_reform_procs[step].desc;
    }
}

void dms_reform_cache_curr_point(unsigned int node_id, void *curr_point)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;

    if (DMS_IS_SHARE_REFORMER) {
        if (bitmap64_exist(&share_info->bitmap_remove, (uint8)node_id)) {
            log_point_t *point = (log_point_t *)curr_point;
            reform_info->curr_points[node_id] = *point;
        }
    }
}
