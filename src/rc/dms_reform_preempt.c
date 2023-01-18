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
 * dms_reform_preempt.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_preempt.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_preempt.h"
#include "dms_reform.h"
#include "dms_process.h"
#include "dms_errno.h"
#include "cm_timer.h"

// Database has not been created, should not get lock from CMS
static void dms_reformer_preempt_for_build(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    reform_info->reformer_id = DMS_REFORMER_ID_FOR_BUILD;
    if (dms_dst_id_is_self(DMS_REFORMER_ID_FOR_BUILD)) {
        reform_info->dms_role = DMS_ROLE_REFORMER;
    } else {
        reform_info->last_fail = CM_TRUE;
        LOG_RUN_ERR("[DMS REFORM]instance %u start when database has not been built completely", g_dms.inst_id);
    }
}

static void dms_reformer_preempt_for_unshared(void)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;

    reform_info->reformer_id = (uint8)g_dms.inst_id;
    reform_info->dms_role = DMS_ROLE_REFORMER;
}

void dms_reformer_preempt_thread(thread_t *thread)
{
    cm_set_thread_name("reformer_preempt");
    reform_info_t *reform_info = DMS_REFORM_INFO;
    uint8 reform_id = CM_INVALID_ID8;
    date_t time_success = g_timer()->now;
    date_t time_now = 0;
    int ret = DMS_SUCCESS;

#ifdef OPENGAUSS
    g_dms.callback.dms_thread_init(CM_FALSE, (char **)&thread->reg_data);
#endif

    if (!reform_info->build_complete) {
        LOG_RUN_INF("[DMS REFORM]dms_reformer_preempt thread started for build");
        dms_reformer_preempt_for_build();
        return;
    }

    if (reform_info->maintain) {
        LOG_RUN_INF("[DMS REFORM]dms_reformer_preempt thread started for maintain");
        dms_reformer_preempt_for_unshared();
        return;
    }

    LOG_RUN_INF("[DMS REFORM]dms_reformer_preempt thread started");
    while (!thread->closed) {
        DMS_REFORM_LONG_SLEEP;
        ret = dms_reform_cm_res_get_lock_owner(&reform_id);
        if (ret != DMS_SUCCESS) {
            time_now = g_timer()->now;
            if (time_now - time_success > DMS_MAX_FAIL_TIME * MICROSECS_PER_SECOND) {
                LOG_RUN_ERR("[DMS REFORM]fail to get lock owner for %d seconds, exit", DMS_MAX_FAIL_TIME);
                cm_exit(0);
            }
            continue;
        }
        time_success = g_timer()->now;
        if (reform_id == CM_INVALID_ID8) {
            dms_reform_cm_res_lock();
            continue;
        }
        reform_info->reformer_id = reform_id;
        if (dms_dst_id_is_self(reform_id)) {
            if (reform_info->dms_role != DMS_ROLE_REFORMER) {
                LOG_RUN_INF("[DMS REFORM]dms_reformer_preempt set role reformer");
            }
            reform_info->dms_role = DMS_ROLE_REFORMER;
        } else {
            if (reform_info->dms_role != DMS_ROLE_PARTNER) {
                LOG_RUN_INF("[DMS REFORM]dms_reformer_preempt set role partner");
            }
            reform_info->dms_role = DMS_ROLE_PARTNER;
        }
    }
}