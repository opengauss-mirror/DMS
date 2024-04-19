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
 * dms_stat.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_stat.c
 *
 * -------------------------------------------------------------------------
 */

#include <assert.h>
#include "dms_stat.h"
#include "dms_process.h"
#include "dms.h"
#include "mes_func.h"

#ifdef __cplusplus
extern "C" {
#endif

dms_stat_t g_dms_stat;
dms_time_consume_t g_dms_time_consume;

void dms_begin_stat(uint32     sid, dms_wait_event_t event, bool32 immediate)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;
    uint32 curr_level = stat->level++;
    if (stat->level > DMS_STAT_MAX_LEVEL) {
        LOG_RUN_WAR("[DMS][dms_begin_stat]: stat level exceeds the upper limit, sid %u, current level %u",
            sid, curr_level);
        return;
    }

    stat->wait[curr_level].is_waiting = CM_TRUE;
    stat->wait[curr_level].event = event;
    stat->wait[curr_level].usecs = 0;
    stat->wait[curr_level].pre_spin_usecs = cm_total_spin_usecs();
    stat->wait[curr_level].immediate = immediate;
    LOG_DEBUG_INF("[DMS][dms_begin_stat]: stat event %u, immediate %d, sid %u, current level %u",
        event, immediate, sid, curr_level);

    if (!immediate || !g_dms_stat.time_stat_enabled) {
        return;
    }

    (void)cm_gettimeofday(&stat->wait[curr_level].begin_tv);
}

void dms_end_stat(uint32 sid)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;

    if (stat->level == 0) {
        LOG_RUN_ERR("[DMS][dms_end_stat]: stat level is already meet the low limit, sid %u", sid);
        return;
    } else if (stat->level > DMS_STAT_MAX_LEVEL) {
        uint32 curr_level = --stat->level;
        LOG_RUN_WAR("[DMS][dms_end_stat]: stat level exceeds the upper limit, sid %u, current level %u",
            sid, curr_level);
        return;
    }

    dms_end_stat_ex(sid, stat->wait[stat->level - 1].event);
}

void dms_end_stat_ex(uint32 sid, dms_wait_event_t event)
{
    session_stat_t *stat = g_dms_stat.sess_stats + sid;

    uint32 curr_level = --stat->level;
    LOG_DEBUG_INF("[DMS][dms_end_stat_ex]: stat event %u, sid %u, current level %u", event, sid, curr_level);

    timeval_t tv_end;

    if (stat->wait[stat->level].immediate && g_dms_stat.time_stat_enabled) {
        (void)cm_gettimeofday(&tv_end);
        stat->wait[stat->level].usecs = (uint64)TIMEVAL_DIFF_US(&stat->wait[stat->level].begin_tv, &tv_end);
    } else {
        stat->wait[stat->level].usecs = cm_total_spin_usecs() - stat->wait[stat->level].pre_spin_usecs;
    }

    stat->wait_time[event] += stat->wait[stat->level].usecs;
    stat->wait_count[event]++;

    stat->wait[stat->level].is_waiting = CM_FALSE;
}

DMS_DECLARE void dms_get_event(dms_wait_event_t event_type, unsigned long long *event_cnt,
    unsigned long long *event_time)
{
    unsigned long long cnt = 0;
    unsigned long long time = 0;

    SCRLockEvent event = dms_scrlock_events_adapt(event_type);
    if (g_dms.scrlock_ctx.enable && event != CM_INVALID_ID32) {
        dms_scrlock_get_event(event, &cnt, &time);
        if (event_cnt) {
            *event_cnt = cnt;
        }
        if (event_time) {
            *event_time = time;
        }
        return;
    }

    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        cnt += stat->wait_count[event_type];
        time += stat->wait_time[event_type];
    }

    if (event_cnt) {
        *event_cnt = cnt;
    }

    if (event_time) {
        *event_time = time;
    }
}

DMS_DECLARE unsigned long long dms_get_stat(dms_sysstat_t stat_type)
{
    unsigned long long cnt = 0;

    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        cnt += stat->stat[stat_type];
    }

    return cnt;
}

DMS_DECLARE void dms_reset_stat(void)
{
    uint32 j;
    uint32 sess_cnt = g_dms_stat.sess_cnt;
    for (uint32 i = 0; i < sess_cnt; ++i) {
        session_stat_t *stat = g_dms_stat.sess_stats + i;
        for (j = 0; j < (uint32)DMS_STAT_COUNT; j++) {
            stat->stat[j] = 0;
        }

        for (j = 0; j < (uint32)DMS_EVT_COUNT; j++) {
            stat->wait_time[j] = 0;
            stat->wait_count[j] = 0;
        }
    }
}

DMS_DECLARE int dms_get_mes_wait_event(unsigned int cmd, unsigned long long *event_cnt, 
    unsigned long long *event_time) 
{
    if (cmd >= CM_MAX_MES_MSG_CMD) {
        return ERR_MES_CMD_TYPE_ERR;
    }
    mes_get_wait_event(cmd, event_cnt, event_time);
    return DMS_SUCCESS;
}

/* please make sure cmd is in order */
const wait_cmd_desc_t g_wait_cmd_desc[] = {
    /* DMS CMD */
    { MSG_REQ_ASK_MASTER_FOR_PAGE, "req ask master for page", "", "dms" },
    { MSG_REQ_ASK_OWNER_FOR_PAGE, "req ask owner for page", "", "dms" },
    { MSG_REQ_INVALIDATE_SHARE_COPY, "req invalidate share copy", "", "dms" },
    { MSG_REQ_CLAIM_OWNER, "req claim owner", "", "dms" },
    { MSG_REQ_CR_PAGE, "req cr page", "", "dms" },
    { MSG_REQ_ASK_MASTER_FOR_CR_PAGE, "req ask master for cr page", "", "dms" },
    { MSG_REQ_ASK_OWNER_FOR_CR_PAGE, "req ask owner for cr page", "", "dms" },
    { MSG_REQ_CHECK_VISIBLE, "req check visible", "", "dms" },
    { MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID, "req try ask master for page owner id", "", "dms" },
    { MSG_REQ_BROADCAST, "req broadcast", "", "dms" },
    { MSG_REQ_TXN_INFO, "req txn info", "", "dms" },
    { MSG_REQ_TXN_SNAPSHOT, "req txn snapshot", "", "dms" },
    { MSG_REQ_WAIT_TXN, "req wait txn", "", "dms" },
    { MSG_REQ_AWAKE_TXN, "req awake txn", "", "dms" },
    { MSG_REQ_MASTER_CKPT_EDP, "req master ckpt edp", "", "dms" },
    { MSG_REQ_OWNER_CKPT_EDP, "req owner ckpt edp", "", "dms" },
    { MSG_REQ_MASTER_CLEAN_EDP, "req master clean edp", "", "dms" },
    { MSG_REQ_OWNER_CLEAN_EDP, "req owner clean edp", "", "dms" },
    { MES_REQ_MGRT_MASTER_DATA, "req mgrt master data", "", "dms" },
    { MSG_REQ_RELEASE_OWNER, "req release owner", "", "dms" },
    { MSG_REQ_BOC, "req boc", "", "dms" },
    { MSG_REQ_SMON_DLOCK_INFO, "req smon dlock info", "", "dms" },
    { MSG_REQ_SMON_DEADLOCK_SQL, "req smon deadlock sql", "", "dms" },
    { MSG_REQ_SMON_DEADLOCK_ITL, "req smon deadlock itl", "", "dms" },
    { MSG_REQ_SMON_BROADCAST, "req smon broadcast", "", "dms" },
    { MSG_REQ_SMON_TLOCK_BY_TID, "req smon depend table lock by tid", "", "dms" },
    { MSG_REQ_SMON_TLOCK_BY_RM, "req smon depend table lock by rm", "", "dms" },
    { MSG_REQ_PAGE_REBUILD, "req page rebuild", "", "dms" },
    { MSG_REQ_LOCK_REBUILD, "req lock rebuild", "", "dms" },
    { MSG_REQ_OPENGAUSS_TXN_STATUS, "req opengauss txn status", "", "dms" },
    { MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, "req opengauss txn snapshot", "", "dms" },
    { MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, "req opengauss txn update xid", "", "dms" },
    { MSG_REQ_OPENGAUSS_XID_CSN, "req opengauss xid csn", "", "dms" },
    { MSG_REQ_ASK_EDP_REMOTE, "req ask edp remote", "", "dms" },
    { MSG_REQ_SYNC_STEP, "req sync step", "", "dms" },
    { MSG_REQ_SYNC_SHARE_INFO, "req sync share info", "", "dms" },
    { MSG_REQ_DMS_STATUS, "req dms status", "", "dms" },
    { MSG_REQ_REFORM_PREPARE, "req reform prepare", "", "dms" },
    { MSG_REQ_SYNC_NEXT_STEP, "req sync next step", "", "dms" },
    { MSG_REQ_PAGE, "req page", "", "dms" },
    { MSG_REQ_SWITCHOVER, "req switchover", "", "dms" },
    { MSG_REQ_CANCEL_REQUEST_RES, "req cancel request res", "", "dms" },
    { MSG_REQ_OPENGAUSS_DDLLOCK, "req opengauss ddllock", "", "dms" },
    { MSG_REQ_CONFIRM_CVT, "req confirm cvt", "", "dms" },
    { MSG_REQ_CHECK_REFORM_DONE, "req check reform done", "", "dms" },
    { MSG_REQ_MAP_INFO, "req map info", "", "dms" },
    { MSG_REQ_DDL_SYNC, "req ddl sync", "", "dms" },
    { MSG_REQ_REFORM_GCV_SYNC, "req reform gcv sync", "", "dms" },
    { MSG_REQ_PAGE_VALIDATE, "req page validate", "", "dms" },
    { MSG_REQ_INVALID_OWNER, "req invalid owner", "", "dms" },
    { MSG_REQ_ASK_RES_OWNER_ID, "req ask res owner id", "", "dms" },
    { MSG_REQ_OPENGAUSS_ONDEMAND_REDO, "req opengauss ondemand redo", "", "dms" },
    { MSG_REQ_OPENGAUSS_TXN_SWINFO, "req opengauss txn swinfo", "", "dms" },
    { MSG_REQ_OPENGAUSS_PAGE_STATUS, "req opengauss page status", "", "dms" },
    { MSG_REQ_SEND_OPENGAUSS_OLDEST_XMIN, "req send opengauss oldest xmin", "", "dms" },
    { MSG_REQ_NODE_FOR_BUF_INFO, "req node for buf info", "", "dms" },
    { MSG_REQ_PROTOCOL_MAINTAIN_VERSION, "req protocol maintain version", "", "dms" },
    { MSG_REQ_CREATE_GLOBAL_XA_RES, "req create global xa res", "", "dms" },
    { MSG_REQ_DELETE_GLOBAL_XA_RES, "req delete global xa res", "", "dms" },
    { MSG_REQ_ASK_XA_OWNER_ID, "req ask xa owner id", "", "dms" },
    { MSG_REQ_END_XA, "req end xa", "", "dms" },
    { MSG_REQ_ASK_XA_IN_USE, "req ask xa in use", "", "dms" },
    { MSG_REQ_MERGE_XA_OWNERS, "req merge xa owners", "", "dms" },
    { MSG_REQ_XA_REBUILD, "req xa rebuild", "", "dms" },
    { MSG_REQ_XA_OWNERS, "req xa owners", "", "dms" },
    { MSG_REQ_RECYCLE, "req recycle", "", "dms" },
    { MSG_REQ_LOCK_VALIDATE, "req lock validate", "", "dms" },
    { MSG_REQ_LSN_VALIDATE, "req lsn validate", "", "dms" },
    { MSG_REQ_OPENGAUSS_IMMEDIATE_CKPT, "notify primary do ckpt", "", "dms"},
    { MSG_REQ_TLOCK_REBUILD, "req table lock rebuild", "", "dms" },
    { MSG_REQ_TLOCK_VALIDATE, "req table lock validate", "", "dms" },
    { MSG_REQ_AZ_SWITCHOVER_DEMOTE, "req az switchover demote", "", "dms" },
    { MSG_REQ_AZ_SWITCHOVER_PROMOTE, "req az switchover promote", "", "dms" },
    { MSG_REQ_AZ_FAILOVER, "req az failover", "", "dms" },
    { MSG_REQ_ALOCK_REBUILD, "req advisory lock rebuild", "", "dms" },
    { MSG_REQ_ALOCK_VALIDATE, "req advisory lock validate", "", "dms" },
    { MSG_REQ_SMON_ALOCK_BY_DRID, "req smon deadlock advisory lock", "", "dms" },
    { MSG_ACK_CHECK_VISIBLE, "ack check visible", "", "dms" },
    { MSG_ACK_PAGE_OWNER_ID, "ack page owner id", "", "dms" },
    { MSG_ACK_BROADCAST, "ack broadcast", "", "dms" },
    { MSG_ACK_BROADCAST_WITH_MSG, "ack broadcast with msg", "", "dms" },
    { MSG_ACK_PAGE_READY, "ack page ready", "", "dms" },
    { MSG_ACK_GRANT_OWNER, "ack grant owner", "", "dms" },
    { MSG_ACK_ALREADY_OWNER, "ack already owner", "", "dms" },
    { MSG_ACK_CR_PAGE, "ack cr page", "", "dms" },
    { MSG_ACK_TXN_WAIT, "ack txn wait", "", "dms" },
    { MSG_ACK_LOCK, "ack lock", "", "dms" },
    { MSG_ACK_TXN_INFO, "ack txn info", "", "dms" },
    { MSG_ACK_TXN_SNAPSHOT, "ack txn snapshot", "", "dms" },
    { MSG_ACK_WAIT_TXN, "ack wait txn", "", "dms" },
    { MSG_ACK_AWAKE_TXN, "ack awake txn", "", "dms" },
    { MSG_ACK_MASTER_CKPT_EDP, "ack master ckpt edp", "", "dms" },
    { MSG_ACK_OWNER_CKPT_EDP, "ack owner ckpt edp", "", "dms" },
    { MSG_ACK_MASTER_CLEAN_EDP, "ack master clean edp", "", "dms" },
    { MSG_ACK_OWNER_CLEAN_EDP, "ack owner clean edp", "", "dms" },
    { MSG_ACK_ERROR, "ack error", "", "dms" },
    { MSG_ACK_RELEASE_PAGE_OWNER, "ack release page owner", "", "dms" },
    { MSG_ACK_INVLDT_SHARE_COPY, "ack invldt share copy", "", "dms" },
    { MSG_ACK_BOC, "ack boc", "", "dms" },
    { MSG_ACK_SMON_DLOCK_INFO, "ack smon dlock info", "", "dms" },
    { MSG_ACK_SMON_DEADLOCK_SQL, "ack smon deadlock sql", "", "dms" },
    { MSG_ACK_SMON_DEADLOCK_ITL, "ack smon deadlock itl", "", "dms" },
    { MSG_ACK_SMON_BROADCAST, "ack smon broadcast", "", "dms" },
    { MSG_ACK_SMON_TLOCK_BY_TID, "ack smon table lock by tid", "", "dms" },
    { MSG_ACK_SMON_TLOCK_BY_RM, "ack smon table lock by rm", "", "dms" },
    { MSG_ACK_OPENGAUSS_TXN_STATUS, "ack opengauss txn status", "", "dms" },
    { MSG_ACK_OPENGAUSS_TXN_SNAPSHOT, "ack opengauss txn snapshot", "", "dms" },
    { MES_ACK_RELEASE_OWNER_BATCH, "ack release owner batch", "", "dms" },
    { MSG_ACK_OPENGAUSS_TXN_UPDATE_XID, "ack opengauss txn update xid", "", "dms" },
    { MSG_ACK_OPENGAUSS_XID_CSN, "ack opengauss xid csn", "", "dms" },
    { MSG_ACK_OPENGAUSS_LOCK_BUFFER, "ack opengauss lock buffer", "", "dms" },
    { MSG_ACK_EDP_LOCAL, "ack edp local", "", "dms" },
    { MSG_ACK_EDP_READY, "ack edp ready", "", "dms" },
    { MSG_ACK_REFORM_COMMON, "ack reform common", "", "dms" },
    { MSG_ACK_CONFIRM_CVT, "ack confirm cvt", "", "dms" },
    { MSG_ACK_MAP_INFO, "ack map info", "", "dms" },
    { MSG_ACK_REFORM_GCV_SYNC, "ack reform gcv sync", "", "dms" },
    { MSG_ACK_INVLD_OWNER, "ack invld owner", "", "dms" },
    { MSG_ACK_ASK_RES_OWNER_ID, "ack ask res owner id", "", "dms" },
    { MSG_ACK_OPENGAUSS_ONDEMAND_REDO, "ack opengauss ondemand redo", "", "dms" },
    { MSG_ACK_OPENGAUSS_TXN_SWINFO, "ack opengauss txn swinfo", "", "dms" },
    { MSG_ACK_OPENGAUSS_PAGE_STATUS, "ack opengauss page status", "", "dms" },
    { MSG_ACK_SEND_OPENGAUSS_OLDEST_XMIN, "ack send opengauss oldest xmin", "", "dms" },
    { MSG_ACK_PROTOCOL_VERSION_NOT_MATCH, "ack protocol version not match", "", "dms" },
    { MSG_ACK_NODE_FOR_BUF_INFO, "ack node for buf info", "", "dms" },
    { MSG_ACK_CREATE_GLOBAL_XA_RES, "ack create global xa res", "", "dms" },
    { MSG_ACK_DELETE_GLOBAL_XA_RES, "ack delete global xa res", "", "dms" },
    { MSG_ACK_ASK_XA_OWNER_ID, "ack ask xa owner id", "", "dms" },
    { MSG_ACK_END_XA, "ack end xa", "", "dms" },
    { MSG_ACK_XA_IN_USE, "ack xa in use", "", "dms" },
    { MSG_ACK_SMON_ALOCK_BY_DRID, "ack smon deadlock alock by drid", "", "dms" },
    { MSG_ACK_OPENGAUSS_IMMEDIATE_CKPT, "ack immediate ckpt request", "", "dms" },
};

/* g_wait_cmd_desc size */
#define DMS_CMD_DESC_SIZE (sizeof(g_wait_cmd_desc)/sizeof(wait_cmd_desc_t))
static_assert(DMS_CMD_SIZE == DMS_CMD_DESC_SIZE,
    "DMS: cmd enum's size is not equal to desc's!!! Please check msg_command_t and g_wait_cmd_desc!!!");

DMS_DECLARE void dms_get_cmd_stat(int index, wait_cmd_stat_result_t *cmd_stat_result)
{
    /* input cmd is offset */
    if (index >= DMS_CMD_SIZE || index < 0) {
        cmd_stat_result->is_valid = CM_FALSE;
        return;
    }

    errno_t ret;
    ret = strcpy_s(cmd_stat_result->name, DMS_MAX_NAME_LEN, g_wait_cmd_desc[index].name);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][dms_get_cmd_stat:name]:strcpy_s err: %d", ret);
        cmd_stat_result->is_valid = CM_FALSE;
        return;
    }
    ret = strcpy_s(cmd_stat_result->p1, DMS_MAX_NAME_LEN, g_wait_cmd_desc[index].p1);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][dms_get_cmd_stat:p1]:strcpy_s err: %d", ret);
        cmd_stat_result->is_valid = CM_FALSE;
        return;
    }
    ret = strcpy_s(cmd_stat_result->wait_class, DMS_MAX_NAME_LEN, g_wait_cmd_desc[index].wait_class);
    if (ret != EOK) {
        LOG_DEBUG_ERR("[DMS][dms_get_cmd_stat:wait_class]:strcpy_s err: %d", ret);
        cmd_stat_result->is_valid = CM_FALSE;
        return;
    }

    cmd_stat_result->wait_count = (uint64)g_dms_time_consume.count[g_wait_cmd_desc[index].cmd];
    cmd_stat_result->wait_time = g_dms_time_consume.time[g_wait_cmd_desc[index].cmd];
    cmd_stat_result->is_valid = CM_TRUE;
}

#ifdef __cplusplus
}
#endif

