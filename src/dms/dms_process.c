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
 * dms_process.c
 *
 *
 * IDENTIFICATION
 *    src/dms/dms_process.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_process.h"
#include "dms_stat.h"
#include "dcs_dc.h"
#include "dcs_msg.h"
#include "dcs_page.h"
#include "dcs_cr_page.h"
#include "dcs_tran.h"
#include "dls_msg.h"
#include "dms_log.h"
#include "dms_msg.h"
#include "drc_lock.h"
#include "drc_res_mgr.h"
#include "drc_tran.h"
#include "dcs_ckpt.h"
#include "dcs_smon.h"
#include "mes_cb.h"
#include "mes_metadata.h"
#include "mes_func.h"
#include "dms_reform.h"
#include "dms_reform_msg.h"

dms_instance_t g_dms = { 0 };

typedef struct st_processor_func {
    msg_command_t cmd_type;
    dms_message_proc_t proc;
    bool32 is_enqueue_work_thread;      // Whether to let the worker thread process
    bool32 is_enable_before_reform;     // Whether msg enable before first reform finished
    bool32 is_sync_msg;
    const char *func_name;
} processor_func_t;

static processor_func_t g_proc_func_req[(uint16)MSG_REQ_END - (uint16)MSG_REQ_BEGIN] = {
    { MSG_REQ_ASK_MASTER_FOR_PAGE,    dms_proc_ask_master_for_res,      CM_TRUE, CM_TRUE,  CM_TRUE,  "ask master for res" },
    { MSG_REQ_ASK_OWNER_FOR_PAGE,     dms_proc_ask_owner_for_res,       CM_TRUE, CM_TRUE,  CM_TRUE,  "ask owner for res" },
    { MSG_REQ_INVALIDATE_SHARE_COPY,  dms_proc_invld_req,               CM_TRUE, CM_TRUE,  CM_TRUE,  "invalidate req" },
    { MSG_REQ_CLAIM_OWNER,            dms_proc_claim_ownership_req,     CM_TRUE, CM_TRUE,  CM_FALSE, "claim ownership req" },
    { MSG_REQ_CR_PAGE,                dcs_proc_pcr_request,
        CM_TRUE, CM_FALSE, CM_TRUE,  "consistency read page req" },
    { MSG_REQ_ASK_MASTER_FOR_CR_PAGE, dcs_proc_pcr_req_master,          CM_TRUE, CM_FALSE, CM_TRUE,  "ask master for cr page" },
    { MSG_REQ_ASK_OWNER_FOR_CR_PAGE,  dcs_proc_pcr_req_owner,           CM_TRUE, CM_FALSE, CM_TRUE,  "ask owner for cr page" },
    { MSG_REQ_CHECK_VISIBLE,          dcs_proc_check_visible,           CM_TRUE, CM_FALSE, CM_TRUE,  "row check visible" },
    { MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID, dcs_proc_try_ask_master_for_page_owner_id,
        CM_TRUE, CM_FALSE, CM_TRUE, "try ask master for page owner id" },
    { MSG_REQ_BROADCAST,              dcs_proc_broadcast_req,           CM_TRUE, CM_FALSE, CM_TRUE,  "broadcast msg" },
    { MSG_REQ_TXN_INFO,               dcs_proc_txn_info_req,            CM_TRUE, CM_FALSE, CM_TRUE,  "txn info msg" },
    { MSG_REQ_TXN_SNAPSHOT,           dcs_proc_txn_snapshot_req,        CM_TRUE, CM_FALSE, CM_TRUE,  "txn snapshot msg" },
    { MSG_REQ_WAIT_TXN,               dcs_proc_txn_wait_req,            CM_TRUE, CM_FALSE, CM_TRUE,  "txn wait msg" },
    { MSG_REQ_AWAKE_TXN,              dcs_proc_txn_awake_req,           CM_TRUE, CM_FALSE, CM_FALSE, "txn awake msg" },
    { MSG_REQ_MASTER_CKPT_EDP,        dcs_proc_master_ckpt_edp_req,     CM_TRUE, CM_FALSE, CM_FALSE, "master ckpt edp msg" },
    { MSG_REQ_OWNER_CKPT_EDP,         dcs_proc_owner_ckpt_edp_req,      CM_TRUE, CM_FALSE, CM_FALSE, "owner ckpt edp msg" },
    { MSG_REQ_MASTER_CLEAN_EDP,       dcs_proc_master_clean_edp_req,    CM_TRUE, CM_FALSE, CM_FALSE, "master clean edp msg" },
    { MSG_REQ_OWNER_CLEAN_EDP,        dcs_proc_owner_clean_edp_req,
        CM_TRUE, CM_FALSE, CM_FALSE, "owner clean edp msg" },
    { MES_REQ_MGRT_MASTER_DATA,       dms_reform_proc_req_migrate,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "drc process the migrated data" },
    { MSG_REQ_RELEASE_OWNER,          dcs_proc_release_owner_req,       CM_TRUE, CM_TRUE,  CM_TRUE,  "release owner req" },
    { MSG_REQ_BOC,                    dcs_proc_boc,                     CM_TRUE, CM_TRUE,  CM_TRUE,  "commit scn broadcast" },
    { MSG_REQ_SMON_DLOCK_INFO,        dcs_proc_smon_dlock_msg,          CM_TRUE, CM_FALSE, CM_TRUE,  "smon req dead lock msg" },
    { MSG_REQ_SMON_DEADLOCK_SQL,      dcs_proc_smon_deadlock_sql,       CM_TRUE, CM_FALSE, CM_TRUE,  "smon req sql" },
    { MSG_REQ_SMON_DEADLOCK_ITL,      dcs_proc_process_get_itl_lock,    CM_TRUE, CM_FALSE, CM_TRUE,  "smon req itl" },
    { MSG_REQ_SMON_DEADLOCK_CHECK_STATUS, dcs_proc_smon_check_tlock_status,
        CM_TRUE, CM_FALSE, CM_TRUE, "smon req event or table status" },
    { MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_TID, dcs_proc_smon_table_lock_by_tid,
        CM_TRUE, CM_FALSE, CM_TRUE, "smon req tlock msg" },
    { MSG_REQ_SMON_DEADLOCK_TABLE_LOCK_BY_RM, dcs_proc_smon_table_lock_by_rm,
        CM_TRUE, CM_FALSE, CM_TRUE, "smon req rm" },
    { MSG_REQ_BUF_RES_DRC_REBUILD,    dms_reform_proc_req_rebuild_buf_res, CM_TRUE, CM_TRUE,  CM_TRUE,  "buf res drc rebuild" },
    { MSG_REQ_LOCK_RES_DRC_REBUILD,   dms_reform_proc_req_rebuild_lock,    CM_TRUE, CM_TRUE,  CM_TRUE,  "lock res drc rebuild" },
    { MSG_REQ_OPENGAUSS_TXN_STATUS,   dcs_proc_opengauss_txn_status_req,
        CM_TRUE, CM_FALSE, CM_TRUE,  "req opengauss txn status" },
    { MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, dcs_proc_opengauss_txn_snapshot_req,
        CM_TRUE, CM_FALSE, CM_TRUE,  "req opengauss txn snapshot" },
    { MES_REQ_RELEASE_OWNER_BATCH,    dcs_proc_release_owner_batch_req,
        CM_TRUE, CM_FALSE, CM_TRUE,  "release page owner batch req"},
    { MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, dcs_proc_opengauss_update_xid_req,
        CM_TRUE, CM_FALSE, CM_TRUE,  "req opengauss update xid" },
    { MSG_REQ_OPENGAUSS_XID_CSN,      dcs_proc_opengauss_xid_csn_req,      CM_TRUE, CM_FALSE, CM_TRUE,  "req opengauss txn csn" },
    { MSG_REQ_OPENGAUSS_LOCK_BUFFER,  dcs_proc_opengauss_lock_buffer_req,
        CM_TRUE, CM_FALSE, CM_TRUE,  "req opengauss lock buffer" },
    { MSG_REQ_ASK_EDP_REMOTE,         dcs_proc_ask_remote_for_edp,         CM_TRUE, CM_TRUE,  CM_TRUE,  "ask remote for edp" },
    { MSG_REQ_SYNC_STEP,              dms_reform_proc_sync_step,           CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform sync step" },
    { MSG_REQ_SYNC_SHARE_INFO,        dms_reform_proc_sync_share_info,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform sync share info" },
    { MSG_REQ_DMS_STATUS,             dms_reform_proc_req_dms_status,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform get instance status" },
    { MSG_REQ_REFORM_PREPARE,         dms_reform_proc_req_prepare,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform broadcast prepare" },
    { MSG_REQ_SYNC_NEXT_STEP,         dms_reform_proc_sync_next_step,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform sync next step" },
    { MSG_REQ_OWNER_CLEAN_FLAG,       dcs_proc_owner_clean_flag_req,       CM_TRUE, CM_FALSE, CM_FALSE, "req owner clean flag"},
    { MSG_REQ_MSG_SYNC,               dms_reform_proc_msg_sync,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform msg sync and wait" },
    { MSG_REQ_PAGE,                   dms_reform_proc_req_page,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform request page info" },
    { MSG_REQ_SWITCHOVER,             dms_reform_proc_req_switchover,      CM_TRUE, CM_FALSE, CM_TRUE,  "dms switchover" },
    { MSG_REQ_CHANNEL_CHECK,          dms_reform_proc_channel_check,       CM_TRUE, CM_TRUE,  CM_TRUE,  "dms check channel" },
    { MSG_REQ_CANCEL_REQUEST_RES,     dms_proc_cancel_request_res,         CM_TRUE, CM_TRUE,  CM_FALSE, "dms cancel request res" },
    { MSG_REQ_OPENGAUSS_DDLLOCK,      dcs_proc_broadcast_req,              CM_TRUE, CM_TRUE,  CM_TRUE,  "broadcast msg" },
    { MSG_REQ_CONFIRM_CVT,            dms_proc_confirm_cvt_req,            CM_TRUE, CM_FALSE, CM_TRUE,  "dms proc confirm converting" },
    { MSG_REQ_CHECK_REFORM_DONE,      dms_reform_proc_reform_done_req,
        CM_TRUE, CM_TRUE,  CM_TRUE,  "dms reform check reform done"},
};

static processor_func_t g_proc_func_ack[(uint16)MSG_ACK_END - (uint16)MSG_ACK_BEGIN] = {
    { MSG_ACK_CHECK_VISIBLE,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "row check visible ack" },
    { MSG_ACK_PAGE_OWNER_ID,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "page owner id ack" },
    { MSG_ACK_BROADCAST,                    dms_proc_broadcast_ack3, CM_FALSE, CM_TRUE, CM_FALSE, "broadcast ack" },
    { MSG_ACK_BROADCAST_WITH_MSG,           dms_proc_broadcast_ack2, CM_FALSE, CM_TRUE, CM_FALSE, "broadcast ack2" },
    { MSG_ACK_PAGE_READY,                   dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "owner ack page ready" },
    { MSG_ACK_GRANT_OWNER,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "master ack grant owner" },
    { MSG_ACK_ALREADY_OWNER,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "master ack already owner" },
    { MSG_ACK_CR_PAGE,                      dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "consistency read ack" },
    { MSG_ACK_TXN_WAIT,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "TXN wait" },
    { MSG_ACK_LOCK,                         dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "lock ack msg" },
    { MSG_ACK_TXN_INFO,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "txn info ack msg" },
    { MSG_ACK_TXN_SNAPSHOT,                 dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "txn snapshot ack msg" },
    { MSG_ACK_WAIT_TXN,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "txn wait ack msg" },
    { MSG_ACK_AWAKE_TXN,                    dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "txn awake ack msg" },
    { MSG_ACK_MASTER_CKPT_EDP,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "master ckpt edp ack msg" },
    { MSG_ACK_OWNER_CKPT_EDP,               dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "owner ckpt edp ack msg" },
    { MSG_ACK_MASTER_CLEAN_EDP,             dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "master clean edp ack msg" },
    { MSG_ACK_OWNER_CLEAN_EDP,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "owner clean edp ack msg" },
    { MSG_ACK_ERROR,                        dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "error msg" },
    { MSG_ACK_RELEASE_PAGE_OWNER,           dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "release page owner ack" },
    { MSG_ACK_CONFIRM_CVT,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "confirm converting ack" },
    { MSG_ACK_INVLD_OWNER,                  dms_proc_broadcast_ack3, CM_FALSE, CM_TRUE, CM_FALSE, "relase lock owner ack" },
    { MSG_ACK_BOC,                          dms_proc_broadcast_ack,  CM_FALSE, CM_TRUE, CM_FALSE, "commit scn broadcast ack" },
    { MSG_ACK_SMON_DLOCK_INFO,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req dead lock msg" },
    { MSG_ACK_SMON_DEADLOCK_SQL,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req sql" },
    { MSG_ACK_SMON_DEADLOCK_ITL,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req itl" },
    { MSG_ACK_SMON_DEADLOCK_CHECK_STATUS,   dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req event or table status" },
    { MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_MSG, dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req tlock msg" },
    { MSG_ACK_SMON_DEADLOCK_TABLE_LOCK_RM,  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack smon req rm" },
    { MSG_ACK_OPENGAUSS_TXN_STATUS,         dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack opengauss transaction info" },
    { MSG_ACK_OPENGAUSS_TXN_SNAPSHOT,       dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack opengauss transaction snapshot" },
    { MES_ACK_RELEASE_OWNER_BATCH,          dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "release page owner batch ack" },
    { MSG_ACK_OPENGAUSS_TXN_UPDATE_XID,     dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack opengauss update xid" },
    { MSG_ACK_OPENGAUSS_XID_CSN,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack opengauss xid csn" },
    { MSG_ACK_OPENGAUSS_LOCK_BUFFER,        dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack opengauss lock buffer" },
    { MSG_ACK_EDP_LOCAL,                    dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack edp local" },
    { MSG_ACK_EDP_READY,                    dms_proc_msg_ack,        CM_FALSE, CM_TRUE, CM_FALSE, "ack edp remote ready" },
    { MSG_ACK_COMMON,                       dms_proc_msg_ack,
        CM_FALSE, CM_TRUE, CM_FALSE, "ack for request used in dms reform" }
};

static bool32 dms_same_global_lock(char *res_id, const char *res, uint32 len)
{
    drc_buf_res_t *buf_res = (drc_buf_res_t *)res_id;
    dms_drid_t *lockid1 = (dms_drid_t*)buf_res->data;
    dms_drid_t *lockid2 = (dms_drid_t *)res;

    if (lockid1->key1 == lockid2->key1 && lockid1->key2 == lockid2->key2) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static bool32 dms_same_local_lock(char *res_id, const char *res, uint32 len)
{
    drc_local_lock_res_t *local_lock = (drc_local_lock_res_t *)res_id;
    dms_drid_t *lock_id = (dms_drid_t *)res;

    if (local_lock->resid.key1 == lock_id->key1 && local_lock->resid.key2 == lock_id->key2) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static bool32 dms_same_txn(char *res, const char *res_id, uint32 len)
{
    drc_txn_res_t *txn_res = (drc_txn_res_t *)res;
    uint64 xid = *(uint64 *)res_id;

    if (txn_res->res_id == xid) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

static void dms_process_message(uint32 work_idx, mes_message_t *msg)
{
    if (work_idx >= g_dms.proc_ctx_cnt) {
        cm_panic(0);
    }

    mes_message_head_t* head = msg->head;
    if ((head->cmd >= MSG_REQ_END && head->cmd < MSG_ACK_BEGIN) || head->cmd >= MSG_ACK_END) {
        DMS_THROW_ERROR(ERRNO_DMS_CMD_INVALID, head->cmd);
        mfc_release_message_buf(msg);
        return;
    }

    dms_processor_t *processor = &g_dms.processors[head->cmd];
    mfc_add_tickets(&g_dms.mfc.recv_tickets[head->src_inst], 1);

#ifdef OPENGAUSS
    bool32 enable_proc = !g_dms.enable_reform || DMS_FIRST_REFORM_FINISH || processor->is_enable_before_reform;
#else
    bool32 enable_proc = DMS_FIRST_REFORM_FINISH || processor->is_enable_before_reform;
#endif
    if (!enable_proc) {
        LOG_DEBUG_INF("[DMS] msg was discarded，cmd:%u, src_inst:%u, dst_inst:%u, src_sid:%u, dest_sid:%u",
            (uint32)head->cmd, (uint32)head->src_inst, (uint32)head->dst_inst, (uint32)head->src_sid,
            (uint32)head->dst_sid);
        mfc_release_message_buf(msg);
        return;
    }
    dms_process_context_t *ctx = &g_dms.proc_ctx[work_idx];
    processor->proc(ctx, msg);

    /*
     * Now DMS use memory manager functions provided by DB,
     * mes message callback functions may allocate and free memory,
     * so we need to reset memory context to free the allocated space,
     * to avoid memory expansion.
     */
    if (g_dms.callback.mem_reset != NULL) {
        g_dms.callback.mem_reset(ctx->db_handle);
    }
}

// add function
static int dms_register_proc_func(processor_func_t *proc_func)
{
    if ((proc_func->cmd_type >= MSG_REQ_END && proc_func->cmd_type < MSG_ACK_BEGIN) ||
        proc_func->cmd_type >= MSG_ACK_END || proc_func->cmd_type >= CM_MAX_MES_MSG_CMD) {
        DMS_THROW_ERROR(ERRNO_DMS_CMD_INVALID, proc_func->cmd_type);
        return ERRNO_DMS_CMD_INVALID;
    }
    g_dms.processors[proc_func->cmd_type].proc = proc_func->proc;
    g_dms.processors[proc_func->cmd_type].is_sync_msg = proc_func->is_sync_msg;
    g_dms.processors[proc_func->cmd_type].is_enqueue  = proc_func->is_enqueue_work_thread;
    g_dms.processors[proc_func->cmd_type].is_enable_before_reform = proc_func->is_enable_before_reform;

    int ret = strcpy_s(g_dms.processors[proc_func->cmd_type].name, CM_MAX_NAME_LEN, proc_func->func_name);
    DMS_SECUREC_CHECK(ret);

    return DMS_SUCCESS;
}

static int dms_register_proc(void)
{
    int ret;
    // register req
    for (uint32 i = MSG_REQ_BEGIN; i < MSG_REQ_END; i++) {
        ret = dms_register_proc_func(&g_proc_func_req[i - MSG_REQ_BEGIN]);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
        mfc_set_msg_enqueue(i, g_dms.processors[i].is_enqueue);
    }

    // register ack
    for (uint32 i = MSG_ACK_BEGIN; i < MSG_ACK_END; i++) {
        ret = dms_register_proc_func(&g_proc_func_ack[i - MSG_ACK_BEGIN]);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
        mfc_set_msg_enqueue(i, g_dms.processors[i].is_enqueue);
    }

    mfc_register_proc_func(dms_process_message);
    return DMS_SUCCESS;
}

static int dms_init_proc_ctx(dms_profile_t *dms_profile)
{
    uint32 total_ctx_cnt = dms_profile->work_thread_cnt + dms_profile->channel_cnt;
    if (total_ctx_cnt == 0) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, total_ctx_cnt);
        return ERRNO_DMS_PARAM_INVALID;
    }

    dms_process_context_t *proc_ctx = (dms_process_context_t *)malloc(sizeof(dms_process_context_t) * total_ctx_cnt);
    if (proc_ctx == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    for (uint32 loop = 0; loop < total_ctx_cnt; loop++) {
        proc_ctx[loop].inst_id = (uint8)dms_profile->inst_id;
        proc_ctx[loop].db_handle = g_dms.callback.get_db_handle(&proc_ctx[loop].sess_id);
    }

    g_dms.proc_ctx_cnt = total_ctx_cnt;
    g_dms.proc_ctx = proc_ctx;
    return DMS_SUCCESS;
}

void dms_set_mes_buffer_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    uint32 pool_idx = 0;

    profile->buffer_pool_attr.pool_count = DMS_BUFFER_POOL_NUM;
    profile->buffer_pool_attr.queue_count = DMS_MSG_BUFFER_QUEUE_NUM;

    // 64 buffer pool
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DMS_FIRST_BUFFER_RATIO) / DMS_FIRST_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DMS_FIRST_BUFFER_LENGTH;

    // 128 buffer pool
    pool_idx++;
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DMS_SECOND_BUFFER_RATIO) / DMS_SECOND_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DMS_SECOND_BUFFER_LENGTH;

    // 32k buffer pool
    pool_idx++;
    profile->buffer_pool_attr.buf_attr[pool_idx].count =
        (uint32)(recv_msg_buf_size * DMS_THIRDLY_BUFFER_RATIO) / DMS_THIRD_BUFFER_LENGTH;
    profile->buffer_pool_attr.buf_attr[pool_idx].size = DMS_THIRD_BUFFER_LENGTH;
}

#define DMS_WORK_THREAD_TASK_GROUP1     2
#define DMS_WORK_THREAD_TASK_GROUP2     1
#define DMS_WORK_THREAD_TASK_GROUP3     0

static mes_task_group_id_t dms_msg_group_id(uint8 cmd)
{
    switch (cmd) {
        case MSG_REQ_SYNC_SHARE_INFO:
        case MSG_REQ_SYNC_STEP:
        case MSG_REQ_DMS_STATUS:
        case MSG_REQ_REFORM_PREPARE:
        case MSG_REQ_SYNC_NEXT_STEP:
        case MES_REQ_MGRT_MASTER_DATA:
        case MSG_REQ_BUF_RES_DRC_REBUILD:
        case MSG_REQ_LOCK_RES_DRC_REBUILD:
        case MSG_REQ_PAGE:
        case MSG_REQ_SWITCHOVER:
        case MSG_REQ_CHANNEL_CHECK:
            return MES_TASK_GROUP_ONE;      // group one is used for reform
        case MSG_REQ_OPENGAUSS_DDLLOCK:
            return MES_TASK_GROUP_TWO;
        default:
            return MES_TASK_GROUP_ZERO;
    }
}

/*
    Work thread allocation
    group 1: total_work_thread   2
    group 2: total_work_thread   0
    group 3: total_work_thread   0
    group 0: total_work_thread - group 1 - group 2 - group 3
    Allocation principle: Allocate time-consuming requests to different groups.
*/
void dms_set_command_group(void)
{
    uint8 group_id = 0;

    for (uint8 i = 0; i < MSG_CMD_CEIL; i++) {
        group_id = dms_msg_group_id(i);
        mfc_set_command_task_group(i, group_id);
    }
}

void dms_set_group_task_num(dms_profile_t *dms_profile, mes_profile_t *mes_profile)
{
    uint32 work_thread = DMS_WORK_THREAD_TASK_GROUP1 + DMS_WORK_THREAD_TASK_GROUP2 + DMS_WORK_THREAD_TASK_GROUP3;

    mes_profile->task_group[MES_TASK_GROUP_ZERO] = dms_profile->work_thread_cnt - work_thread;
    mes_profile->task_group[MES_TASK_GROUP_ONE] = DMS_WORK_THREAD_TASK_GROUP1;
    mes_profile->task_group[MES_TASK_GROUP_TWO] = DMS_WORK_THREAD_TASK_GROUP2;
    mes_profile->task_group[MES_TASK_GROUP_THREE] = DMS_WORK_THREAD_TASK_GROUP3;

    dms_set_command_group();
}

int dms_init_mes(dms_profile_t *dms_profile)
{
    int ret;
    mes_profile_t mes_profile;
    mes_profile.inst_id = dms_profile->inst_id;
    mes_profile.inst_cnt = dms_profile->inst_cnt;
    if (dms_profile->pipe_type == DMS_CONN_MODE_TCP) {
        mes_profile.pipe_type = CS_TYPE_TCP;
    } else if (dms_profile->pipe_type == DMS_CONN_MODE_RDMA) {
        mes_profile.pipe_type = CS_TYPE_RDMA;
    } else {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, dms_profile->pipe_type);
        return ERRNO_DMS_PARAM_INVALID;
    }

    mes_profile.conn_created_during_init = dms_profile->conn_created_during_init;
    mes_profile.channel_cnt = dms_profile->channel_cnt;
    mes_profile.work_thread_cnt = dms_profile->work_thread_cnt;
    mes_profile.mes_elapsed_switch = dms_profile->elapsed_switch;
    mes_profile.rdma_rpc_use_busypoll = dms_profile->rdma_rpc_use_busypoll;
    mes_profile.rdma_rpc_is_bind_core = dms_profile->rdma_rpc_is_bind_core;
    mes_profile.rdma_rpc_bind_core_start = dms_profile->rdma_rpc_bind_core_start;
    mes_profile.rdma_rpc_bind_core_end = dms_profile->rdma_rpc_bind_core_end;
    ret = memcpy_s(mes_profile.inst_net_addr, sizeof(mes_addr_t) * CM_MAX_INSTANCES, dms_profile->inst_net_addr,
        sizeof(mes_addr_t) * CM_MAX_INSTANCES);
    DMS_SECUREC_CHECK(ret);
    ret = memcpy_s(mes_profile.ock_log_path, MES_MAX_LOG_PATH, dms_profile->ock_log_path, DMS_OCK_LOG_PATH_LEN);
    DMS_SECUREC_CHECK(ret);

    dms_set_mes_buffer_pool(dms_profile->recv_msg_buf_size, &mes_profile);
    dms_set_group_task_num(dms_profile, &mes_profile);

    ret = mfc_init(&mes_profile);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }
    return ret;
}

static status_t dms_global_res_init(drc_global_res_map_t *global_res, int32 res_type, uint32 pool_size,
    uint32 item_size, res_cmp_callback res_cmp_func, res_hash_callback get_hash_func)
{
    uint32 i;

    for (i = 0; i < DRC_MAX_PART_NUM; i++) {
        cm_bilist_init(&global_res->res_parts[i]);
    }

    return drc_res_map_init(&global_res->res_map, res_type, pool_size, item_size, res_cmp_func, get_hash_func);
}

static inline int32 init_common_res_ctx(const dms_profile_t *dms_profile)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 item_num = CM_MAX_SESSIONS * dms_profile->inst_cnt * 2;
    int32 ret = drc_res_pool_init(&ctx->lock_item_pool, sizeof(drc_lock_item_t), item_num);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]lock item pool init fail,return error:%d", ret);
    }

    return ret;
}

static inline int32 init_page_res_ctx(const dms_profile_t *dms_profile)
{
    int ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 res_num = (uint32)MAX(dms_profile->data_buffer_size / dms_profile->page_size, SIZE_M(2));
    ret = dms_global_res_init(&ctx->global_buf_res, DMS_RES_TYPE_IS_PAGE, res_num, sizeof(drc_buf_res_t), dms_same_page,
        dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global page resource pool init fail,return error:%d", ret);
    }
    return ret;
}

static int32 init_lock_res_ctx(dms_profile_t *dms_profile)
{
    int ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ret = dms_global_res_init(&ctx->global_lock_res, DMS_RES_TYPE_IS_LOCK, DRC_DEFAULT_LOCK_RES_NUM,
        sizeof(drc_buf_res_t), dms_same_global_lock, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global lock resource pool init fail,return error:%d", ret);
        return ret;
    }

    ret = drc_res_map_init(&ctx->local_lock_res, DMS_RES_TYPE_IS_LOCK, DRC_DEFAULT_LOCK_RES_NUM,
        sizeof(drc_local_lock_res_t), dms_same_local_lock, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]local lock resource pool init fail,return error:%d", ret);
        return ret;
    }

    return DMS_SUCCESS;
}

static int32 init_txn_res_ctx(const dms_profile_t *dms_profile)
{
    int32 ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 item_num = CM_MAX_SESSIONS * dms_profile->inst_cnt;
    ret = drc_res_map_init(&ctx->local_txn_map, DMS_RES_TYPE_IS_LOCAL_TXN, item_num,
        sizeof(drc_txn_res_t), dms_same_txn, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]local txn resource pool init fail,return error:%d", ret);
        return ret;
    }

    ret = drc_res_map_init(&ctx->txn_res_map, DMS_RES_TYPE_IS_TXN, item_num,
        sizeof(drc_txn_res_t), dms_same_txn, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]txn resource pool init fail,return error:%d", ret);
        return ret;
    }

    return DMS_SUCCESS;
}

static inline void init_reform_res_ctx(dms_profile_t *dms_profile)
{
    drc_init_deposit_map();
}

static int32 init_drc_smon_ctx(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    ctx->chan = cm_chan_new(DRC_SMON_QUEUE_SIZE, sizeof(void*));
    if (ctx->chan == NULL) {
        LOG_RUN_ERR("[DRC]fail to create smon queue,size=%d", DRC_SMON_QUEUE_SIZE);
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    int32 ret = cm_create_thread(dms_smon_entry, 0, NULL, &ctx->smon_thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DRC]fail to create smon thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    ctx->smon_handle = g_dms.callback.get_db_handle(&ctx->smon_sid);
    if (ctx->smon_handle == NULL) {
        LOG_RUN_ERR("[DRC]fail to get db session");
        DMS_THROW_ERROR(ERRNO_DMS_CALLBACK_GET_DB_HANDLE);
        return ERRNO_DMS_CALLBACK_GET_DB_HANDLE;
    }
    return DMS_SUCCESS;
}

int dms_init_drc_res_ctx(dms_profile_t *dms_profile)
{
    int ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ret = memset_s(ctx, sizeof(drc_res_ctx_t), 0, sizeof(drc_res_ctx_t));
    DMS_SECUREC_CHECK(ret);

    do {
        if ((ret = init_common_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_page_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_lock_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_txn_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        init_reform_res_ctx(dms_profile);

        if ((ret = init_drc_smon_ctx()) != DMS_SUCCESS) {
            break;
        }
    } while (0);

    if (ret != DMS_SUCCESS) {
        drc_destroy();
    }

    return ret;
}

static void dms_init_log(dms_profile_t *dms_profile)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t)dms_profile->callback.log_output;
    cm_log_param_instance()->log_level = MAX_LOG_LEVEL;
}

static int dms_init_stat(dms_profile_t *dms_profile)
{
    g_dms_stat.time_stat_enabled = dms_profile->time_stat_enabled;
    g_dms_stat.sess_cnt = dms_profile->work_thread_cnt + dms_profile->channel_cnt + dms_profile->max_session_cnt;

    size_t size = g_dms_stat.sess_cnt * sizeof(session_stat_t);
    g_dms_stat.sess_stats = (session_stat_t *)malloc(size);

    if (g_dms_stat.sess_stats == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    int ret = memset_s(g_dms_stat.sess_stats, size, 0, size);
    DMS_SECUREC_CHECK(ret);

    return DMS_SUCCESS;
}

static void dms_set_global_dms(dms_profile_t *dms_profile)
{
    g_dms.callback = dms_profile->callback;
    g_dms.page_size = dms_profile->page_size;
    g_dms.inst_id = dms_profile->inst_id;
    g_dms.inst_cnt = dms_profile->inst_cnt;
    g_dms.inst_map = dms_profile->inst_map;
    g_dms.enable_reform = dms_profile->enable_reform;
}

static void dms_init_mfc(dms_profile_t *dms_profile)
{
    g_dms.mfc.profile_tickets = dms_profile->mfc_tickets;
    g_dms.mfc.max_wait_ticket_time = dms_profile->mfc_max_wait_ticket_time;

    for (uint32 i = 0; i < CM_MAX_INSTANCES; ++i) {
        g_dms.mfc.remain_tickets[i].count = g_dms.mfc.profile_tickets;
        GS_INIT_SPIN_LOCK(g_dms.mfc.remain_tickets[i].lock);

        g_dms.mfc.recv_tickets[i].count = 0;
        GS_INIT_SPIN_LOCK(g_dms.mfc.recv_tickets[i].lock);
    }
}

static int32 dms_init_cntlr(void)
{
    size_t mem_size = CM_MAX_MES_ROOMS * sizeof(dms_cntlr_t);
    for (uint32 i = 0; i < g_dms.inst_cnt; i++) {
        g_dms.cntlr[i] = (dms_cntlr_t *)malloc(mem_size);
        if (g_dms.cntlr[i] == NULL) {
            LOG_RUN_ERR("[DMS] alloc proc ctrl failed");
            return ERRNO_DMS_ALLOC_FAILED;
        }
        DMS_SECUREC_CHECK(memset_s(g_dms.cntlr[i], mem_size, 0, mem_size));
    }
    return DMS_SUCCESS;
}

static inline void dms_release_inst_resource(void)
{
    if (g_dms.proc_ctx != NULL) {
        CM_FREE_PTR(g_dms.proc_ctx);
    }

    for (uint32 i = 0; i < g_dms.inst_cnt; i++) {
        if (g_dms.cntlr[i] != NULL) {
            CM_FREE_PTR(g_dms.cntlr[i]);
        }
    }
}

int dms_init(dms_profile_t *dms_profile)
{
    int ret;

    ret = cm_start_timer(g_timer());
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dms_init_error_desc();
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    if (dms_profile == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return ERRNO_DMS_PARAM_NULL;
    }
    dms_init_log(dms_profile);

    ret = memset_s(&g_dms, sizeof(dms_instance_t), 0, sizeof(dms_instance_t));
    DMS_SECUREC_CHECK(ret);

    dms_set_global_dms(dms_profile);

    ret = dms_init_stat(dms_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dms_register_proc();
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dms_init_proc_ctx(dms_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dms_init_drc_res_ctx(dms_profile);
    if (ret != DMS_SUCCESS) {
        dms_release_inst_resource();
        return ret;
    }

    ret = dms_init_cntlr();
    if (ret != DMS_SUCCESS) {
        dms_release_inst_resource();
        return ret;
    }

    ret = dms_init_mes(dms_profile);
    if (ret != DMS_SUCCESS) {
        drc_destroy();
        dms_release_inst_resource();
        return ret;
    }

    dms_init_mfc(dms_profile);

    ret = dms_reform_init(dms_profile);
    if (ret != DMS_SUCCESS) {
        drc_destroy();
        dms_release_inst_resource();
        return ret;
    }

#ifndef WIN32
    char dms_version[DMS_VERSION_MAX_LEN];
    dms_show_version(dms_version);
    LOG_RUN_INF("[DMS]%s", dms_version);
#endif
    return DMS_SUCCESS;
}

void dms_uninit(void)
{
    dms_reform_uninit();
    mfc_uninit();

    if (g_dms_stat.sess_stats != NULL) {
        free(g_dms_stat.sess_stats);
        g_dms_stat.sess_stats = NULL;
    }
    dms_uninit_error_desc();
    drc_destroy();
    cm_res_mgr_uninit(&g_dms.cm_res_mgr);
    cm_close_timer(g_timer());
    dms_release_inst_resource();
}

unsigned long long dms_get_min_scn(unsigned long long min_scn)
{
    uint32 i;
    uint64 *dms_min_scn = g_dms.min_scn;
    for (i = 0; i < g_dms.inst_cnt; i++) {
        if (i == g_dms.inst_id) {
            continue;
        }

        if (dms_min_scn[i] != 0 && dms_min_scn[i] < min_scn) {
            min_scn = dms_min_scn[i];
        }
    }

    return min_scn;
}

void dms_set_min_scn(unsigned char inst_id, unsigned long long min_scn)
{
    (void)cm_atomic_set((atomic_t *)&(g_dms.min_scn[inst_id]), (int64)min_scn);
}

int dms_register_thread_init(dms_thread_init_t thrd_init)
{
    return set_mes_worker_init_cb(thrd_init);
}

int dms_register_ssl_decrypt_pwd(dms_decrypt_pwd_t cb_func)
{
    int ret;
    ret = mfc_register_decrypt_pwd(cb_func);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }
    return DMS_SUCCESS;
}

int dms_set_ssl_param(const char* param_name, const char* param_value)
{
    cbb_param_t param_type;
    param_value_t out_value;
    int ret;
    if (param_name == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return ERRNO_DMS_PARAM_NULL;
    }

    LOG_RUN_INF("dms begin set ssl param, param_name = %s", param_name);

    ret = mes_chk_md_param(param_name, param_value, &param_type, &out_value);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    ret = mes_set_md_param(param_type, &out_value);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }
    return DMS_SUCCESS;
}

int dms_get_ssl_param(const char *param_name, char *param_value, unsigned int size)
{
    int ret;
    if (param_name == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return ERRNO_DMS_PARAM_NULL;
    }
    ret = mes_get_md_param_by_name(param_name, param_value, size);
    if (ret != CM_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }
    return DMS_SUCCESS;
}

