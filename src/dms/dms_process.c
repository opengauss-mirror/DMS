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
#include "dms_error.h"
#include "dms_msg.h"
#include "dms_msg_command.h"
#include "dms_msg_protocol.h"
#include "drc_lock.h"
#include "drc_res_mgr.h"
#include "drc_tran.h"
#include "dcs_ckpt.h"
#include "dcs_smon.h"
#include "mes_metadata.h"
#include "mes_interface.h"
#include "cm_timer.h"
#include "dms_reform.h"
#include "dms_reform_msg.h"
#include "scrlock_adapter.h"
#include "cm_log.h"
#include "dms_reform_xa.h"
#include "fault_injection.h"
#include "dms_reform_proc_stat.h"
#include "dms_reform_alock.h"
#include "dms_dynamic_trace.h"

#ifndef WIN32
#include <sys/prctl.h>
#endif

#define DEBUG_LOG_LEVEL 0x0000007F
#define SESSION_MULTIPLES 2

dms_instance_t g_dms = { 0 };
mes_thread_set_t g_mes_thread_set = { 0 };

typedef struct st_processor_func {
    msg_command_t cmd_type;
    dms_message_proc_t proc;
    bool32 is_enqueue_work_thread;      // Whether to let the worker thread process
    bool32 is_enable_before_reform;     // Whether msg enable before first reform finished
    const char *func_name;
} processor_func_t;

static processor_func_t g_proc_func_req[(uint32)MSG_REQ_END - (uint32)MSG_REQ_BEGIN] = {
    { MSG_REQ_ASK_MASTER_FOR_PAGE,    dms_proc_ask_master_for_res,      CM_TRUE, CM_TRUE,  "ask master for res" },
    { MSG_REQ_ASK_OWNER_FOR_PAGE,     dms_proc_ask_owner_for_res,       CM_TRUE, CM_TRUE,  "ask owner for res" },
    { MSG_REQ_INVALIDATE_SHARE_COPY,  dms_proc_invld_req,               CM_TRUE, CM_TRUE,  "invalidate req" },
    { MSG_REQ_CLAIM_OWNER,            dms_proc_claim_ownership_req,     CM_TRUE, CM_TRUE,  "claim owner req" },
    { MSG_REQ_CR_PAGE,                dcs_proc_pcr_request,             CM_TRUE, CM_FALSE, "consistency read page req" },
    { MSG_REQ_ASK_MASTER_FOR_CR_PAGE, dcs_proc_pcr_req_master,          CM_TRUE, CM_FALSE, "ask master for cr page" },
    { MSG_REQ_ASK_OWNER_FOR_CR_PAGE,  dcs_proc_pcr_req_owner,           CM_TRUE, CM_FALSE, "ask owner for cr page" },
    { MSG_REQ_CHECK_VISIBLE,          dcs_proc_check_visible,           CM_TRUE, CM_FALSE, "row check visible" },
    { MSG_REQ_TRY_ASK_MASTER_FOR_PAGE_OWNER_ID, dcs_proc_try_ask_master_for_page_owner_id,
        CM_TRUE, CM_FALSE, "try ask master for page owner id" },
    { MSG_REQ_BROADCAST,              dcs_proc_broadcast_req,           CM_TRUE, CM_TRUE,  "broadcast msg" },
    { MSG_REQ_TXN_INFO,               dcs_proc_txn_info_req,            CM_TRUE, CM_FALSE,  "txn info msg" },
    { MSG_REQ_TXN_SNAPSHOT,           dcs_proc_txn_snapshot_req,        CM_TRUE, CM_FALSE,  "txn snapshot msg" },
    { MSG_REQ_WAIT_TXN,               dcs_proc_txn_wait_req,            CM_TRUE, CM_FALSE,  "txn wait msg" },
    { MSG_REQ_AWAKE_TXN,              dcs_proc_txn_awake_req,           CM_TRUE, CM_FALSE,  "txn awake msg" },
    { MSG_REQ_MASTER_CKPT_EDP,        dcs_proc_master_ckpt_edp_req,     CM_TRUE, CM_FALSE,  "master ckpt edp msg" },
    { MSG_REQ_OWNER_CKPT_EDP,         dcs_proc_owner_ckpt_edp_req,      CM_TRUE, CM_FALSE,  "owner ckpt edp msg" },
    { MSG_REQ_MASTER_CLEAN_EDP,       dcs_proc_master_clean_edp_req,    CM_TRUE, CM_FALSE,  "master clean edp msg" },
    { MSG_REQ_OWNER_CLEAN_EDP,        dcs_proc_owner_clean_edp_req,     CM_TRUE, CM_FALSE,  "owner clean edp msg" },
    { MES_REQ_MGRT_MASTER_DATA,       dms_reform_proc_req_migrate,      CM_TRUE, CM_TRUE,   "drc process the migrated data" },
    { MSG_REQ_RELEASE_OWNER,          dcs_proc_release_owner_req,       CM_TRUE, CM_TRUE,   "release owner req" },
    { MSG_REQ_BOC,                    dcs_proc_boc,                     CM_TRUE, CM_TRUE,   "commit scn broadcast" },
    { MSG_REQ_SMON_DLOCK_INFO,        dcs_proc_smon_dlock_msg,          CM_TRUE, CM_FALSE,  "smon req dead lock msg" },
    { MSG_REQ_SMON_DEADLOCK_SQL,      dcs_proc_smon_deadlock_sql,       CM_TRUE, CM_FALSE,  "smon req sql" },
    { MSG_REQ_SMON_DEADLOCK_ITL,      dcs_proc_process_get_itl_lock,    CM_TRUE, CM_FALSE,  "smon req itl" },
    { MSG_REQ_SMON_BROADCAST,         dcs_proc_smon_broadcast_req,      CM_TRUE, CM_FALSE,  "smon broadcast msg" },
    { MSG_REQ_SMON_TLOCK_BY_TID,      dcs_proc_smon_tlock_by_tid,       CM_TRUE, CM_FALSE,  "smon req tlock by tid" },
    { MSG_REQ_SMON_TLOCK_BY_RM,       dcs_proc_smon_tlock_by_rm,        CM_TRUE, CM_FALSE,  "smon req tlock by rm" },
    { MSG_REQ_SMON_ALOCK_BY_DRID,     dcs_proc_smon_alock_by_drid,      CM_TRUE, CM_FALSE,  "smon req alock msg" },
    { MSG_REQ_PAGE_REBUILD,           dms_reform_proc_req_page_rebuild, CM_TRUE, CM_TRUE,  "page rebuild" },
    { MSG_REQ_LOCK_REBUILD,           dms_reform_proc_req_lock_rebuild, CM_TRUE, CM_TRUE,  "lock rebuild" },
    { MSG_REQ_TLOCK_REBUILD,          dms_reform_proc_req_tlock_rebuild, CM_TRUE, CM_TRUE, "table lock rebuild" },
    { MSG_REQ_ALOCK_REBUILD,          dms_reform_proc_req_alock_rebuild, CM_TRUE, CM_TRUE,  "alock rebuild" },
    { MSG_REQ_OPENGAUSS_TXN_STATUS,   dcs_proc_opengauss_txn_status_req,   CM_TRUE, CM_FALSE, "req opengauss txn status" },
    { MSG_REQ_OPENGAUSS_TXN_SNAPSHOT, dcs_proc_opengauss_txn_snapshot_req,
        CM_TRUE, CM_FALSE,  "req opengauss txn snapshot" },
    { MSG_REQ_OPENGAUSS_TXN_UPDATE_XID, dcs_proc_opengauss_update_xid_req,
        CM_TRUE, CM_FALSE,  "req opengauss update xid" },
    { MSG_REQ_OPENGAUSS_XID_CSN,      dcs_proc_opengauss_xid_csn_req,  CM_TRUE, CM_FALSE, "req opengauss txn csn" },
    { MSG_REQ_SYNC_STEP,              dms_reform_proc_sync_step,       CM_TRUE, CM_TRUE,  "dms reform sync step" },
    { MSG_REQ_SYNC_SHARE_INFO,        dms_reform_proc_sync_share_info, CM_TRUE, CM_TRUE,  "dms reform sync share info" },
    { MSG_REQ_DMS_STATUS,             dms_reform_proc_req_dms_status,  CM_TRUE, CM_TRUE,  "dms reform get instance status" },
    { MSG_REQ_REFORM_PREPARE,         dms_reform_proc_req_prepare,     CM_TRUE, CM_TRUE,  "dms reform broadcast prepare" },
    { MSG_REQ_SYNC_NEXT_STEP,         dms_reform_proc_sync_next_step,  CM_TRUE, CM_TRUE,  "dms reform sync next step" },
    { MSG_REQ_PAGE,                   dms_reform_proc_req_page,        CM_TRUE, CM_TRUE,  "dms reform request page info" },
    { MSG_REQ_SWITCHOVER,             dms_reform_proc_req_switchover,  CM_TRUE, CM_FALSE, "dms switchover" },
    { MSG_REQ_CANCEL_REQUEST_RES,     dms_proc_cancel_request_res,     CM_TRUE, CM_TRUE,  "dms cancel request res" },
    { MSG_REQ_OPENGAUSS_DDLLOCK,      dcs_proc_broadcast_req,          CM_TRUE, CM_TRUE,  "broadcast msg" },
    { MSG_REQ_CONFIRM_CVT,            dms_proc_confirm_cvt_req,        CM_TRUE, CM_FALSE, "dms proc confirm converting" },
    { MSG_REQ_CHECK_REFORM_DONE,      dms_reform_proc_reform_done_req, CM_TRUE, CM_TRUE,  "dms reform check reform done"},
    { MSG_REQ_MAP_INFO,               dms_reform_proc_map_info_req,    CM_TRUE, CM_TRUE,  "dms ask map from IN instance"},
    { MSG_REQ_DDL_SYNC,               dcs_proc_broadcast_req,          CM_TRUE, CM_TRUE,  "broadcast msg" },
    { MSG_REQ_REFORM_GCV_SYNC,        dms_reform_proc_req_gcv_sync,    CM_TRUE, CM_TRUE,  "ask partner to sync gcv" },
    { MSG_REQ_INVALID_OWNER,          dms_proc_invld_req,              CM_TRUE, CM_TRUE,  "invalid owner" },
    { MSG_REQ_ASK_RES_OWNER_ID,       dms_proc_ask_res_owner_id,       CM_TRUE, CM_TRUE,  "ask res owner id" },
    { MSG_REQ_OPENGAUSS_ONDEMAND_REDO, dms_reform_proc_opengauss_ondemand_redo_buffer,
        CM_TRUE, CM_FALSE, "dms notify primary node ondemand-redo buffer"},
    { MSG_REQ_OPENGAUSS_TXN_SWINFO, dcs_proc_opengauss_txn_of_master_req,
        CM_TRUE, CM_FALSE,  "req opengauss txn sw info for write redirect" },
    { MSG_REQ_OPENGAUSS_PAGE_STATUS, dcs_proc_opengauss_page_status_req,
        CM_TRUE, CM_FALSE,  "req opengauss page hit buffer" },
    { MSG_REQ_SEND_OPENGAUSS_OLDEST_XMIN, dcs_proc_send_opengauss_oldest_xmin,
        CM_TRUE, CM_TRUE, "send primary openGauss self oldest xmin"},
    { MSG_REQ_NODE_FOR_BUF_INFO,      dms_proc_ask_node_buf_info,      CM_TRUE, CM_FALSE, "ask node for buffer related info"},
    { MSG_REQ_PROTOCOL_MAINTAIN_VERSION, dms_protocol_proc_maintain_version,
        CM_TRUE, CM_TRUE, "req maintain protocol version"},
    { MSG_REQ_CREATE_GLOBAL_XA_RES,   dms_proc_create_xa_res,          CM_TRUE, CM_TRUE,  "create xa res remote" },
    { MSG_REQ_DELETE_GLOBAL_XA_RES,   dms_proc_delete_xa_res,          CM_TRUE, CM_TRUE,  "delete xa res remote" },
    { MSG_REQ_ASK_XA_OWNER_ID,        dms_proc_ask_xa_owner,           CM_TRUE, CM_TRUE,  "ask xa res owner id" },
    { MSG_REQ_END_XA,                 dms_proc_end_xa,                 CM_TRUE, CM_TRUE,  "request to end the xa" },
    { MSG_REQ_ASK_XA_IN_USE,          dms_proc_ask_xa_inuse,           CM_TRUE, CM_TRUE,  "ask xa in use or not" },
    { MSG_REQ_XA_REBUILD,             dms_reform_proc_xa_rebuild,      CM_TRUE, CM_TRUE,  "xa res rebuild" },
    { MSG_REQ_RECYCLE,                drc_proc_buf_ctrl_recycle,       CM_TRUE, CM_TRUE,  "req buf ctrl recycle" },
    { MSG_REQ_OPENGAUSS_IMMEDIATE_CKPT, dms_proc_opengauss_immediate_ckpt,
        CM_TRUE, CM_FALSE, "dms notify primary node do ckpt immediately" },
    { MSG_REQ_AZ_SWITCHOVER_DEMOTE, dms_reform_proc_req_az_switchover, CM_TRUE, CM_FALSE,  "dms az switchover demote" },
    { MSG_REQ_AZ_SWITCHOVER_PROMOTE, dms_reform_proc_req_az_switchover, CM_TRUE, CM_FALSE,  "dms az switchover promote" },
    { MSG_REQ_AZ_FAILOVER, dms_reform_proc_req_az_failover, CM_TRUE, CM_FALSE,  "dms az failover" },
    { MSG_REQ_CHECK_OWNERSHIP, dms_proc_check_page_ownership, CM_TRUE, CM_FALSE,  "check page ownership" },
    { MSG_REQ_REPAIR_NEW, dms_reform_proc_repair, CM_TRUE, CM_TRUE, "repair new" },
    { MSG_REQ_DRC_MIGRATE,            dms_proc_drc_migrate,               CM_TRUE, CM_FALSE, "drc migrate" },
    { MSG_REQ_DRC_RELEASE,            dms_proc_drc_release,               CM_TRUE, CM_FALSE, "drc release" },
    { MSG_REQ_DRM,                    dms_proc_drm,                       CM_TRUE, CM_FALSE, "drm" },
    { MSG_REQ_DRM_FINISH,             dms_proc_drm_finish,                CM_TRUE, CM_FALSE, "drm finish" },
};

static processor_func_t g_proc_func_ack[(uint32)MSG_ACK_END - (uint32)MSG_ACK_BEGIN] = {
    { MSG_ACK_CHECK_VISIBLE,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "row check visible ack" },
    { MSG_ACK_PAGE_OWNER_ID,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "page owner id ack" },
    { MSG_ACK_BROADCAST,                    dms_proc_broadcast_ack2, CM_FALSE, CM_TRUE, "broadcast ack" },
    { MSG_ACK_BROADCAST_WITH_MSG,           dms_proc_broadcast_ack2, CM_FALSE, CM_TRUE, "broadcast ack2" },
    { MSG_ACK_PAGE_READY,                   dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "owner ack page ready" },
    { MSG_ACK_GRANT_OWNER,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "master ack grant owner" },
    { MSG_ACK_ALREADY_OWNER,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "master ack already owner" },
    { MSG_ACK_CR_PAGE,                      dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "consistency read ack" },
    { MSG_ACK_TXN_WAIT,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "TXN wait" },
    { MSG_ACK_LOCK,                         dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "lock ack msg" },
    { MSG_ACK_TXN_INFO,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "txn info ack msg" },
    { MSG_ACK_TXN_SNAPSHOT,                 dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "txn snapshot ack msg" },
    { MSG_ACK_WAIT_TXN,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "txn wait ack msg" },
    { MSG_ACK_AWAKE_TXN,                    dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "txn awake ack msg" },
    { MSG_ACK_MASTER_CKPT_EDP,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "master ckpt edp ack msg" },
    { MSG_ACK_OWNER_CKPT_EDP,               dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "owner ckpt edp ack msg" },
    { MSG_ACK_MASTER_CLEAN_EDP,             dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "master clean edp ack msg" },
    { MSG_ACK_OWNER_CLEAN_EDP,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "owner clean edp ack msg" },
    { MSG_ACK_ERROR,                        dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "remote ack error" },
    { MSG_ACK_RELEASE_PAGE_OWNER,           dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "release page owner ack" },
    { MSG_ACK_CONFIRM_CVT,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "confirm converting ack" },
    { MSG_ACK_INVLDT_SHARE_COPY,            dms_proc_broadcast_ack2, CM_FALSE, CM_TRUE, "relase lock owner ack" },
    { MSG_ACK_BOC,                          dms_proc_broadcast_ack2,  CM_FALSE, CM_TRUE, "commit scn broadcast ack" },
    { MSG_ACK_SMON_DLOCK_INFO,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack smon req dead lock msg" },
    { MSG_ACK_SMON_DEADLOCK_SQL,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack smon req sql" },
    { MSG_ACK_SMON_DEADLOCK_ITL,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack smon req itl" },
    { MSG_ACK_SMON_BROADCAST,               dms_proc_broadcast_ack2, CM_FALSE, CM_TRUE, "smon broadcast ack" },
    { MSG_ACK_SMON_TLOCK_BY_TID,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack smon req tlock by tid" },
    { MSG_ACK_SMON_TLOCK_BY_RM,             dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack smon req tlock by rm" },
    { MSG_ACK_OPENGAUSS_TXN_STATUS,         dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss transaction info" },
    { MSG_ACK_OPENGAUSS_TXN_SNAPSHOT,       dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss transaction snapshot" },
    { MES_ACK_RELEASE_OWNER_BATCH,          dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "release page owner batch ack" },
    { MSG_ACK_OPENGAUSS_TXN_UPDATE_XID,     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss update xid" },
    { MSG_ACK_OPENGAUSS_XID_CSN,            dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss xid csn" },
    { MSG_ACK_OPENGAUSS_LOCK_BUFFER,        dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss lock buffer" },
    { MSG_ACK_REFORM_COMMON,                dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack for reform requests only" },
    { MSG_ACK_MAP_INFO,                     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack instance for map info" },
    { MSG_ACK_REFORM_GCV_SYNC,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack instance for gcv sync" },
    { MSG_ACK_INVLD_OWNER,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack for invalid owner" },
    { MSG_ACK_ASK_RES_OWNER_ID,             dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack for res owner id" },
    { MSG_ACK_OPENGAUSS_ONDEMAND_REDO,      dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack on-demand redo request"},
    { MSG_ACK_OPENGAUSS_TXN_SWINFO,         dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss transaction swinfo" },
    { MSG_ACK_OPENGAUSS_PAGE_STATUS,        dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack opengauss page hit buffer" },
    { MSG_ACK_SEND_OPENGAUSS_OLDEST_XMIN,   dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack oldest xmin received"},
    { MSG_ACK_PROTOCOL_VERSION_NOT_MATCH,   dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack msg version is not match"},
    { MSG_ACK_NODE_FOR_BUF_INFO,            dms_proc_broadcast_ack2,
            CM_FALSE, CM_TRUE, "ack request for buffer information" },
    { MSG_ACK_CREATE_GLOBAL_XA_RES,         dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack create xa res remote" },
    { MSG_ACK_DELETE_GLOBAL_XA_RES,         dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack delete xa res remote" },
    { MSG_ACK_ASK_XA_OWNER_ID,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack ask xa res owner id" },
    { MSG_ACK_END_XA,                       dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack end xa transactions" },
    { MSG_ACK_XA_IN_USE,                    dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack ask xa in use or not" },
    { MSG_ACK_OPENGAUSS_IMMEDIATE_CKPT,     dms_proc_msg_ack,        CM_FALSE, CM_TRUE, "ack immediate ckpt request" },
    { MSG_ACK_SMON_ALOCK_BY_DRID,           dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack smon deadlock alock drid" },
    { MSG_ACK_CHECK_OWNERSHIP,              dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack check page ownership" },
    { MSG_ACK_DRC_MIGRATE,                  dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack drc migrate" },
    { MSG_ACK_DRM_FINISH,                   dms_proc_msg_ack,        CM_FALSE, CM_TRUE,  "ack drm finish" },
};

static bool32 dms_cmd_is_reform(uint32 cmd)
{
    switch (cmd) {
        case MES_REQ_MGRT_MASTER_DATA:
        case MSG_REQ_PAGE_REBUILD:
        case MSG_REQ_LOCK_REBUILD:
        case MSG_REQ_SYNC_STEP:
        case MSG_REQ_SYNC_SHARE_INFO:
        case MSG_REQ_SYNC_NEXT_STEP:
        case MSG_REQ_PAGE:
        case MSG_REQ_SWITCHOVER:
        case MSG_REQ_CHECK_REFORM_DONE:
        case MSG_REQ_MAP_INFO:
        case MSG_REQ_REFORM_GCV_SYNC:
        case MSG_REQ_OPENGAUSS_ONDEMAND_REDO:
        case MSG_REQ_XA_REBUILD:
            return CM_TRUE;
        default:
            return CM_FALSE;
    }
}

static bool32 dms_same_global_lock(char *res_id, const char *res, uint32 len)
{
    drc_lock_t *drc_lock = (drc_lock_t *)res_id;
    dms_drid_t *lockid1 = &drc_lock->lockid;
    dms_drid_t *lockid2 = (dms_drid_t *)res;
    return lockid1->key1 == lockid2->key1 && lockid1->key2 == lockid2->key2 && lockid1->key3 == lockid2->key3;
}

static bool32 dms_same_local_lock(char *res_id, const char *res, uint32 len)
{
    drc_local_lock_res_t *local_lock = (drc_local_lock_res_t *)res_id;
    dms_drid_t *lock_id = (dms_drid_t *)res;

    if (local_lock->resid.key1 == lock_id->key1 && local_lock->resid.key2 == lock_id->key2 &&
        local_lock->resid.key3 == lock_id->key3) {
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

static bool32 dms_same_global_xid(char *res, const char *res_id, uint32 len)
{
    drc_xa_t *drc_xa = (drc_xa_t *)res;
    drc_global_xid_t *global_xid1 = &drc_xa->xid;
    drc_global_xid_t *global_xid2 = (drc_global_xid_t *)res_id;
    if (global_xid1->fmt_id != global_xid2->fmt_id) {
        return CM_FALSE;
    }

    if (global_xid1->gtrid_len != global_xid2->gtrid_len || global_xid1->bqual_len != global_xid2->bqual_len) {
        return CM_FALSE;
    }

    text_t text1, text2;
    text1.str = global_xid1->gtrid;
    text1.len = global_xid1->gtrid_len;
    text2.str = global_xid2->gtrid;
    text2.len = global_xid2->gtrid_len;
    if (!cm_text_equal_ins(&text1, &text2)) {
        return CM_FALSE;
    }

    text1.str = global_xid1->bqual;
    text1.len = global_xid1->bqual_len;
    text2.str = global_xid2->bqual;
    text2.len = global_xid2->bqual_len;
    if (!cm_text_equal_ins(&text1, &text2)) {
        return CM_FALSE;
    }

    return CM_TRUE;
}

/* Reform-related messages are exempt from GCV check or instance lock. */
static bool32 dms_msg_skip_gcv_check(unsigned int cmd)
{
    switch (cmd) {
        case MSG_REQ_REFORM_GCV_SYNC:
        case MSG_ACK_REFORM_GCV_SYNC:
        case MSG_REQ_REFORM_PREPARE:
        case MSG_REQ_SYNC_STEP:
        case MSG_REQ_SYNC_NEXT_STEP:
        case MSG_REQ_SYNC_SHARE_INFO:
        case MSG_REQ_DMS_STATUS:
        case MSG_REQ_MAP_INFO:
        case MSG_ACK_MAP_INFO:
        case MSG_ACK_REFORM_COMMON:
        case MES_REQ_MGRT_MASTER_DATA:
        case MSG_REQ_PAGE_REBUILD:
        case MSG_REQ_LOCK_REBUILD:
        case MSG_REQ_SWITCHOVER:
        case MSG_REQ_CHECK_REFORM_DONE:
        case MSG_REQ_TXN_INFO:
        case MSG_REQ_TXN_SNAPSHOT:
        case MSG_REQ_WAIT_TXN:
        case MSG_REQ_AWAKE_TXN:
        case MSG_REQ_BOC:
        case MSG_REQ_DDL_SYNC:
        case MSG_REQ_CR_PAGE:
        case MSG_REQ_CHECK_VISIBLE:
        case MSG_REQ_ASK_OWNER_FOR_CR_PAGE:
        case MSG_REQ_ASK_MASTER_FOR_CR_PAGE:
        case MSG_REQ_BROADCAST:
            return CM_TRUE;
        default:
            break;
    }
    return CM_FALSE;
}

static void dms_lock_instance_s(unsigned char cmd, uint16 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (!dms_msg_skip_gcv_check(cmd)) {
        cm_latch_s(&reform_info->instance_lock, 0, CM_FALSE, NULL);
        LOG_DEBUG_INF("locked instance lock S, sid=%u", sess_id);
    }
}

static void dms_unlock_instance_s(unsigned char cmd, uint16 sess_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    if (!dms_msg_skip_gcv_check(cmd)) {
        cm_unlatch(&reform_info->instance_lock, NULL);
        LOG_DEBUG_INF("unlocked instance lock S, sid=%u", sess_id);
    }
}

void *dms_malloc(memory_context_t *context, size_t size)
{
    size_t alloc_size = size + sizeof(dms_buffer_header_t);
    char *buffer = NULL;
    dms_malloc_fun_type_t type;
    if (context == NULL) {
        if (g_dms.callback.dms_malloc_prot == NULL) {
            buffer = (char *)malloc(alloc_size);
            type = MALLOC_TYPE_OS;
        } else {
            buffer = (char *)g_dms.callback.dms_malloc_prot(alloc_size);
            type = MALLOC_TYPE_REGIST;
        }
    } else {
        buffer = (char *)ddes_alloc(context, alloc_size);
        type = MALLOC_TYPE_CONTEXT;
    }
    if (buffer == NULL) {
        return NULL;
    }
    dms_buffer_header_t *head = (dms_buffer_header_t *)(buffer);
    head->type = type;
    return (void *)((char *)buffer + sizeof(dms_buffer_header_t));
}

void dms_free(void *ptr)
{
    dms_buffer_header_t *head = (dms_buffer_header_t *)((char *)(ptr) - sizeof(dms_buffer_header_t));
    switch (head->type) {
        case MALLOC_TYPE_OS:
            CM_FREE_PTR(head);
            break;
        case MALLOC_TYPE_REGIST:
            g_dms.callback.dms_free_prot(head);
            break;
        case MALLOC_TYPE_CONTEXT:
            ddes_free(head);
            break;
        default:
            CM_ASSERT(CM_FALSE);
            return;
    }
}

void dms_protocol_send_ack_version_not_match(dms_process_context_t *ctx, dms_message_t *receive_msg, bool8 support_cmd)
{
    dms_protocol_result_ack_t ack_msg;
    dms_message_head_t *recv_head = get_dms_head(receive_msg);
    uint32 send_proto_ver = dms_get_send_proto_version_by_cmd(MSG_ACK_PROTOCOL_VERSION_NOT_MATCH,
        receive_msg->head->src_inst);
    dms_init_ack_head(recv_head, &ack_msg.head, MSG_ACK_PROTOCOL_VERSION_NOT_MATCH,
        sizeof(dms_protocol_result_ack_t), (uint16)ctx->sess_id);
    ack_msg.head.msg_proto_ver = send_proto_ver;

    if (support_cmd) {
        ack_msg.result = DMS_PROTOCOL_VERSION_NOT_MATCH;
    } else {
        ack_msg.result = DMS_PROTOCOL_VERSION_NOT_SUPPORT;
    }

    int32 ret = mfc_send_data(&ack_msg.head);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DMS PROTOCOL] send ack version not match failed, src_inst:%u, src_sid:%u, dst_inst:%u, "
            "dst_sid:%u, result:%d, msg_proto_ver:%u, recv msg:{cmd:%d, msg_proto_ver:%u, send_inst sw_proto_ver:%u}, "
            "my sw_proto_ver:%u",
            ack_msg.head.src_inst, ack_msg.head.src_sid, ack_msg.head.dst_inst, ack_msg.head.dst_sid, ack_msg.result,
            ack_msg.head.msg_proto_ver, recv_head->cmd, recv_head->msg_proto_ver, recv_head->sw_proto_ver,
            DMS_SW_PROTO_VER);
        return;
    }
    LOG_RUN_INF("[DMS PROTOCOL] send ack version not match success, src_inst:%u, src_sid:%u, dst_inst:%u, "
        "dst_sid:%u, result:%d, msg_proto_ver:%u, recv msg:{cmd:%d, msg_proto_ver:%u, send_inst sw_proto_ver:%u}, "
        "my sw_proto_ver:%u",
        ack_msg.head.src_inst, ack_msg.head.src_sid, ack_msg.head.dst_inst, ack_msg.head.dst_sid, ack_msg.result,
        ack_msg.head.msg_proto_ver, recv_head->cmd, recv_head->msg_proto_ver, recv_head->sw_proto_ver,
        DMS_SW_PROTO_VER);
    return;
}

void dms_cast_mes_msg(mes_msg_t *mes_msg, dms_message_t *dms_msg)
{
    dms_msg->head = (dms_message_head_t *)mes_msg->buffer;
    dms_msg->buffer = mes_msg->buffer;
}

static void dms_process_message(uint32 work_idx, uint64 ruid, mes_msg_t *mes_msg)
{
    if (work_idx >= g_dms.proc_ctx_cnt) {
        cm_panic(0);
    }

    dms_message_t dms_msg;
    dms_cast_mes_msg(mes_msg, &dms_msg);
    dms_reform_proc_stat_bind_mes_task(work_idx);
    dms_process_context_t *ctx = &g_dms.proc_ctx[work_idx];
    dms_message_head_t* head = get_dms_head(&dms_msg);

    bool32 init_finish = g_dms.dms_init_finish;
    if (!init_finish) {
        LOG_DEBUG_INF("[DMS] discard msg with cmd:%u, src_inst:%u, dst_inst:%u, "
            "src_sid:%u, dest_sid:%u, finish dms init:%u", 
            (uint32)head->cmd, (uint32)head->src_inst, (uint32)head->dst_inst,
            (uint32)head->src_sid, (uint32)head->dst_sid, (uint32)g_dms.dms_init_finish);
        return;
    }

    if (SECUREC_UNLIKELY(ctx->db_handle == NULL)) {
        ctx->db_handle = g_dms.callback.get_db_handle(&ctx->sess_id, DMS_SESSION_TYPE_WORKER);
        if (ctx->db_handle == NULL) {
            return;
        }
    }
    
    /* ruid should have been brought in dms msghead */
    CM_ASSERT(ruid == 0 || head->ruid == ruid);

    dms_set_node_proto_version(head->src_inst, head->sw_proto_ver);
    if ((head->cmd >= MSG_REQ_END && head->cmd < MSG_ACK_BEGIN) || head->cmd >= MSG_ACK_END) {
        dms_protocol_send_ack_version_not_match(ctx, &dms_msg, CM_FALSE);
        return;
    }

    mes_msg_info_t msg_data = {head->cmd, head->src_sid};
    mes_set_cur_msg_info(work_idx, &msg_data, sizeof(mes_msg_info_t));
    dms_processor_t *processor = &g_dms.processors[head->cmd];
    if (processor->is_enqueue) {
        bool8 pass_check = dms_check_message_proto_version(head);
        if (!pass_check) {
            if (dms_cmd_need_ack(head->cmd)) {
                dms_protocol_send_ack_version_not_match(ctx, &dms_msg, CM_TRUE);
            }
            return;
        }
    }

#ifdef OPENGAUSS
    bool32 enable_proc = DMS_FIRST_REFORM_FINISH || processor->is_enable_before_reform;
#else
    bool32 enable_proc = CM_TRUE;
#endif

    dms_lock_instance_s(head->cmd, ctx->sess_id);
    bool32 gcv_approved = head->cluster_ver == DMS_GLOBAL_CLUSTER_VER || \
        dms_msg_skip_gcv_check(head->cmd);
    if (!enable_proc || !gcv_approved) {
        LOG_DEBUG_INF("[DMS] discard msg with cmd:%u, src_inst:%u, dst_inst:%u, local_gcv=%u, recv_gcv=%u, "
            "src_sid:%u, dest_sid:%u, finish dms init:%u", 
            (uint32)head->cmd, (uint32)head->src_inst, (uint32)head->dst_inst,
            DMS_GLOBAL_CLUSTER_VER, head->cluster_ver, (uint32)head->src_sid,
            (uint32)head->dst_sid, (uint32)g_dms.dms_init_finish);
        dms_unlock_instance_s(head->cmd, ctx->sess_id);
        return;
    }

    if (dms_cmd_is_reform(head->cmd)) {
        dms_dyn_trc_begin(ctx->sess_id, DMS_EVT_PROC_REFORM_REQ);
    } else {
        /* temp ban DMS_EVT_PROC_GENERIC_REQ event trace for better performance */
    }

#ifdef OPENGAUSS  
    (void)g_dms.callback.cache_msg(ctx->db_handle, (char*)mes_msg->buffer);
#endif
    if (processor->is_enqueue) {
        processor->proc(ctx, &dms_msg);
    }
#ifdef OPENGAUSS  
    (void)g_dms.callback.db_check_lock(ctx->db_handle);
#endif   

    /*
     * Now DMS use memory manager functions provided by DB,
     * mes message callback functions may allocate and free memory,
     * so we need to reset memory context to free the allocated space,
     * to avoid memory expansion.
     */
    if (g_dms.callback.mem_reset != NULL) {
        g_dms.callback.mem_reset(ctx->db_handle);
    }

    if (dms_cmd_is_reform(head->cmd)) {
        dms_dyn_trc_end(ctx->sess_id);
    }

    dms_unlock_instance_s(head->cmd, ctx->sess_id);
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
    g_dms.processors[proc_func->cmd_type].is_enqueue  = proc_func->is_enqueue_work_thread;
    g_dms.processors[proc_func->cmd_type].is_enable_before_reform = proc_func->is_enable_before_reform;

    int ret = strcpy_s(g_dms.processors[proc_func->cmd_type].name, CM_MAX_NAME_LEN, proc_func->func_name);
    DMS_SECUREC_CHECK(ret);

    return DMS_SUCCESS;
}

static int dms_register_proc(void)
{
    int ret;
    LOG_RUN_INF("[DMS] dms_register_proc start");
    // register req
    for (uint32 i = MSG_REQ_BEGIN; i < MSG_REQ_END; i++) {
        ret = dms_register_proc_func(&g_proc_func_req[i - MSG_REQ_BEGIN]);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    // register ack
    for (uint32 i = MSG_ACK_BEGIN; i < MSG_ACK_END; i++) {
        ret = dms_register_proc_func(&g_proc_func_ack[i - MSG_ACK_BEGIN]);
        if (ret != DMS_SUCCESS) {
            return ret;
        }
    }

    mfc_register_proc_func(dms_process_message);
    LOG_RUN_INF("[DMS] dms_register_proc end");
    return DMS_SUCCESS;
}

static int dms_init_proc_ctx(dms_profile_t *dms_profile)
{
    LOG_RUN_INF("[DMS] dms_init_proc_ctx start");
    uint32 total_ctx_cnt = DMS_WORK_THREAD_COUNT + dms_profile->channel_cnt;
    if (total_ctx_cnt == 0) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "total_ctx_cnt");
        return ERRNO_DMS_PARAM_INVALID;
    }

    dms_process_context_t *proc_ctx =
        (dms_process_context_t *)dms_malloc(NULL, sizeof(dms_process_context_t) * total_ctx_cnt);
    if (proc_ctx == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    for (uint32 loop = 0; loop < total_ctx_cnt; loop++) {
        proc_ctx[loop].inst_id   = (uint8)dms_profile->inst_id;
        proc_ctx[loop].sess_id   = CM_INVALID_ID32;
        proc_ctx[loop].db_handle = NULL;
    }

    g_dms.proc_ctx_cnt = total_ctx_cnt;
    g_dms.proc_ctx = proc_ctx;
    LOG_RUN_INF("[DMS] dms_init_proc_ctx end");
    return DMS_SUCCESS;
}

static void dms_deinit_proc_ctx(void)
{
    if (g_dms.proc_ctx == NULL) {
        return;
    }

    for (uint32 loop = 0; loop < g_dms.proc_ctx_cnt; loop++) {
        DMS_RELEASE_DB_HANDLE(g_dms.proc_ctx[loop].db_handle);
    }

    DMS_FREE_PROT_PTR(g_dms.proc_ctx);
}

void dms_set_mes_message_pool(unsigned long long recv_msg_buf_size, mes_profile_t *profile)
{
    mes_msg_pool_attr_t *mpa = &profile->msg_pool_attr;
    mpa->total_size = recv_msg_buf_size;
    mpa->enable_inst_dimension = CM_FALSE;
    mpa->buf_pool_count = DMS_MSG_BUFFER_NO_CEIL;

    mes_msg_buffer_pool_attr_t *buffer_pool_attr;
    // buf0
    buffer_pool_attr = &mpa->buf_pool_attr[DMS_MSG_BUFFER_NO_0];
    buffer_pool_attr->buf_size = DMS_FIRST_BUFFER_LENGTH;
    buffer_pool_attr->proportion = DMS_FIRST_BUFFER_RATIO;

    // buf1
    buffer_pool_attr = &mpa->buf_pool_attr[DMS_MSG_BUFFER_NO_1];
    buffer_pool_attr->buf_size = DMS_SECOND_BUFFER_LENGTH;
    buffer_pool_attr->proportion = DMS_SECOND_BUFFER_RATIO;

    // buf2
    buffer_pool_attr = &mpa->buf_pool_attr[DMS_MSG_BUFFER_NO_2];
    buffer_pool_attr->buf_size = DMS_THIRD_BUFFER_LENGTH;
    buffer_pool_attr->proportion = DMS_THIRDLY_BUFFER_RATIO;

    for (int buf_pool_no = 0; buf_pool_no < mpa->buf_pool_count; buf_pool_no++) {
        buffer_pool_attr = &mpa->buf_pool_attr[buf_pool_no];
        buffer_pool_attr->shared_pool_attr.queue_num = DMS_MSG_BUFFER_QUEUE_NUM;
        for (int prio = 0; prio < DMS_CURR_PRIORITY_COUNT; prio++) {
            if (prio == MES_PRIORITY_SIX) {
                buffer_pool_attr->priority_pool_attr[MES_PRIORITY_SIX].queue_num =
                    DMS_MSG_BUFFER_QUEUE_NUM_PRIO_6;
            } else {
                buffer_pool_attr->priority_pool_attr[prio].queue_num = DMS_MSG_BUFFER_QUEUE_NUM;
            }
        }
    }

    for (int prio = 0; prio < DMS_CURR_PRIORITY_COUNT; prio++) {
        mpa->max_buf_size[prio] = mpa->buf_pool_attr[DMS_MSG_BUFFER_NO_2].buf_size;
    }
}

/*
 * Priority principle: reform/ddl >= ckpt >= derived > others
 * group 1 reform proc messages
 * group 2 reform judgement
 * group 3 checkpoint
 * group 4 edp clean
 * group 5 derived messages
 * group 6 everythin else
 */
unsigned int dms_get_mes_prio_by_cmd(dms_message_head_t *msg)
{
    switch (msg->cmd) {
        case MSG_REQ_SYNC_STEP:
        case MES_REQ_MGRT_MASTER_DATA:
        case MSG_REQ_PAGE_REBUILD:
        case MSG_REQ_LOCK_REBUILD:
        case MSG_REQ_SWITCHOVER:
        case MSG_REQ_CHECK_REFORM_DONE:
        case MSG_REQ_REPAIR_NEW:
            return MES_PRIORITY_ZERO;
        case MSG_REQ_OPENGAUSS_DDLLOCK:
        case MSG_REQ_DDL_SYNC:
            return MES_PRIORITY_ONE;
        case MSG_REQ_SYNC_NEXT_STEP:
        case MSG_REQ_MAP_INFO:
        case MSG_REQ_REFORM_PREPARE:
        case MSG_REQ_SYNC_SHARE_INFO:
        case MSG_REQ_DMS_STATUS:
        case MSG_REQ_REFORM_GCV_SYNC:
            return MES_PRIORITY_TWO;
        case MSG_REQ_MASTER_CKPT_EDP:
        case MSG_REQ_OWNER_CKPT_EDP:
            return MES_PRIORITY_THREE;
        case MSG_REQ_MASTER_CLEAN_EDP:
        case MSG_REQ_OWNER_CLEAN_EDP:
            return MES_PRIORITY_FOUR;
        case MSG_REQ_TXN_INFO:
        case MSG_REQ_CLAIM_OWNER:
        case MSG_REQ_INVALID_OWNER:
        case MSG_REQ_INVALIDATE_SHARE_COPY:
            return MES_PRIORITY_FIVE;
        case MSG_REQ_ASK_MASTER_FOR_PAGE:
        case MSG_REQ_ASK_OWNER_FOR_PAGE:
            return (msg->flags & REQ_FLAG_REFORM_SESSION ? MES_PRIORITY_ZERO : MES_PRIORITY_SIX);
        default:
            return MES_PRIORITY_SIX;
    }
}

/* Work thread allocation */
void dms_set_task_worker_num(dms_profile_t *dms_profile, mes_profile_t *mes_profile)
{
    uint32 sp_count = DMS_WORK_THREAD_PRIO_0 + DMS_WORK_THREAD_PRIO_1 + DMS_WORK_THREAD_PRIO_2 +
        DMS_WORK_THREAD_PRIO_3 + DMS_WORK_THREAD_PRIO_4 + DMS_WORK_THREAD_PRIO_5;
    CM_ASSERT(sp_count < DMS_WORK_THREAD_COUNT);
    uint32 common_count = DMS_WORK_THREAD_COUNT - sp_count;
    uint32 common_recv_count = MAX(1, (uint32)(common_count * DMS_RECV_WORK_THREAD_RATIO));

    mes_profile->send_task_count[MES_PRIORITY_ZERO] = DMS_WORK_THREAD_PRIO_0;
    mes_profile->send_task_count[MES_PRIORITY_ONE] = DMS_WORK_THREAD_PRIO_1;
    mes_profile->send_task_count[MES_PRIORITY_TWO] = DMS_WORK_THREAD_PRIO_2;
    mes_profile->send_task_count[MES_PRIORITY_THREE] = DMS_WORK_THREAD_PRIO_3;
    mes_profile->send_task_count[MES_PRIORITY_FOUR] = DMS_WORK_THREAD_PRIO_4;
    mes_profile->send_task_count[MES_PRIORITY_FIVE] = DMS_WORK_THREAD_PRIO_5;
    mes_profile->send_task_count[MES_PRIORITY_SIX] = common_count;

    if (!dms_profile->enable_mes_task_threadpool) {
        mes_profile->work_task_count[MES_PRIORITY_ZERO] = DMS_WORK_THREAD_PRIO_0;
        mes_profile->work_task_count[MES_PRIORITY_ONE] = DMS_WORK_THREAD_PRIO_1;
        mes_profile->work_task_count[MES_PRIORITY_TWO] = DMS_WORK_THREAD_PRIO_2;
        mes_profile->work_task_count[MES_PRIORITY_THREE] = DMS_WORK_THREAD_PRIO_3;
        mes_profile->work_task_count[MES_PRIORITY_FOUR] = DMS_WORK_THREAD_PRIO_4;
        mes_profile->work_task_count[MES_PRIORITY_FIVE] = DMS_WORK_THREAD_PRIO_5;
        mes_profile->work_task_count[MES_PRIORITY_SIX] = common_count;
    } else {
        mes_profile->work_task_count[MES_PRIORITY_ZERO] = 0;
        mes_profile->work_task_count[MES_PRIORITY_ONE] = 0;
        mes_profile->work_task_count[MES_PRIORITY_TWO] = 0;
        mes_profile->work_task_count[MES_PRIORITY_THREE] = 0;
        mes_profile->work_task_count[MES_PRIORITY_FOUR] = 0;
        mes_profile->work_task_count[MES_PRIORITY_FIVE] = 0;
        mes_profile->work_task_count[MES_PRIORITY_SIX] = 0;
    }

    mes_profile->recv_task_count[MES_PRIORITY_ZERO] = DMS_RECV_THREAD_PRIO_0;
    mes_profile->recv_task_count[MES_PRIORITY_ONE] = DMS_RECV_THREAD_PRIO_1;
    mes_profile->recv_task_count[MES_PRIORITY_TWO] = DMS_RECV_THREAD_PRIO_2;
    mes_profile->recv_task_count[MES_PRIORITY_THREE] = DMS_RECV_THREAD_PRIO_3;
    mes_profile->recv_task_count[MES_PRIORITY_FOUR] = DMS_RECV_THREAD_PRIO_4;
    mes_profile->recv_task_count[MES_PRIORITY_FIVE] = DMS_RECV_THREAD_PRIO_5;
    mes_profile->recv_task_count[MES_PRIORITY_SIX] = common_recv_count;
}

static inline void dms_init_mes_compress(mes_profile_t *mes_profile)
{
    mes_profile->enable_compress_priority = CM_FALSE;
    mes_profile->algorithm = COMPRESS_NONE;
    mes_profile->compress_level = DMS_PRIORITY_COMPRESS_LEVEL;
}

static status_t dms_set_mes_task_threadpool_attr(dms_profile_t *dms_profile, mes_profile_t *mes_profile)
{
    mes_task_threadpool_attr_t *tpool_attr = &mes_profile->tpool_attr;

    tpool_attr->min_cnt = DMS_WORK_THREAD_MIN_CNT;
    tpool_attr->max_cnt = dms_profile->mes_task_worker_max_cnt;
    tpool_attr->group_num = DMS_CURR_PRIORITY_COUNT;

    tpool_attr->group_attr[MES_PRIORITY_ZERO].group_id = MES_PRIORITY_ZERO;
    tpool_attr->group_attr[MES_PRIORITY_ZERO].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_ZERO].min_cnt = DMS_WORK_THREAD_PRIO_0_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_ZERO].max_cnt = MAX(DMS_WORK_THREAD_PRIO_0_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_0_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_ZERO].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_ZERO].task_num_ceiling = DMS_PRIO_0_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_ZERO].task_num_floor = DMS_PRIO_0_MSG_NUM_FLOOR;


    tpool_attr->group_attr[MES_PRIORITY_ONE].group_id = MES_PRIORITY_ONE;
    tpool_attr->group_attr[MES_PRIORITY_ONE].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_ONE].min_cnt = DMS_WORK_THREAD_PRIO_1_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_ONE].max_cnt = MAX(DMS_WORK_THREAD_PRIO_1_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_1_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_ONE].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_ONE].task_num_ceiling = DMS_DEFAULT_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_ONE].task_num_floor = DMS_DEFAULT_MSG_NUM_FLOOR;

    tpool_attr->group_attr[MES_PRIORITY_TWO].group_id = MES_PRIORITY_TWO;
    tpool_attr->group_attr[MES_PRIORITY_TWO].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_TWO].min_cnt = DMS_WORK_THREAD_PRIO_2_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_TWO].max_cnt = MAX(DMS_WORK_THREAD_PRIO_2_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_2_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_TWO].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_TWO].task_num_ceiling = DMS_PRIO_2_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_TWO].task_num_floor = DMS_PRIO_2_MSG_NUM_FLOOR;

#ifdef OPENGAUSS
    tpool_attr->group_attr[MES_PRIORITY_THREE].group_id = MES_PRIORITY_THREE;
    tpool_attr->group_attr[MES_PRIORITY_THREE].enabled = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_THREE].max_cnt = 0;

    tpool_attr->group_attr[MES_PRIORITY_FOUR].group_id = MES_PRIORITY_FOUR;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].enabled = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].max_cnt = 0;
#else
    tpool_attr->group_attr[MES_PRIORITY_THREE].group_id = MES_PRIORITY_THREE;
    tpool_attr->group_attr[MES_PRIORITY_THREE].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_THREE].min_cnt = DMS_WORK_THREAD_PRIO_3_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_THREE].max_cnt = MAX(DMS_WORK_THREAD_PRIO_3_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_3_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_THREE].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_THREE].task_num_ceiling = DMS_DEFAULT_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_THREE].task_num_floor = DMS_DEFAULT_MSG_NUM_FLOOR;

    tpool_attr->group_attr[MES_PRIORITY_FOUR].group_id = MES_PRIORITY_FOUR;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].min_cnt = DMS_WORK_THREAD_PRIO_4_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].max_cnt = MAX(DMS_WORK_THREAD_PRIO_4_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_4_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_FOUR].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].task_num_ceiling = DMS_DEFAULT_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_FOUR].task_num_floor = DMS_DEFAULT_MSG_NUM_FLOOR;
#endif

    tpool_attr->group_attr[MES_PRIORITY_FIVE].group_id = MES_PRIORITY_FIVE;
    tpool_attr->group_attr[MES_PRIORITY_FIVE].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_FIVE].min_cnt = DMS_WORK_THREAD_PRIO_5_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_FIVE].max_cnt = MAX(DMS_WORK_THREAD_PRIO_5_MIN_CNT,
        dms_profile->mes_task_worker_max_cnt * DMS_WORK_THREAD_PRIO_5_RATIO);
    tpool_attr->group_attr[MES_PRIORITY_FIVE].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_FIVE].task_num_ceiling = DMS_DEFAULT_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_FIVE].task_num_floor = DMS_DEFAULT_MSG_NUM_FLOOR;

    unsigned int left_max_cnt = dms_profile->mes_task_worker_max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_ZERO].max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_ONE].max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_TWO].max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_THREE].max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_FOUR].max_cnt \
        - tpool_attr->group_attr[MES_PRIORITY_FIVE].max_cnt;
    
    if (left_max_cnt < DMS_WORK_THREAD_MAJOR_MIN_CNT) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "dms_profile's mes_task_worker_max_cnt");
        return ERRNO_DMS_PARAM_INVALID;
    }
    
    tpool_attr->group_attr[MES_PRIORITY_SIX].group_id = MES_PRIORITY_SIX;
    tpool_attr->group_attr[MES_PRIORITY_SIX].enabled = CM_TRUE;
    tpool_attr->group_attr[MES_PRIORITY_SIX].min_cnt = DMS_WORK_THREAD_MAJOR_MIN_CNT;
    tpool_attr->group_attr[MES_PRIORITY_SIX].max_cnt = left_max_cnt;
    tpool_attr->group_attr[MES_PRIORITY_SIX].num_fixed = CM_FALSE;
    tpool_attr->group_attr[MES_PRIORITY_SIX].task_num_ceiling = DMS_DEFAULT_MSG_NUM_CEILING;
    tpool_attr->group_attr[MES_PRIORITY_SIX].task_num_floor = DMS_DEFAULT_MSG_NUM_FLOOR;
    return DMS_SUCCESS;
}

int dms_set_mes_profile(dms_profile_t *dms_profile, mes_profile_t *mes_profile)
{
    LOG_RUN_INF("[DMS] dms_set_mes_profile start");
    mes_profile->inst_id = dms_profile->inst_id;
    mes_profile->inst_cnt = dms_profile->inst_cnt;
    if (dms_profile->pipe_type == DMS_CONN_MODE_TCP) {
        mes_profile->pipe_type = DMS_CS_TYPE_TCP;
    } else if (dms_profile->pipe_type == DMS_CONN_MODE_RDMA) {
        mes_profile->pipe_type = DMS_CS_TYPE_RDMA;
    } else {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "dms_profile's pipe_type");
        return ERRNO_DMS_PARAM_INVALID;
    }

    mes_profile->conn_created_during_init = dms_profile->conn_created_during_init;
    mes_profile->channel_cnt = dms_profile->channel_cnt;
    mes_profile->priority_cnt = DMS_CURR_PRIORITY_COUNT;
    mes_profile->mes_elapsed_switch = dms_profile->elapsed_switch;
    mes_profile->rdma_rpc_use_busypoll = dms_profile->rdma_rpc_use_busypoll;
    mes_profile->rdma_rpc_is_bind_core = dms_profile->rdma_rpc_is_bind_core;
    mes_profile->rdma_rpc_bind_core_start = dms_profile->rdma_rpc_bind_core_start;
    mes_profile->rdma_rpc_bind_core_end = dms_profile->rdma_rpc_bind_core_end;
    mes_profile->frag_size = DMS_MESSAGE_BUFFER_SIZE;
    mes_profile->max_wait_time = dms_profile->max_wait_time;
    mes_profile->connect_timeout = (int)CM_CONNECT_TIMEOUT;
    mes_profile->socket_timeout = (int)CM_NETWORK_IO_TIMEOUT;
    mes_profile->send_directly = CM_TRUE;
    mes_profile->need_serial = CM_FALSE;
    errno_t err = memcpy_s(mes_profile->inst_net_addr, sizeof(mes_addr_t) * DMS_MAX_INSTANCES, dms_profile->inst_net_addr,
        sizeof(mes_addr_t) * DMS_MAX_INSTANCES);
    DMS_SECUREC_CHECK(err);
    err = memcpy_s(mes_profile->ock_log_path, MES_MAX_LOG_PATH, dms_profile->ock_log_path, DMS_OCK_LOG_PATH_LEN);
    DMS_SECUREC_CHECK(err);

    dms_init_mes_compress(mes_profile);
    dms_set_task_worker_num(dms_profile, mes_profile);

    if (dms_profile->enable_mes_task_threadpool) {
        mes_profile->tpool_attr.enable_threadpool = CM_TRUE;
        dms_set_mes_task_threadpool_attr(dms_profile, mes_profile);
    }
    dms_set_mes_message_pool(dms_profile->recv_msg_buf_size, mes_profile);
    LOG_RUN_INF("[DMS] dms_set_mes_profile end");
    return DMS_SUCCESS;
}

static unsigned short dms_get_msg_cmd(char *buff)
{
    dms_message_head_t *dms_head = (dms_message_head_t *)buff;
    return (unsigned short)(dms_head->cmd);
}

int dms_mes_interrupt(void *arg, int wait_time)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    share_info_t *share_info = DMS_SHARE_INFO;
    if (reform_info->is_locking) {
        return CM_TRUE;
    }
    if (dms_reform_in_process() && wait_time >= MILLISECS_PER_SECOND &&
        !REFORM_TYPE_IS_AZ_SWITCHOVER(share_info->reform_type)) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

int dms_init_mes(dms_profile_t *dms_profile)
{
    int ret;
    mes_profile_t mes_profile = { 0 };
    ret = dms_set_mes_profile(dms_profile, &mes_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = mfc_init(&mes_profile);
    if (ret != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }
    mes_set_app_cmd_cb(dms_get_msg_cmd);
    mes_register_interrupt(dms_mes_interrupt);
    // save g_cbb_mes address
    g_dms.mes_ptr = mes_get_global_inst();

    return ret;
}

static status_t dms_global_res_init(drc_global_res_map_t *global_res, uint32 inst_cnt, int32 res_type,
    uint32 pool_size, uint32 item_size, res_cmp_callback res_cmp_func, res_hash_callback get_hash_func)
{
    uint32 size = sizeof(drc_part_list_t) * DRC_MAX_PART_NUM;
    DMS_SECUREC_CHECK(memset_s(global_res->res_parts, size, 0, size));
    return drc_res_map_init(&global_res->res_map, inst_cnt, res_type, pool_size,
        item_size, res_cmp_func, get_hash_func);
}

void dms_global_res_reinit(drc_global_res_map_t *global_res)
{
    uint32 size = sizeof(drc_part_list_t) * DRC_MAX_PART_NUM;
    DMS_SECUREC_CHECK(memset_s(global_res->res_parts, size, 0, size));
    drc_res_map_reinit(&global_res->res_map);
}

static inline int32 init_common_res_ctx(const dms_profile_t *dms_profile)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 item_num = DMS_CM_MAX_SESSIONS * 2;
    int32 ret = drc_res_pool_init(&ctx->lock_item_pool, dms_profile->inst_cnt, sizeof(drc_lock_item_t), item_num);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]lock item pool init fail,return error:%d", ret);
    }

    return ret;
}

static int32 init_page_res_ctx(const dms_profile_t *dms_profile)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 res_num = (uint32)(DRC_RECYCLE_ALLOC_COUNT * dms_profile->data_buffer_size / dms_profile->page_size);
#ifdef OPENGAUSS
    res_num = (uint32)MAX(res_num, SIZE_M(1));
#endif
    int ret = dms_global_res_init(&ctx->global_buf_res, dms_profile->inst_cnt, DMS_RES_TYPE_IS_PAGE, res_num,
        sizeof(drc_page_t), dms_same_page, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global page resource pool init fail,return error:%d", ret);
    }
    return ret;
}

static bool32 dms_same_global_alock(char *drc, const char *resid, uint32 len)
{
    drc_alock_t *drc_alock = (drc_alock_t *)drc;
    alockid_t *alockid1 = &drc_alock->alockid;
    alockid_t *alockid2 = (alockid_t *)resid;

    if (alockid1->len != alockid2->len || alockid1->type != alockid2->type) {
        return CM_FALSE;
    }
    return memcmp(alockid1->name, alockid2->name, alockid1->len) == 0 ? CM_TRUE : CM_FALSE;
}

static int32 init_alock_res_ctx(const dms_profile_t *dms_profile)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 alock_num = DRC_DEFAULT_ALOCK_RES_NUM;
    int ret = dms_global_res_init(&ctx->global_alock_res, dms_profile->inst_cnt, DMS_RES_TYPE_IS_ALOCK, alock_num,
        sizeof(drc_alock_t), dms_same_global_alock, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global alock resource pool init fail,return error:%d", ret);
    }
    return ret;
}

int dms_dyn_change_buf_drc_num(unsigned long long new_data_buffer_size, unsigned long long old_data_buffer_size)
{
    dms_reset_error();
    if (new_data_buffer_size < old_data_buffer_size) {
        LOG_RUN_ERR("[DRC]Can not reduce DATA_BUFFER_SIZE online. old_data_buffer_size:%llu, new_data_buffer_size:%llu",
            old_data_buffer_size, new_data_buffer_size);
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "new data_buffer_size");
        return DMS_ERROR;
    }

    if (new_data_buffer_size == old_data_buffer_size) {
        return DMS_SUCCESS;
    }

    drc_res_ctx_t *ctx = DRC_RES_CTX;
    float change_pool_num_rate = (float)new_data_buffer_size / old_data_buffer_size;
    drc_res_pool_t *pool = &ctx->global_buf_res.res_map.res_pool;
    uint32 old_max_extend_num = pool->max_extend_num;
    cm_spin_lock(&pool->lock, NULL);
    pool->max_extend_num = MIN(DRC_RES_EXTEND_MAX_NUM, MAX(old_max_extend_num,
        ceil(change_pool_num_rate * old_max_extend_num)));
    cm_spin_unlock(&pool->lock);
    LOG_RUN_INF("[DRC]buf drc pool's max_extend_num changes, ori:%u, now:%u", old_max_extend_num, pool->max_extend_num);
    return DMS_SUCCESS;
}

static int32 init_lock_res_ctx(dms_profile_t *dms_profile)
{
    int ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ret = dms_global_res_init(&ctx->global_lock_res, dms_profile->inst_cnt, DMS_RES_TYPE_IS_LOCK,
        DRC_DEFAULT_GLOCK_RES_NUM, sizeof(drc_lock_t), dms_same_global_lock, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global lock resource pool init fail,return error:%d", ret);
        return ret;
    }

    ret = drc_res_map_init(&ctx->local_lock_res, dms_profile->inst_cnt, DMS_RES_TYPE_IS_LOCK, DRC_DEFAULT_LLOCK_RES_NUM,
        sizeof(drc_local_lock_res_t), dms_same_local_lock, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]local lock resource pool init fail,return error:%d", ret);
        return ret;
    }

    return DMS_SUCCESS;
}

static int32 init_xa_res_ctx(dms_profile_t *dms_profile)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 res_num = dms_profile->max_session_cnt;
    int32 ret = dms_global_res_init(&ctx->global_xa_res, dms_profile->inst_cnt, DMS_RES_TYPE_IS_XA, res_num,
        sizeof(drc_xa_t), dms_same_global_xid, dms_xa_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]global xid resource pool init fail, return error:%d", ret);
        return ret;
    }

    return DMS_SUCCESS;
}

static int32 init_txn_res_ctx(const dms_profile_t *dms_profile)
{
    int32 ret;
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    uint32 item_num = DMS_CM_MAX_SESSIONS * dms_profile->inst_cnt;
    ret = drc_res_map_init(&ctx->local_txn_map, dms_profile->inst_cnt, DMS_RES_TYPE_IS_LOCAL_TXN, item_num,
        sizeof(drc_txn_res_t), dms_same_txn, dms_res_hash);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]local txn resource pool init fail,return error:%d", ret);
        return ret;
    }

    ret = drc_res_map_init(&ctx->txn_res_map, dms_profile->inst_cnt, DMS_RES_TYPE_IS_TXN, item_num,
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

static void drc_smon_ctx_deinit(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    cm_close_thread(&ctx->smon_thread);
    cm_close_thread(&ctx->smon_recycle_thread);
    DMS_RELEASE_DB_HANDLE(ctx->smon_handle);
    DMS_RELEASE_DB_HANDLE(ctx->smon_recycle_handle);
}

static int32 init_drc_smon_ctx(void)
{
    drc_res_ctx_t *ctx = DRC_RES_CTX;

    ctx->chan = cm_chan_new(DRC_SMON_QUEUE_SIZE, sizeof(res_id_t));
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

    ret = cm_create_thread(drc_recycle_thread, 0, NULL, &ctx->smon_recycle_thread);
    if (ret != CM_SUCCESS) {
        LOG_RUN_ERR("[DRC]fail to create smon recycle thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    ret = drm_thread_init();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]fail to create drm thread");
        DMS_THROW_ERROR(ERRNO_DMS_COMMON_CBB_FAILED, ret);
        return ERRNO_DMS_COMMON_CBB_FAILED;
    }

    return DMS_SUCCESS;
}

static int init_drc_mem_context(dms_profile_t *dms_profile)
{
    g_dms.drc_mem_context = NULL;
    if (dms_profile->drc_buf_size == 0) {
        return DMS_SUCCESS;
    }
    cm_memory_allocator_t memory_allocator = {
        .malloc_proc = (g_dms.callback.drc_malloc_prot == NULL ? malloc : g_dms.callback.drc_malloc_prot),
        .free_proc = (g_dms.callback.drc_free_prot == NULL ? free : g_dms.callback.drc_free_prot)
    };

    g_dms.drc_mem_context =
        ddes_memory_context_create(NULL, dms_profile->drc_buf_size, "drc_mem_context", &memory_allocator);
    if (g_dms.drc_mem_context == NULL) {
        return DMS_ERROR;
    }
    return DMS_SUCCESS;
}

int dms_init_drc_res_ctx(dms_profile_t *dms_profile)
{
    int ret;
    LOG_RUN_INF("[DMS] dms_init_drc_res_ctx start");
    drc_res_ctx_t *ctx = DRC_RES_CTX;
    ret = memset_s(ctx, sizeof(drc_res_ctx_t), 0, sizeof(drc_res_ctx_t));
    DMS_SECUREC_CHECK(ret);

    ret = init_drc_mem_context(dms_profile);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DRC]init_drc_mem_context failed");
        return ret;
    }

    do {
        if ((ret = init_common_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_page_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_alock_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_lock_res_ctx(dms_profile)) != DMS_SUCCESS) {
            break;
        }

        if ((ret = init_xa_res_ctx(dms_profile)) != DMS_SUCCESS) {
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
        drc_smon_ctx_deinit();
        drc_destroy();
    }
    LOG_RUN_INF("[DMS] dms_init_drc_res_ctx end");
    return ret;
}

static int32 init_single_logger(log_param_t *log_param, log_type_t log_id);

#ifndef OPENGAUSS
static void dms_init_log(dms_profile_t *dms_profile)
{
    cm_log_param_instance()->log_write = (usr_cb_log_output_t)dms_profile->callback.log_output;
    cm_log_param_instance()->log_level = dms_profile->log_level;
}
#endif

void dms_set_log_level(unsigned int log_level)
{
    cm_log_param_instance()->log_level = log_level;
}

void dms_set_log_file_count(unsigned int log_count)
{
    cm_log_param_instance()->log_backup_file_count = log_count;
    cm_log_param_instance()->audit_backup_file_count = log_count;
}

void dms_set_log_file_size(unsigned long long log_size)
{
    cm_log_param_instance()->max_log_file_size = log_size;
    cm_log_param_instance()->max_audit_file_size = log_size;
}

static int32 init_single_logger_core(log_param_t *log_param, log_type_t log_id, char *file_name, uint32 file_name_len)
{
    int32 ret;
    switch (log_id) {
        case CM_LOG_RUN:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DMS/run/%s", log_param->log_home, "dms.rlog");
            break;
        case CM_LOG_DEBUG:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DMS/debug/%s", log_param->log_home, "dms.dlog");
            break;
        case CM_LOG_ALARM:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DMS/alarm/%s", log_param->log_home, "dms.alog");
            break;
        case CM_LOG_AUDIT:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN, "%s/DMS/audit/%s", log_param->log_home, "dms.aud");
            break;
        case CM_LOG_DMS_EVT_TRC:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN,
                "%s/trc/%s", log_param->log_home, "dms_event.trc");
            break;
        case CM_LOG_DMS_RFM_TRC:
            ret = snprintf_s(file_name, file_name_len, CM_MAX_FILE_NAME_LEN,
                "%s/trc/%s", log_param->log_home, "dms_reform.trc");
            break;
        default:
            ret = 0;
            break;
    }

    if (ret != -1) {
        return DMS_SUCCESS;
    }

    DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
    return ERRNO_DMS_INIT_LOG_FAILED;
}

static int32 init_single_logger(log_param_t *log_param, log_type_t log_id)
{
    char file_name[CM_FILE_NAME_BUFFER_SIZE] = {'\0'};
    CM_RETURN_IFERR(init_single_logger_core(log_param, log_id, file_name, CM_FILE_NAME_BUFFER_SIZE));
    LOG_RUN_INF("[DMS]log file name=%s", file_name);
    (void)cm_log_init(log_id, (const char *)file_name);
    cm_log_open_compress(log_id, true);
    return DMS_SUCCESS;
}

int dms_dyn_trc_init_logger_handle()
{
    log_param_t *log_param = cm_log_param_instance();
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DMS_EVT_TRC));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DMS_RFM_TRC));
    return DMS_SUCCESS;
}

void dms_refresh_logger(char *log_field, unsigned long long *value)
{
    if (log_field ==NULL) {
        return;
    }

    if (strcmp(log_field, "LOG_LEVEL") == 0) {
        cm_log_param_instance()->log_level = (uint32)(*value);
    } else if (strcmp(log_field, "LOG_MAX_FILE_SIZE") == 0) {
        cm_log_param_instance()->max_log_file_size = (uint64)(*value);
        cm_log_param_instance()->max_audit_file_size = (uint64)(*value);
    } else if (strcmp(log_field, "LOG_BACKUP_FILE_COUNT") == 0) {
        cm_log_param_instance()->log_backup_file_count = (uint32)(*value);
        cm_log_param_instance()->audit_backup_file_count = (uint32)(*value);
    }
}

int32 dms_init_logger(logger_param_t *param_def)
{
    dms_reset_error();
    errno_t ret;
    log_param_t *log_param = cm_log_param_instance();
    ret = memset_s(log_param, sizeof(log_param_t), 0, sizeof(log_param_t));
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }

    log_param->log_level = param_def->log_level;
    log_param->log_backup_file_count = param_def->log_backup_file_count;
    log_param->audit_backup_file_count = param_def->log_backup_file_count;
    log_param->max_log_file_size = param_def->log_max_file_size;
    log_param->max_audit_file_size = param_def->log_max_file_size;
#ifdef OPENGAUSS
    log_param->log_compressed = CM_FALSE;
#else
    log_param->log_compressed = CM_TRUE;
#endif
    log_param->log_compress_buf = dms_malloc(NULL, CM_LOG_COMPRESS_BUFSIZE);
    if (log_param->log_compress_buf == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }
    cm_log_set_file_permissions(600);
    cm_log_set_path_permissions(700);
    (void)cm_set_log_module_name("DMS", sizeof("DMS"));
    ret = strcpy_sp(log_param->instance_name, CM_MAX_NAME_LEN, "DMS");
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }

    ret = strcpy_sp(log_param->log_home, CM_MAX_LOG_HOME_LEN, param_def->log_home);
    if (ret != EOK) {
        DMS_THROW_ERROR(ERRNO_DMS_INIT_LOG_FAILED);
        return ERRNO_DMS_INIT_LOG_FAILED;
    }

#ifdef OPENGAUSS
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_RUN));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DEBUG));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_ALARM));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_AUDIT));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DMS_EVT_TRC));
    CM_RETURN_IFERR(init_single_logger(log_param, CM_LOG_DMS_RFM_TRC));
#endif

    log_param->log_instance_startup = (bool32)CM_TRUE;

#ifdef OPENGAUSS
    if (log_param->log_level >= DEBUG_LOG_LEVEL) {
        cm_recovery_log_file(CM_LOG_DEBUG);
        cm_recovery_log_file(CM_LOG_RUN);
    }
#endif
    return DMS_SUCCESS;
}

void dms_fsync_logfile(void)
{
    cm_fync_logfile();
}

/* max timeout interval should be within [1, 30]s */
static inline uint32 dms_check_max_wait_time(uint32 time)
{
    const uint32 max = 30000;
    const uint32 min = 1000;
    return time < min ? min : (time > max ? max : time);
}

static int dms_init_stat(dms_profile_t *dms_profile)
{
    g_dms_stat.time_stat_enabled = dms_profile->time_stat_enabled;
    g_dms_stat.sess_cnt = dms_profile->work_thread_cnt + dms_profile->channel_cnt + dms_profile->max_session_cnt;
    g_dms_stat.sess_iterator = 0;

    size_t size = g_dms_stat.sess_cnt * sizeof(session_stat_t);
    g_dms_stat.sess_stats = (session_stat_t *)dms_malloc(NULL, size);

    if (g_dms_stat.sess_stats == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_ALLOC_FAILED);
        return ERRNO_DMS_ALLOC_FAILED;
    }

    int ret = memset_s(g_dms_stat.sess_stats, size, 0, size);
    DMS_SECUREC_CHECK(ret);
    g_dms_stat.inited = CM_TRUE;

    return DMS_SUCCESS;
}

static void dms_uninit_stat()
{
    g_dms_stat.inited = CM_FALSE;
    DMS_FREE_PROT_PTR(g_dms_stat.sess_stats);
}

static void dms_set_global_dms(dms_profile_t *dms_profile)
{
    LOG_RUN_INF("[DMS] dms_set_global_dms start");
    g_dms.callback = dms_profile->callback;
    g_dms.page_size = dms_profile->page_size;
    g_dms.inst_id = dms_profile->inst_id;
    g_dms.inst_cnt = dms_profile->inst_cnt;
    g_dms.inst_map = dms_profile->inst_map;
    g_dms.scrlock_ctx.enable = dms_profile->enable_scrlock;
    g_dms.gdb_in_progress = CM_FALSE;
    g_dms.max_wait_time = dms_check_max_wait_time(dms_profile->max_wait_time);
    g_dms.max_alive_time_for_abnormal_status = dms_check_max_wait_time(dms_profile->max_alive_time_for_abnormal_status);
    if (dms_profile->max_alive_time_for_abnormal_status == 0) {
        dms_profile->max_alive_time_for_abnormal_status = DEFAULT_TIME_FOR_ABNORMAL_STATUS;
    }
    dms_init_cluster_proto_version();
    cm_set_spin_sleep_time(dms_profile->spin_sleep_time_nsec);
    LOG_RUN_INF("[DMS] dms_set_global_dms end");
}

int dms_init(dms_profile_t *dms_profile)
{
    int ret;

#ifndef OPENGAUSS
    dms_init_log(dms_profile);
#endif

    ret = cm_start_timer(g_timer());
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    LOG_RUN_INF("[DMS] dms_init start");

    if (dms_profile == NULL) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_NULL);
        return ERRNO_DMS_PARAM_NULL;
    }

    ret = memset_s(&g_dms, sizeof(dms_instance_t), 0, sizeof(dms_instance_t));
    DMS_SECUREC_CHECK(ret);

    dms_set_global_dms(dms_profile);

    ret = dms_init_stat(dms_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = dms_init_dynamic_trace(dms_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    cm_init_error_handler(cm_set_log_error);
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
        dms_deinit_proc_ctx();
        return ret;
    }

    ret = dms_init_mes(dms_profile);
    if (ret != DMS_SUCCESS) {
        drc_smon_ctx_deinit();
        drc_destroy();
        dms_deinit_proc_ctx();
        return ret;
    }

    ret = dms_reform_init(dms_profile);
    if (ret != DMS_SUCCESS) {
        drc_smon_ctx_deinit();
        dms_reform_uninit();
        drc_destroy();
        dms_deinit_proc_ctx();
        return ret;
    }

    ret = dms_scrlock_init(dms_profile);
    if (ret != DMS_SUCCESS) {
        drc_smon_ctx_deinit();
        dms_reform_uninit();
        drc_destroy();
        dms_deinit_proc_ctx();
        return ret;
    }

#ifndef WIN32
    char version[DMS_VERSION_MAX_LEN];
    dms_show_version(version);
    LOG_RUN_INF("[DMS]%s", version);
#endif
    g_dms.dms_init_finish = CM_TRUE;
    return DMS_SUCCESS;
}

void dms_pre_uninit(void)
{
    dms_reform_uninit();
}

void dms_uninit(void)
{
#ifdef OPENGAUSS
    dms_scrlock_uninit();
    dms_reform_uninit();
#else
    dms_reform_cm_res_unlock();
#endif
    cm_res_mgr_uninit(&g_dms.cm_res_mgr);
    drc_smon_ctx_deinit();
    mfc_uninit();
    drc_destroy();
    cm_close_timer(g_timer());
    DMS_FREE_PROT_PTR(g_dms_stat.sess_stats);
    DMS_FREE_PROT_PTR(cm_log_param_instance()->log_compress_buf);
    dms_deinit_proc_ctx();
    dms_uninit_dynamic_trace();
    dms_uninit_stat();
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

int dms_register_thread_init(dms_thread_init_t thrd_init)
{
    dms_reset_error();
    mes_set_worker_init_cb(thrd_init);
    return DMS_SUCCESS;
}

int dms_register_thread_deinit(dms_thread_deinit_t thrd_deinit)
{
    dms_reset_error();
    mes_set_worker_deinit_cb(thrd_deinit);
    return DMS_SUCCESS;
}

int dms_register_ssl_decrypt_pwd(dms_decrypt_pwd_t cb_func)
{
    dms_reset_error();
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
    dms_reset_error();
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
    dms_reset_error();
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

#define DMS_MAX_MES_ROOMS (16384)
unsigned int dms_get_mes_max_watting_rooms(void)
{
    return DMS_MAX_MES_ROOMS;
}

int dms_create_global_xa_res(dms_context_t *dms_ctx, uint8 owner_id, uint8 undo_set_id, uint32 *remote_result,
    bool8 ignore_exist)
{
    uint8 master_id = 0xFF;
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;

    int ret = drc_get_master_id((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS][%s]: get master id for xa res failed", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        *remote_result = DMS_SUCCESS;
        ret = drc_xa_create(dms_ctx->db_handle, DMS_SESSION_NORMAL, dms_ctx->sess_id, global_xid, owner_id);
        if (ret == ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS && ignore_exist) {
            return DMS_SUCCESS;
        } else {
            return ret;
        }
    }

    ret = dms_request_create_xa_res(dms_ctx, master_id, undo_set_id, remote_result);
    if (ret == DMS_SUCCESS && *remote_result == ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS && ignore_exist) {
        *remote_result = DMS_SUCCESS;
    }

    return ret;
}

int dms_delete_global_xa_res(dms_context_t *dms_ctx, uint32 *remote_result) 
{
    uint8 master_id = 0xFF;
    drc_global_xid_t *global_xid = &dms_ctx->global_xid;

    int ret = drc_get_master_id((char *)global_xid, DRC_RES_GLOBAL_XA_TYPE, &master_id);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("[DMS][%s]: get master id for xa res failed", cm_display_resid((char *)global_xid,
            DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    if (master_id == dms_ctx->inst_id) {
        *remote_result = DMS_SUCCESS;
        return drc_xa_delete(global_xid);
    }
    
    return dms_request_delete_xa_res(dms_ctx, master_id, remote_result);
}

int dms_end_global_xa(dms_context_t *dms_ctx, uint64 flags, uint64 scn, bool8 is_commit, int32 *remote_result)
{
    uint8 owner_id = CM_INVALID_ID8;
    drc_global_xid_t *xid = &dms_ctx->global_xid;

    LOG_DEBUG_INF("[DMS][%s]: enter dms_end_global_xa", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
    int ret = dms_request_xa_owner(dms_ctx, &owner_id);
    if (ret != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS][%s] get owner for xa failed", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        return ret;
    }

    ret = DMS_SUCCESS;
    if (owner_id == dms_ctx->inst_id) {
        ret = g_dms.callback.end_xa(dms_ctx->db_handle, xid, flags, scn, is_commit);
        if (ret != DMS_SUCCESS) {
            LOG_DEBUG_ERR("[DMS][%s] end xa local failed, errcode = %d", cm_display_resid((char *)xid,
                DRC_RES_GLOBAL_XA_TYPE), ret);
        } else {
            LOG_DEBUG_INF("[DMS][%s]: end xa local success", cm_display_resid((char *)xid, DRC_RES_GLOBAL_XA_TYPE));
        }

        return ret;
    }

    return dms_request_end_xa(dms_ctx, owner_id, flags, scn, is_commit, remote_result);
}

uint64 dms_calc_res_map_mem(uint32 item_num, uint32 item_size, uint32 max_extend_num)
{
    uint32 bucket_num = DMS_RES_MAP_INIT_PARAM * item_num + 1;
    // bucket size
    uint64 total_mem = (uint64)(bucket_num * sizeof(drc_res_bucket_t));
    // pool size
    total_mem += (uint64)item_size * item_num * max_extend_num;
    return total_mem;
}

int dms_calc_mem_usage(dms_profile_t *dms_profile, uint64 *total_mem)
{
    // dms proc_ctx
    *total_mem = (dms_profile->work_thread_cnt + dms_profile->channel_cnt) * sizeof(dms_process_context_t);
    // dms sess_stats
    *total_mem += (uint64)((dms_profile->work_thread_cnt + dms_profile->channel_cnt + dms_profile->max_session_cnt) * sizeof(session_stat_t));
    if (g_dms.drc_mem_context == NULL) {
        // common res
        *total_mem += DMS_CM_MAX_SESSIONS * SESSION_MULTIPLES * sizeof(drc_lock_item_t) * dms_profile->inst_cnt;
        // page res
        uint32 page_res_num =
            (uint32)(DRC_RECYCLE_ALLOC_COUNT * dms_profile->data_buffer_size / dms_profile->page_size);
        *total_mem += dms_calc_res_map_mem(page_res_num, sizeof(drc_page_t), dms_profile->inst_cnt);
        // global lock res
        *total_mem += dms_calc_res_map_mem(DRC_DEFAULT_GLOCK_RES_NUM, sizeof(drc_lock_t), dms_profile->inst_cnt);
        // global alock res
        *total_mem += dms_calc_res_map_mem(DRC_DEFAULT_ALOCK_RES_NUM, sizeof(drc_alock_t), dms_profile->inst_cnt);
        // local lock res
        *total_mem +=
            dms_calc_res_map_mem(DRC_DEFAULT_LLOCK_RES_NUM, sizeof(drc_local_lock_res_t), dms_profile->inst_cnt);
        // xa res
        *total_mem +=
            dms_calc_res_map_mem(dms_profile->max_session_cnt, sizeof(drc_xa_t), dms_profile->inst_cnt);
        // local txn res
        *total_mem += dms_calc_res_map_mem(dms_profile->max_session_cnt, sizeof(drc_txn_res_t), dms_profile->inst_cnt);
        // global txn res
        *total_mem += dms_calc_res_map_mem(dms_profile->max_session_cnt, sizeof(drc_txn_res_t), dms_profile->inst_cnt);
    } else {
        *total_mem += g_dms.drc_mem_context->mem_max_size;
    }
    // dms smon ctx
    *total_mem += DRC_SMON_QUEUE_SIZE * sizeof(res_id_t) + sizeof(chan_t);

    mes_profile_t mes_profile = {0};
    int ret = dms_set_mes_profile(dms_profile, &mes_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }
    *total_mem += mes_calc_mem_usage(&mes_profile);

    return DMS_SUCCESS;
}

static inline void dms_get_reform_thread(thread_set_t *thread_set, char *dms_thread_name_format)
{
    dms_get_one_thread(thread_set, &DMS_REFORM_CONTEXT->thread_judgement, dms_thread_name_format, "judgement");
    dms_get_one_thread(thread_set, &DMS_REFORM_CONTEXT->thread_reformer, dms_thread_name_format, "reformer");
    dms_get_one_thread(thread_set, &DMS_REFORM_CONTEXT->thread_reform, dms_thread_name_format, "reform");
    dms_get_one_thread(thread_set, &DMS_REFORM_CONTEXT->thread_health, dms_thread_name_format, "health");
}

static inline void dms_get_smon_thread(thread_set_t *thread_set, char *dms_thread_name_format)
{
    dms_get_one_thread(thread_set, &DRC_RES_CTX->smon_thread, dms_thread_name_format, "smon");
    dms_get_one_thread(thread_set, &DRC_RES_CTX->smon_recycle_thread, dms_thread_name_format, "smon recycle");
}

static void dms_get_reform_parallel_thread(thread_set_t *thread_set, char *dms_thread_name_format)
{
    parallel_info_t *parallel_info = DMS_PARALLEL_INFO;
    parallel_thread_t *parallel = NULL;
    for (uint32 i = 0; i < parallel_info->parallel_num; i++) {
        parallel = &parallel_info->parallel[i];
        if (parallel->handle == NULL) {
            return;
        }
        dms_get_one_thread(thread_set, &parallel->thread, dms_thread_name_format, "reform parallel");
    }
}

void dms_get_dms_thread(thread_set_t *thread_set)
{
    errno_t err = memset_s(&g_mes_thread_set, sizeof(mes_thread_set_t), 0, sizeof(mes_thread_set_t));
    DMS_SECUREC_CHECK_SS(err);
    mes_get_all_threads(&g_mes_thread_set);

    for (int32 i = 0; i < g_mes_thread_set.thread_count; i++) {
        if (thread_set->thread_count >= MAX_DMS_THREAD_NUM) {
            return;
        }
        err = sprintf_s(thread_set->threads[thread_set->thread_count].thread_name,
            DMS_MAX_NAME_LEN, "%s", g_mes_thread_set.threads[i].thread_name);
        DMS_SECUREC_CHECK_SS(err);
        thread_set->threads[thread_set->thread_count].thread_info = g_mes_thread_set.threads[i].thread_info;
        thread_set->thread_count++;
    }

    char dms_thread_name_format[] = "dms %s";
    dms_get_reform_thread(thread_set, dms_thread_name_format);
    dms_get_smon_thread(thread_set, dms_thread_name_format);
    dms_get_reform_parallel_thread(thread_set, dms_thread_name_format);
}

int dms_convert_error_to_event(unsigned int dms_error, unsigned int *dms_event)
{
    switch (dms_error) {
        case ERRNO_DMS_DRC_IS_RECYCLING:
            *dms_event = DMS_EVT_DRC_RECYCLE;
            break;
        case ERRNO_DMS_DRC_FROZEN:
        case ERRNO_DMS_DRC_RECOVERY_PAGE:
            *dms_event = DMS_EVT_DRC_FROZEN;
            break;
        case ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH:
            *dms_event = DMS_EVT_DRC_ENQ_ITEM_NOT_ENOUGH;
            break;
        case ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER:
            *dms_event = DMS_EVT_DRC_ENQ_ITEM_CONFLICT;
            break;
        case ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH:
            *dms_event = DMS_EVT_DRC_NOT_ENOUGH;
            break;
        default:
            *dms_event = DMS_EVT_IDLE_WAIT;
            break;
    }

    return DMS_SUCCESS;
}

int dms_begin_sess_wait(unsigned int sid, unsigned int dms_event)
{
    dms_begin_stat(sid, dms_event, CM_TRUE);
    return DMS_SUCCESS;
}

int dms_end_sess_wait(unsigned int sid, unsigned int dms_event)
{
    dms_end_stat_ex(sid, dms_event);
    return DMS_SUCCESS;
}