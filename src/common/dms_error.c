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
 * dms_error.c
 *
 *
 * IDENTIFICATION
 *    src/common/dms_error.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_error.h"
#include "dms.h"
#include "cm_log.h"
#include "dms_cm.h"

const char *g_dms_errno_common_desc[] = {
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_SECUREC_CHECK_FAIL)] = "dms securec check fail",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_COMMON_MSG_ACK)] = "common msg ack fail, reason %s",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_PARAM_NULL)] = "dms param is null",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_CMD_INVALID)] = "dms cmd is invalid, cmd is %d",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_ALLOC_FAILED)] = "dms alloc failed",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_PARAM_INVALID)] = "dms param is invalid, param = %s",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_CAPABILITY_NOT_SUPPORT)] = "dms not support this capability, type = %d",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_COMMON_COPY_PAGEID_FAIL)] = "copy pageid fail, pageid is %s",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_SEND_MSG_FAILED)] = "send msg failed,errcode:%d, cmd:%u, dst_inst:%u",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_RECV_MSG_FAILED)] = "recv msg failed,errcode:%d, cmd:%u, dst_inst:%u",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_COMMON_CBB_FAILED)] = "common cbb api fail, cbb error code id %d",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_MFC_NO_TICKETS)] = "dms mfc has no tickets",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_MES_INVALID_MSG)] = "dms invalid msg",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_INIT_LOG_FAILED)] = "dms init log failed",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH)] = "dms message protocol version not match",
    [ERRNO_DMS_COMMON_INDEX(ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT)] = "dms message protocol version not support",
};

const char *g_dms_errno_dcs_desc[] = {
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_PAGE_MASTER_ID)] = "dms get page master id fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_SEND_MSG_FAULT)] = "dms send msg fault",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_READ_LOCAL_PAGE)] = "dms read local page fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_BROADCAST_FAILED)] = "dms broadcast failed, errmsg: %s,",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_TXN_INFO_FAILED)] = "dms get txn info fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED)] = "dms get txn snapshot fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_SEND_EDP_FAILED)] = "dms send edp fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_UPDATE_XID_FAILED)] = "dms get update xid fail, ret: %d",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_TXN_STATUS_FAILED)] = "dms get txn status fail, ret: %d",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_XID_CSN_FAILED)] = "dms get xid csn fail, ret: %d",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_LOCK_BUFFER_FAILED)] = "dms lock buffer fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_PAGE_IN_BUFFER_FAILED)] = "dms get page in buffer fail, ret: %d",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_PAGE_CHECKSUM_FAILED)] = "dms page checksum fail",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_REFORM_VISIT_RES)] = "dms %s is visited by reform",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_GET_DISK_LSN_FAILED)] = "[%s]fail to get disk lsn",
    [ERRNO_DMS_DCS_INDEX(ERRNO_DMS_DCS_RECV_MSG_FAULT)] = "dms receive msg fault",
};

const char *g_dms_errno_drc_desc[] = {
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL)] = "resources size too small, res_size = %d",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT)] = "dms request owner type is invalid, type = %d",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH)] = "page pool has no enough capacity",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH)] = "enq item has no enough capacity",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_PAGE_NOT_FOUND)] = "drc page not found, page:%s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_LOCK_ABANDON_TRY)] = "abandon to try lock",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND)] = "page master not found, pageid is %s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER)] = "dms req conflict with other requester",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_LOCK_MASTER_NOT_FOUND)] = "lock master not found, lockid is %s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_RECOVERY_PAGE)] = "page in recovery, please try again, pageid is %s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_LOCK_STATUS_FAIL)] = "lock status fail",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST)] = "invalid repeat request",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_INVALID)] = "invalid drc: %s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_IS_RECYCLING)] = "drc: %s is recycling",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_XA_MASTER_NOT_FOUND)] = "the master of global xid not found, xid is %s",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_XA_POOL_CAPACITY_NOT_ENOUGH)] = "global xa pool has not enough capacity",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_XA_RES_ALREADY_EXISTS)] = "global xa res %s already exists",
    [ERRNO_DMS_DRC_INDEX(ERRNO_DMS_DRC_XA_RES_NOT_EXISTS)] = "global xa res %s does not exists",
};

const char *g_dms_errno_dls_desc[] = {
    [ERRNO_DMS_DLS_INDEX(ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED)] = "dms try release lock fail",
    [ERRNO_DMS_DLS_INDEX(ERRNO_DMS_DLS_TRY_LOCK_FAILED)] = "try lock fail",
};

const char *g_dms_errno_cb_desc[] = {
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR)] = "dms callback alloc cr cursor is null",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST)] =
    "dms callback get heap invisible txn list fail, ret = %d",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST)] =
    "dms callback get index invisible txn list fail, ret = %d",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO)] =
    "dms callback reorganize heap page with undo list fail, ret = %d",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO)] =
    "dms callback reorganize index page with undo list fail, ret = %d",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_READ_PAGE)] = "dms callback read page fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_STACK_PUSH)] = "dms callback stack push fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_RC_UNDO_INIT)] = "dms callback rc undo init fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT)] = "dms callback rc transaction area init fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD)] = "dms callback rc transaction area load fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_GET_DB_HANDLE)] = "dms get db handle fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_FLUSH_COPY)] = "dms callback flush copy fail",
    [ERRNO_DMS_CB_INDEX(ERRNO_DMS_CALLBACK_GET_TXN_INFO)] = "dms callback get txn info fail",
};

const char *g_dms_errno_reform_desc[] = {
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED)] = "switchover not finished",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST)] = "get stat list from CM fail",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_SWITCHOVER_NOT_REFORMER)] = "instance is not reformer",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_NOT_FINISHED)] = "reform not finished",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED)] = "save stable list fail",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_FAIL)] = "reform fail, reason: %s",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_IN_PROCESS)] = "reform in process",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_GET_LOCK_FAILED)] = "get lock from CM fail",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_LMODE_VLDT_PANIC)] = "DRC resource lock mode validate failed",
    [ERRNO_DMS_REFORM_INDEX(ERRNO_DMS_REFORM_LSN_VLDT_PANIC)] = "DRC resource LSN validate failed",
};

const char *dms_get_error_desc(int code)
{
    if (ERRNO_IS_DMS_COMMON(code)) {
        return g_dms_errno_common_desc[ERRNO_DMS_COMMON_INDEX(code)];
    } else if (ERRNO_IS_DMS_DCS(code)) {
        return g_dms_errno_dcs_desc[ERRNO_DMS_DCS_INDEX(code)];
    } else if (ERRNO_IS_DMS_DRC(code)) {
        return g_dms_errno_drc_desc[ERRNO_DMS_DRC_INDEX(code)];
    } else if (ERRNO_IS_DMS_DLS(code)) {
        return g_dms_errno_dls_desc[ERRNO_DMS_DLS_INDEX(code)];
    } else if (ERRNO_IS_DMS_CB(code)) {
        return g_dms_errno_cb_desc[ERRNO_DMS_CB_INDEX(code)];
    } else if (ERRNO_IS_DMS_REFORM(code)) {
        return g_dms_errno_reform_desc[ERRNO_DMS_REFORM_INDEX(code)];
    } else {
        return "invalid errno";
    }
}

void dms_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
}

void dms_reset_error(void)
{
    cm_reset_error();
}