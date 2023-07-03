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
 * dms_error.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_error.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DMS_ERROR_H__
#define __DMS_ERROR_H__

#include "cm_error.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ****BEGIN error code definition of dms common 10001 ~ 11000 **** */
enum en_errno_dms_common {
    ERRNO_DMS_COMMON_BASE = 10000,
    /* add new errno below */

    ERRNO_DMS_SECUREC_CHECK_FAIL = 10001,
    ERRNO_DMS_COMMON_MSG_ACK = 10002,
    ERRNO_DMS_PARAM_NULL = 10003,
    ERRNO_DMS_CMD_INVALID = 10004,
    ERRNO_DMS_ALLOC_FAILED = 10005,
    ERRNO_DMS_MEMSET_FAILED = 10006,
    ERRNO_DMS_PARAM_INVALID = 10007,
    ERRNO_DMS_CAPABILITY_NOT_SUPPORT = 10008,
    ERRNO_DMS_COMMON_COPY_PAGEID_FAIL = 10009,
    ERRNO_DMS_SEND_MSG_FAILED = 10010,
    ERRNO_DMS_RECV_MSG_FAILED = 10011,
    ERRNO_DMS_COMMON_CBB_FAILED = 10012,
    ERRNO_DMS_MFC_NO_TICKETS = 10013,
    ERRNO_DMS_MES_INVALID_MSG = 10014,
    ERRNO_DMS_RES_INVALID_VERSION = 10015,
    ERRNO_DMS_INIT_LOG_FAILED = 10016,

    /* add new errno above */
    ERRNO_DMS_COMMON_END
};
#define ERRNO_DMS_COMMON_INDEX(x)   ((x) - ERRNO_DMS_COMMON_BASE)
#define ERRNO_IS_DMS_COMMON(x)      ((x) > ERRNO_DMS_COMMON_BASE && (x) < ERRNO_DMS_COMMON_END)

/* BEGIN error code definition of dms dcs 11001 ~ 13000 **** */
enum en_errno_dms_dcs {
    ERRNO_DMS_DCS_BASE = 11000,
    /* add new errno below */

    ERRNO_DMS_DCS_PAGE_MASTER_ID = 11001,
    ERRNO_DMS_DCS_MSG_EAGAIN = 11002,
    ERRNO_DMS_DCS_READ_LOCAL_PAGE = 11003,
    ERRNO_DMS_DCS_BROADCAST_FAILED = 11004,
    ERRNO_DMS_DCS_GET_TXN_INFO_FAILED = 11005,
    ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED = 11006,
    ERRNO_DMS_DCS_SEND_EDP_FAILED = 11007,
    ERRNO_DMS_DCS_BOC_FAILED = 11008,
    ERRNO_DMS_DCS_GET_UPDATE_XID_FAILED = 11009,
    ERRNO_DMS_DCS_PAGE_RREQUEST_FAILED = 11010,
    ERRNO_DMS_DCS_GET_TXN_STATUS_FAILED = 11011,
    ERRNO_DMS_DCS_GET_XID_CSN_FAILED = 11012,
    ERRNO_DMS_DCS_LOCK_BUFFER_FAILED = 11013,
    ERRNO_DMS_DCS_GET_PAGE_IN_BUFFER_FAILED = 11014,

    /* add new errno above */
    ERRNO_DMS_DCS_END
};
#define ERRNO_DMS_DCS_INDEX(x)  ((x) - ERRNO_DMS_DCS_BASE)
#define ERRNO_IS_DMS_DCS(x)     ((x) > ERRNO_DMS_DCS_BASE && (x) < ERRNO_DMS_DCS_END)

/* ****BEGIN errror code definition of dms drc 13001 ~ 15000 **** */
enum en_errno_dms_drc {
    ERRNO_DMS_DRC_BASE = 13000,
    /* add new errno below */

    ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL = 13001,
    ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT = 13002,
    ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH = 13003,
    ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH = 13004,
    ERRNO_DMS_DRC_PAGE_NOT_FOUND = 13005,
    ERRNO_DMS_DRC_LOCKITEM_CAPACITY_NOT_ENOUGH = 13006,
    ERRNO_DMS_DRC_LOCK_CONVERT_QUEUE_ABNORMAL = 13007,
    ERRNO_DMS_DRC_LOCK_NOT_FOUND = 13008,
    ERRNO_DMS_DRC_LOCK_ABANDON_TRY = 13009,
    ERRNO_DMS_DRC_LOCK_DEAD_LOCK = 13010,
    ERRNO_DMS_DRC_PAGE_OWNER_NOT_FOUND = 13011,
    ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND = 13012,
    ERRNO_DMS_DRC_CONFLICT_WITH_OWNER = 13013,
    ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER = 13014,
    ERRNO_DMS_DRC_REMASTER_IN_MIGRATE = 13015,
    ERRNO_DMS_DRC_CONFLICT_WITH_INVALID_PAGE = 13016,
    ERRNO_DMS_DRC_RECOVERY_PAGE = 13017,
    ERRNO_DMS_DRC_LOCK_STATUS_FAIL = 13018,
    ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST = 13019,
    ERRNO_DMS_DRC_INVALID_CLAIM_REQUEST = 13020,
    ERRNO_DMS_DRC_INVALID = 13021,
    ERRNO_DMS_DRC_IS_RECYCLING = 13022,
    /* add new errno above */
    ERRNO_DMS_DRC_END
};

#define ERRNO_DMS_DRC_INDEX(x)  ((x) - ERRNO_DMS_DRC_BASE)
#define ERRNO_IS_DMS_DRC(x)     ((x) > ERRNO_DMS_DRC_BASE && (x) < ERRNO_DMS_DRC_END)

/* ****BEGIN error code definition of dms dls 15001 ~ 16000 **** */
enum en_errno_dms_dls {
    ERRNO_DMS_DLS_BASE = 15000,
    /* add new errno below */

    ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED = 15001,
    ERRNO_DMS_DLS_TRY_LOCK_FAILED = 15002,

    /* add new errno above */
    ERRNO_DMS_DLS_END
};

#define ERRNO_DMS_DLS_INDEX(x)  ((x) - ERRNO_DMS_DLS_BASE)
#define ERRNO_IS_DMS_DLS(x)     ((x) > ERRNO_DMS_DLS_BASE && (x) < ERRNO_DMS_DLS_END)

/* ****BEGIN error code definition of dms callback function 16001 ~ 17000 **** */
enum en_errno_dms_cb {
    ERRNO_DMS_CALLBACK_BASE = 16000,
    /* add new errno below */

    ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR = 16001,
    ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST = 16002,
    ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST = 16003,
    ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO = 16004,
    ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO = 16005,
    ERRNO_DMS_CALLBACK_READ_PAGE = 16006,
    ERRNO_DMS_CALLBACK_CHECK_HEAP_PAGE_VISIBLE_WITH_UDSS = 16007,
    ERRNO_DMS_CALLBACK_STACK_PUSH = 16008,
    ERRNO_DMS_CALLBACK_RC_UNDO_INIT = 16009,
    ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT = 16010,
    ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD = 16011,
    ERRNO_DMS_CALLBACK_GET_DB_HANDLE = 16012,

    /* add new errno above */
    ERRNO_DMS_CALLBACK_END
};

#define ERRNO_DMS_CB_INDEX(x)   ((x) - ERRNO_DMS_CALLBACK_BASE)
#define ERRNO_IS_DMS_CB(x)      ((x) > ERRNO_DMS_CALLBACK_BASE && (x) < ERRNO_DMS_CALLBACK_END)

/* ****BEGIN error code definition of rc function 17001 ~ 18000 **** */
enum en_errno_dms_reform {
    ERRNO_DMS_REFORM_BASE = 17000,
    /* add new errno below */

    ERRNO_DMS_REFORM_GET_RES_DATA_FAILED = 17001,
    ERRNO_DMS_REFORM_SWITCHOVER_NOT_FINISHED = 17002,
    ERRNO_DMS_REFORM_FAIL_GET_STAT_LIST = 17003,
    ERRNO_DMS_REFORM_SWITCHOVER_NOT_REFORMER = 17004,
    ERRNO_DMS_REFORM_NOT_FINISHED = 17005,
    ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED = 17006,
    ERRNO_DMS_REFORM_FAIL = 17007,
    ERRNO_DMS_REFORM_IN_PROCESS = 17008,
    ERRNO_DMS_REFORM_GET_LOCK_FAILED = 17009,

    /* add new errno above */
    ERRNO_DMS_REFORM_END
};
#define ERRNO_DMS_REFORM_INDEX(x)   ((x) - ERRNO_DMS_REFORM_BASE)
#define ERRNO_IS_DMS_REFORM(x)      ((x) > ERRNO_DMS_REFORM_BASE && (x) < ERRNO_DMS_REFORM_END)

const char *dms_get_error_desc(int code);

#define DMS_THROW_ERROR(error_no, ...)                                                                      \
    do {                                                                                                    \
        cm_set_error((char *)__FILE_NAME__, (uint32)__LINE__, (cm_errno_t)error_no,                         \
            dms_get_error_desc(error_no), ##__VA_ARGS__);                                                   \
    } while (CM_FALSE)

#define dms_reset_error     cm_reset_error

#ifdef __cplusplus
}
#endif

#endif /* __DMS_ERROR_H__ */
