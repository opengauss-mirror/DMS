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
 * dms_errno.h
 *
 *
 * IDENTIFICATION
 *    src/interface/dms_errno.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_ERRNO_H__
#define __DMS_ERRNO_H__

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_SUCCESS 0

// DMS ERRNO: 10001 - 20000

/* ****BEGIN error code definition of dms common 10001 ~ 11000 ************* */
#define ERRNO_DMS_SECUREC_CHECK_FAIL       10001
#define ERRNO_DMS_COMMON_MSG_ACK           10002
#define ERRNO_DMS_PARAM_NULL               10003
#define ERRNO_DMS_CMD_INVALID              10004
#define ERRNO_DMS_ALLOC_FAILED             10005
#define ERRNO_DMS_MEMSET_FAILED            10006
#define ERRNO_DMS_PARAM_INVALID            10007
#define ERRNO_DMS_CAPABILITY_NOT_SUPPORT   10008
#define ERRNO_DMS_COMMON_COPY_PAGEID_FAIL  10009
#define ERRNO_DMS_SEND_MSG_FAILED          10010
#define ERRNO_DMS_RECV_MSG_FAILED          10011
#define ERRNO_DMS_COMMON_CBB_FAILED        10012
#define ERRNO_DMS_MFC_NO_TICKETS           10013
#define ERRNO_DMS_MES_INVALID_MSG          10014
#define ERRNO_DMS_RES_INVALID_VERSION      10015

/* ****BEGIN error code definition of dms dcs 11001 ~ 13000 ************* */
#define ERRNO_DMS_DCS_PAGE_MASTER_ID       11001
#define ERRNO_DMS_DCS_MSG_EAGAIN           11002
#define ERRNO_DMS_DCS_READ_LOCAL_PAGE      11003
#define ERRNO_DMS_DCS_BROADCAST_FAILED     11004
#define ERRNO_DMS_DCS_GET_TXN_INFO_FAILED  11005
#define ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED 11006
#define ERRNO_DMS_DCS_SEND_EDP_FAILED         11007
#define ERRNO_DMS_DCS_BOC_FAILED              11008
#define ERRNO_DMS_DCS_GET_UPDATE_XID_FAILED   11009
#define ERRNO_DMS_DCS_PAGE_REQUEST_FAILED     11010
#define ERRNO_DMS_DCS_GET_TXN_STATUS_FAILED   11011
#define ERRNO_DMS_DCS_GET_XID_CSN_FAILED      11012
#define ERRNO_DMS_DCS_LOCK_BUFFER_FAILED      11013

/* ****BEGIN error code definition of dms drc 13001 ~ 15000 ************* */
#define ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL               13001
#define ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT        13002
#define ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH    13003
#define ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH     13004
#define ERRNO_DMS_DRC_PAGE_NOT_FOUND                   13005
#define ERRNO_DMS_DRC_LOCKITEM_CAPACITY_NOT_ENOUGH     13006
#define ERRNO_DMS_DRC_LOCK_CONVERT_QUEUE_ABNORMAL      13007
#define ERRNO_DMS_DRC_LOCK_NOT_FOUND                   13008
#define ERRNO_DMS_DRC_LOCK_ABANDON_TRY                 13009
#define ERRNO_DMS_DRC_LOCK_DEAD_LOCK                   13010
#define ERRNO_DMS_DRC_PAGE_OWNER_NOT_FOUND             13011
#define ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND            13012
#define ERRNO_DMS_DRC_CONFLICT_WITH_OWNER              13013
#define ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER        13014
#define ERRNO_DMS_DRC_REMASTER_IN_MIGRATE              13015
#define ERRNO_DMS_DRC_CONFLICT_WITH_INVALID_PAGE       13016
#define ERRNO_DMS_DRC_RECOVERY_SET_FAIL                13017
#define ERRNO_DMS_DRC_RECOVERY_PAGE                    13018
#define ERRNO_DMS_DRC_LOCK_STATUS_FAIL                 13019
#define ERRNO_DMS_REFORM_FAIL                          13020
#define ERRNO_DMS_REFORM_IN_PROCESS                    13021
#define ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST           13022
#define ERRNO_DMS_DRC_INVALID_CLAIM_REQUEST            13023
#define ERRNO_DMS_DRC_INVALID                          13024

/* ****BEGIN error code definition of dms dls 15001 ~ 16000 ************* */
#define ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED          15001
#define ERRNO_DMS_DLS_INFORM_NEW_OWNERS_FAILED         15002
#define ERRNO_DMS_DLS_TRY_LOCK_FAILED                  15003

/* ****BEGIN error code definition of dms callback function 16001 ~ 17000 ************* */
#define ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR                      16001
#define ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST          16002
#define ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST         16003
#define ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO       16004
#define ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO      16005
#define ERRNO_DMS_CALLBACK_READ_PAGE                            16006
#define ERRNO_DMS_CALLBACK_CHECK_HEAP_PAGE_VISIBLE_WITH_UDSS    16007
#define ERRNO_DMS_CALLBACK_STACK_PUSH                           16008
#define ERRNO_DMS_CALLBACK_RC_UNDO_INIT                         16009
#define ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT                      16010
#define ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD                      16011
#define ERRNO_DMS_CALLBACK_GET_DB_HANDLE                        16012


/* ****BEGIN error code definition of rc function 17001 ~ 18000 ************* */
#define ERRNO_DMS_RC_GET_RES_DATA_FAILED                        17001
#define ERRNO_DMS_RC_BROADCAST_INSTMAP_FAILED                   17002
#define ERRNO_DMS_SWITCHOVER_NOT_FINISHED                       17003
#define ERRNO_DMS_FAIL_GET_STAT_LIST                            17004
#define ERRNO_DMS_SWITCHOVER_NOT_REFORMER                       17005
#define ERRNO_DMS_REFORM_NOT_FINISHED                           17006
#define ERRNO_DMS_REFORM_SAVE_LIST_STABLE_FAILED                17007
#ifdef __cplusplus
}
#endif

#endif /* __DMS_ERRNO_H__ */

