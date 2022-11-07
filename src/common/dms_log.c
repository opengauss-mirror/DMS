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
 * dms_log.c
 *
 *
 * IDENTIFICATION
 *    src/common/dms_log.c
 *
 * -------------------------------------------------------------------------
 */


#include "dms_log.h"
#include "cm_debug.h"
#include "cm_hash.h"
#include "dms.h"
#include "dms_cm.h"

#ifdef __cplusplus
extern "C" {
#endif

cm_hash_pool_t *g_dms_error_desc_pool = NULL;


dms_error_desc_t g_dms_error_desc[] = {
    /* ****BEGIN error code definition of dms common 10001 ~ 11000 ************* */
    {ERRNO_DMS_SECUREC_CHECK_FAIL, "Common copy fail"},
    {ERRNO_DMS_COMMON_MSG_ACK, "Common msg ack fail, reason %s"},
    {ERRNO_DMS_PARAM_NULL, "dms param is null"},
    {ERRNO_DMS_CMD_INVALID, "dms cmd is invalid, cmd is %d"},
    {ERRNO_DMS_ALLOC_FAILED, "dms alloc failed"},
    {ERRNO_DMS_MEMSET_FAILED, "dms memset failed"},
    {ERRNO_DMS_PARAM_INVALID, "dms param is invalid, param = %d"},
    {ERRNO_DMS_CAPABILITY_NOT_SUPPORT, "dms not support this capability, type = %d"},
    {ERRNO_DMS_COMMON_COPY_PAGEID_FAIL, "copy pageid fail, pageid is %s"},
    {ERRNO_DMS_SEND_MSG_FAILED, "send msg failed,errcode:%d, cmd:%u, dst_inst:%u"},
    {ERRNO_DMS_RECV_MSG_FAILED, "recv msg failed,errcode:%d, cmd:%u, dst_inst:%u"},
    {ERRNO_DMS_COMMON_CBB_FAILED, "Common cbb api fail, cbb error code id %d"},
    /* ****BEGIN error code definition of dms dcs 11001 ~ 13000 ************* */
    {ERRNO_DMS_DCS_PAGE_MASTER_ID, "dms get page master id fail"},
    {ERRNO_DMS_DCS_MSG_EAGAIN, "failed to send ask master request"},
    {ERRNO_DMS_DCS_READ_LOCAL_PAGE, "dms read local page fail"},
    {ERRNO_DMS_DCS_BROADCAST_FAILED, "dms boardcast fail"},
    {ERRNO_DMS_DCS_GET_TXN_INFO_FAILED, "dms get txn info fail"},
    {ERRNO_DMS_DCS_GET_TXN_SNAPSHOT_FAILED, "dms get txn snapshot fail"},
    {ERRNO_DMS_DCS_SEND_EDP_FAILED, "dms send edp failed"},
    {ERRNO_DMS_DCS_BOC_FAILED, "dms broadcast fail , invalid instance = %d, success instance = %d"},
    {ERRNO_DMS_DCS_PAGE_REQUEST_FAILED, "invokes DCS page request fail"},

    /* ****BEGIN error code definition of dms drc 13001 ~ 15000 ************* */
    {ERRNO_DMS_DRC_RES_SIZE_TOO_SMALL, "resources size too small, res_size = %d"},
    {ERRNO_DMS_DRC_REQ_OWNER_TYPE_NOT_EXPECT, "dms request omner type is invalid, type = %d"},
    {ERRNO_DMS_DRC_PAGE_POOL_CAPACITY_NOT_ENOUGH, "page pool has no enough capacity"},
    {ERRNO_DMS_DRC_ENQ_ITEM_CAPACITY_NOT_ENOUGH, "enq item has no enough capacity"},
    {ERRNO_DMS_DRC_PAGE_NOT_FOUND, "drc page not found"},
    {ERRNO_DMS_DRC_LOCKITEM_CAPACITY_NOT_ENOUGH, "lock item has no enough capacity"},
    {ERRNO_DMS_DRC_LOCK_CONVERT_QUEUE_ABNORMAL, "lock convert queue abnormal"},
    {ERRNO_DMS_DRC_LOCK_NOT_FOUND, "lock resorce not found"},
    {ERRNO_DMS_DRC_LOCK_ABANDON_TRY, "abandon to try lock"},
    {ERRNO_DMS_DRC_LOCK_DEAD_LOCK, "dms lock dead lock"},
    {ERRNO_DMS_DRC_PAGE_OWNER_NOT_FOUND, "page owner not found, pageid is %s"},
    {ERRNO_DMS_DRC_PAGE_MASTER_NOT_FOUND, "page master not found, pageid is %s"},
    {ERRNO_DMS_DRC_CONFLICT_WITH_OWNER, "dms req conflict with owner"},
    {ERRNO_DMS_DRC_CONFLICT_WITH_OTHER_REQER, "dms req conflict with other requester"},
    {ERRNO_DMS_DRC_REMASTER_IN_MIGRATE, "remaster in migrate, remaster status = %d"},
    {ERRNO_DMS_DRC_CONFLICT_WITH_INVALID_PAGE, "dms req conflict with invalid page"},
    {ERRNO_DMS_DRC_RECOVERY_SET_FAIL, "fail to create recovery set"},
    {ERRNO_DMS_DRC_RECOVERY_PAGE, "page in recovery set, please try again, pageid is %s"},
    {ERRNO_DMS_DRC_LOCK_STATUS_FAIL, "lock status fail"},
    {ERRNO_DMS_REFORM_FAIL, "reform failed"},
    {ERRNO_DMS_REFORM_IN_PROCESS, "reform is in progress"},
    {ERRNO_DMS_DRC_INVALID_REPEAT_REQUEST, "invalid repeat request" },

    /* ****BEGIN error code definition of dms dls 15001 ~ 16000 ************* */
    {ERRNO_DMS_DLS_TRY_RELEASE_LOCK_FAILED, "dms try release lock fail"},
    {ERRNO_DMS_DLS_INFORM_NEW_OWNERS_FAILED, "dms try inform lock new owner fail, \
                                             lock_id:(%u/%u/%u/%u/%u), new_owner_map:%llu"},

    /* ****BEGIN error code definition of dms callback function 16001 ~ 17000 ************* */
    {ERRNO_DMS_CALLBACK_ALLOC_CR_CURSOR, "dms callback alloc cr cursor is null"},
    {ERRNO_DMS_CALLBACK_GET_HEAP_INVISIBLE_TXN_LIST, "dms callback get heap invisible txn list fail, \
                                                                        ret = %d"},
    {ERRNO_DMS_CALLBACK_GET_INDEX_INVISIBLE_TXN_LIST, "dms callback get index invisible txn list fail, \
                                                                        ret = %d"},
    {ERRNO_DMS_CALLBACK_REORGANIZE_HEAP_PAGE_WITH_UNDO, "dms callback reorganize heap page with undo \
                                                                        list fail, ret = %d"},
    {ERRNO_DMS_CALLBACK_REORGANIZE_INDEX_PAGE_WITH_UNDO, "dms callback reorganize index page with undo \
                                                                        list fail, ret = %d"},
    {ERRNO_DMS_CALLBACK_READ_PAGE, "dms callback read page fail"},
    {ERRNO_DMS_CALLBACK_CHECK_HEAP_PAGE_VISIBLE_WITH_UDSS, "dms callback check heap page visible with udss"},
    {ERRNO_DMS_CALLBACK_STACK_PUSH, "dms callback stack push fail"},
    {ERRNO_DMS_CALLBACK_RC_UNDO_INIT, "dms callback rc undo init fail"},
    {ERRNO_DMS_CALLBACK_RC_TX_AREA_INIT, "dms callback rc transaction area init fail"},
    {ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD, "dms callback rc transaction area load fail"},

    /* ****BEGIN error code definition of rc function 17001 ~ 18000 ************* */
    {ERRNO_DMS_RC_GET_RES_DATA_FAILED, "failed to read data from cms: %s"},
    {ERRNO_DMS_RC_BROADCAST_INSTMAP_FAILED, "rc broadcast instmap failed, invalid instance = %d, success instance = %d"}

};

static inline bool32 dms_desc_match_data(void *data, void *item)
{
    uint32 data_code = (*(dms_error_desc_t *)data).code;
    uint32 item_code = (*(dms_error_desc_t *)item).code;
    return data_code == item_code;
}

static inline uint32 dms_desc_hash_data(void *data)
{
    dms_error_desc_t *tmpdata = (dms_error_desc_t *)data;
    return cm_hash_uint32_shard((uint32)tmpdata->code);
}

status_t dms_init_error_desc(void)
{
    int32 ret;
    cm_hash_profile_t dms_desc;
    dms_desc.bucket_num = DMS_DESC_HASH_BUCKET_NUM;
    dms_desc.entry_size = (uint32)sizeof(dms_error_desc_t);
    dms_desc.max_num = DMS_DESC_MAX_ENTRY_NUM;
    dms_desc.cb_match_data = dms_desc_match_data;
    dms_desc.cb_hash_data = dms_desc_hash_data;
    MEMS_RETURN_IFERR(strncpy_sp(dms_desc.name, DMS_ERROR_DESC_POOL_NAME_SIZE, "dms desc hash pool",
        sizeof("dms desc hash pool") - 1));

    g_dms_error_desc_pool = (cm_hash_pool_t *)malloc(sizeof(cm_hash_pool_t));
    CM_CHECK_NULL_PTR(g_dms_error_desc_pool);
    ret = cm_hash_pool_create(&dms_desc, g_dms_error_desc_pool);
    if (ret != DMS_SUCCESS) {
        CM_FREE_PTR(g_dms_error_desc_pool);
        LOG_RUN_ERR("dms_init_error_desc failed.ret = %d", ret);
        return ret;
    }
    for (uint32 i = 0; i < (sizeof(g_dms_error_desc) / sizeof(dms_error_desc_t)); i++) {
        ret = cm_hash_pool_add(g_dms_error_desc_pool, &g_dms_error_desc[i]);
        if (ret != DMS_SUCCESS) {
            dms_uninit_error_desc();
            LOG_RUN_ERR("dms_init_error_desc failed.ret = %d", ret);
        }
    }
    return ret;
}

void dms_uninit_error_desc(void)
{
    if (g_dms_error_desc_pool == NULL) {
        return;
    }

    cm_hash_pool_destory(g_dms_error_desc_pool);
    CM_FREE_PTR(g_dms_error_desc_pool);
}

void dms_get_error_desc(uint32 code, char *errmsg)
{
    uint64 tmpcode = code;
    int ret;
    uint32 size;
    dms_error_desc_t *entry = NULL;
    entry = (dms_error_desc_t *)cm_hash_pool_match_nolock(g_dms_error_desc_pool, (void *)&tmpcode);
    if (entry == NULL) {
        LOG_RUN_ERR("dms_get_error_desc failed.entry is null");
        errmsg[0] = '\0';
        CM_ASSERT(0);
        return;
    }
    size = (uint32)strlen(entry->desc);
    if (size >= DMS_ERROR_DESC_SIZE) {
        LOG_RUN_ERR("dms_get_error_desc failed.err msg too long. error : %u, errmsg : %s", code, entry->desc);
    }
    uint32 copy_size =
        (size > (DMS_ERROR_DESC_SIZE - DMS_ONE_BYTE_SIZE) ? (DMS_ERROR_DESC_SIZE - DMS_ONE_BYTE_SIZE) : size);
    ret = memcpy_sp(errmsg, DMS_ERROR_DESC_SIZE, entry->desc, copy_size);
    errmsg[copy_size] = '\0';
    CM_ASSERT(ret == DMS_SUCCESS);
    return;
}

void dms_get_error(int *errcode, const char **errmsg)
{
    cm_get_error(errcode, errmsg);
    if ((*errcode < ERRNO_DMS_SECUREC_CHECK_FAIL) || (*errcode > ERRNO_DMS_CALLBACK_RC_TX_AREA_LOAD)) {
        *errcode = -1;
        *errmsg = "Failed to get dms errcode";
    }
}

#ifdef __cplusplus
}
#endif
