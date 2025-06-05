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
 * drc_page.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_page.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DRC_PAGE_H__
#define __DRC_PAGE_H__

#include "drc.h"
#include "dms.h"
#include "dms_error.h"
#include "cm_date.h"
#include "cm_timer.h"
#include "drc_res_mgr.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline bool32 if_cvt_need_confirm(drc_cvt_item_t *converting)
{
    if (((g_timer()->monotonic_now - converting->begin_time) / (int64)MICROSECS_PER_MILLISEC) > DMS_CVT_EXPIRE_TIME) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

void drc_release_by_part(drc_part_list_t *part, uint8 type);
int drc_request_page_owner(dms_process_context_t *ctx, char* resid, uint16 len, uint8 res_type,
    drc_request_info_t* req_info, drc_req_owner_result_t* result);
int32 drc_claim_page_owner(claim_info_t* claim_info, cvt_info_t* cvt_info);
void drc_add_edp_map(drc_page_t *drc_page, uint8 inst_id, uint64 lsn);
void drc_cancel_request_res(char *resid, uint16 len, uint8 res_type, drc_request_info_t *req, cvt_info_t* cvt_info);
void drc_convert_page_owner(drc_head_t *drc, claim_info_t* claim_info, cvt_info_t* cvt_info);
bool8 drc_cancel_converting(drc_head_t *drc, drc_request_info_t *req, cvt_info_t* cvt_info);
bool8 drc_chk_4_release(char *resid, uint16 len, uint8 inst_id);
void dms_get_buf_res(uint64 *index, dv_drc_buf_info *res_buf_info, int drc_type);
bool8 drc_chk_page_ownership(char* resid, uint16 len, uint8 inst_id, uint8 curr_mode);
int drc_get_no_owner_id(void *db_handle, drc_head_t *drc, uint8 *owner_id);

#ifdef __cplusplus
}
#endif

#endif /* __DRC_LOCK_H__ */