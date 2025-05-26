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
 * cmpt_msg_drm.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_drm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_DRM_H__
#define __CMPT_MSG_DRM_H__

#include "cmpt_msg_common.h"
#include "drc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_XA_SIZE             sizeof(drc_global_xid_t)

typedef struct st_drm_migrate_page {
    char                resid[DMS_PAGEID_SIZE];
    uint8               owner;
    uint8               lock_mode;
    uint8               last_edp;
    uint8               unused;
    uint64              copy_insts;
    uint64              last_edp_lsn;
    uint64              edp_map;
    uint64              seq;
    drc_cvt_item_t      converting;
} drm_migrate_page_t;

typedef struct st_drm_migrate_lock {
    char                resid[DMS_DRID_SIZE];
    uint8               owner;
    uint8               lock_mode;
    uint16              unused;
    uint64              copy_insts;
    drc_cvt_item_t      converting;
} drm_migrate_lock_t;

typedef struct st_drm_migrate_alock {
    char                resid[DMS_ALOCKID_SIZE];
    uint8               owner;
    uint8               lock_mode;
    uint16              unused;
    uint64              copy_insts;
    drc_cvt_item_t      converting;
} drm_migrate_alock_t;

typedef struct st_drm_migrate_xa {
    char                resid[DMS_XA_SIZE];
    uint8               owner;
    uint8               unused[3];
} drm_migrate_xa_t;

#define DRM_RESID_LEN       sizeof(drc_global_xid_t)

typedef struct st_dms_req_drc_migrate {
    dms_message_head_t  head;
    char                data[DRM_RESID_LEN];
    uint16              len;
    uint8               type;
    uint8               options;
} dms_req_drc_migrate_t;

typedef struct st_dms_ack_drc_migrate {
    dms_message_head_t  head;
    uint64              edp_map;
    uint64              last_edp_lsn;
    uint64              seq;
    uint64              copy_insts;
    drc_cvt_item_t      converting;
    uint8               owner;
    uint8               lock_mode;
    uint8               last_edp;
    uint8               exist;
    uint32              ret;
} dms_ack_drc_migrate_t;

typedef struct st_dms_notify_old_master {
    dms_message_head_t  head;
    char                data[DRM_RESID_LEN];
    uint16              len;
    uint8               type;
    uint8               options;
} dms_notify_old_master_t;

typedef struct st_drm_req_data {
    dms_message_head_t  head;
    uint8               inst_id;
    uint8               res_type;
    uint16              res_len;
    uint32              data_type;
    uint32              data_len;
} drm_req_data_t;

typedef struct st_drm_ack_finish {
    dms_message_head_t  head;
    bool32              trigger;
} drm_ack_finish_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_DRM_H__