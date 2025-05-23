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
 * drc_tran.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drc_tran.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DRC_TRAN_H__
#define __DRC_TRAN_H__

#include "drc.h"
#include "dms.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_drc_txn_res {
    bilist_node_t node;
    dms_res_type_e res_type;
    uint64 res_id;
    uint64 inst_map;
    cm_thread_cond_t cond;
    bool8 is_cond_inited;
    uint8 unused[3];
    atomic32_t ref_count; // just maintained when local txn
} drc_txn_res_t;

drc_txn_res_t *drc_create_txn_res(uint64 *xid, dms_res_type_e res_type);
void drc_release_txn_res(drc_txn_res_t *txn_res);
int32 drc_enqueue_txn(void *db_handle, uint64 *xid, uint8 inst_id, dms_txn_info_t *txn_info);
bool8 drc_local_txn_wait(uint64 *xid);
void drc_local_txn_recycle(uint64 *xid);
void drc_local_txn_awake(uint64 *xid);
uint16 drc_get_xa_partid(drc_global_xid_t *xid);
int32 drc_get_xa_master_id(drc_global_xid_t *global_xid, uint8 *master_id);
int32 drc_get_xa_old_master_id(drc_global_xid_t *xid, uint8 *master_id);
int32 drc_xa_create(void *db_handle, dms_session_e sess_type, uint32 sess_id, drc_global_xid_t *xid, uint8 owner_id);
int32 drc_xa_delete(drc_global_xid_t *xid);

#ifdef __cplusplus
}
#endif
#endif