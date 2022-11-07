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
} drc_txn_res_t;

drc_txn_res_t *drc_create_txn_res(uint64 *xid, dms_res_type_e res_type);
void drc_release_txn_res(drc_txn_res_t *txn_res);
void drc_enqueue_txn(uint64 *xid, uint8 inst_id);
bool8 drc_local_txn_wait(uint64 *xid);
void drc_local_txn_recycle(uint64 *xid);
void drc_local_txn_awake(uint64 *xid);

#ifdef __cplusplus
}
#endif
#endif