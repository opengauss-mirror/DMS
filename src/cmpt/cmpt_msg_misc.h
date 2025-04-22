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
 * cmpt_msg_misc.h
 *
 *
 * IDENTIFICATION
 *    src/cmpt/cmpt_msg_misc.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CMPT_MSG_MISC_H__
#define __CMPT_MSG_MISC_H__

#include "cmpt_msg_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
* The following structs are used for communication
* between Primary and Standby to obtain relevant
* information about buffers on other nodes.
*/
typedef struct st_dms_req_buf_info {
    dms_message_head_t      head;
    unsigned long long      copy_insts;
    unsigned char           claimed_owner;
    unsigned char           master_id;
    unsigned char           from_inst;
    char                    resid[DMS_RESID_SIZE];
} dms_req_buf_info_t;

typedef struct st_dms_ack_buf_info {
    dms_message_head_t      head;
    stat_buf_info_t         buf_info;
} dms_ack_buf_info_t;

typedef struct st_dcs_boc_req {
    dms_message_head_t head;
    uint64 commit_scn;
    uint64 min_scn;
    uint32 inst_id;
    uint64 lsn;
} dcs_boc_req_t;

#ifdef __cplusplus
}
#endif

#endif // __CMPT_MSG_MISC_H__