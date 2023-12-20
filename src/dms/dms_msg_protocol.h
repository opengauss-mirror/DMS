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
 * dms_msg_protocol.h
 *
 *
 * IDENTIFICATION
 *    src/common/dms_msg_protocol.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DMS_MSG_PROTOCOL_H__
#define __DMS_MSG_PROTOCOL_H__

typedef enum st_dms_protocol_version {
    DMS_PROTO_VER_0 = 0,    // invalid version
    DMS_PROTO_VER_1 = 1,    // first version
    DMS_PROTO_VER_2 = 2,
    DMS_PROTO_VER_NUMS
} dms_protocol_version_t;

#define DMS_INVALID_PROTO_VER DMS_PROTO_VER_0
#define DMS_SW_PROTO_VER      DMS_PROTO_VER_2

typedef enum en_dms_protocol_result {
    DMS_PROTOCOL_VERSION_NOT_MATCH = 0,
    DMS_PROTOCOL_VERSION_NOT_SUPPORT = 1,
} dms_protocol_result_e;

typedef struct st_dms_protocol_result_ack {
    dms_message_head_t head;
    dms_protocol_result_e result;
} dms_protocol_result_ack_t;

static inline bool8 dms_check_if_protocol_compatibility_error(int ret)
{
    if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH || ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT) {
        return CM_TRUE;
    }
    return CM_FALSE;
}

#define DMS_RETURN_IF_PROTOCOL_COMPATIBILITY_ERROR(ret)    \
    do {                                            \
        if (ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_MATCH || ret == ERRNO_DMS_PROTOCOL_VERSION_NOT_SUPPORT) { \
            return ret;                             \
        }                                           \
    } while (0)

// about protocol version
void dms_set_node_proto_version(uint8 inst_id, uint32 version);
uint32 dms_get_node_proto_version(uint8 inst_id);
void dms_init_cluster_proto_version();
uint32 dms_get_send_proto_version_by_cmd(uint32 cmd, uint8 dest_inst);
bool8 dms_check_message_proto_version(dms_message_head_t *head);
uint32 dms_get_forward_request_proto_version(uint8 dst_inst, uint32 recv_req_proto_ver);
void dms_protocol_proc_maintain_version(dms_process_context_t *proc_ctx, dms_message_t *receive_msg);

/****************** A lightweight, universal DMS message version compatibility solution *******************/
typedef struct st_dms_proto_version_attr {
    uint32 req_size;
} dms_proto_version_attr;

const dms_proto_version_attr *dms_get_version_attr(dms_proto_version_attr *version_attrs, uint32 proto_version);
int dms_fill_versioned_msg_head(dms_proto_version_attr *version_attrs, dms_message_head_t *head, uint32 send_version);
int dms_recv_versioned_msg(dms_proto_version_attr *version_attrs, dms_message_t *msg,
    void *out_info, uint32 info_size);

#endif // __DMS_MSG_PROTOCOL_H__