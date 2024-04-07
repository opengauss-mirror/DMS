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
 * dms_reform_drc_repair.c
 *
 *
 * IDENTIFICATION
 *    src/rc/dms_reform_drc_repair.c
 *
 * -------------------------------------------------------------------------
 */

#include "dms_reform_proc.h"
#include "dms_reform_msg.h"

static int dms_reform_repair_new_item(uint8 thread_index, drc_buf_res_t *buf_res, page_action_t action)
{
    repair_item_t item;
    uint8 dst = buf_res->claimed_owner;

    item.action = action;
    (void)memcpy_s(item.page_id, DMS_PAGEID_SIZE, buf_res->data, DMS_PAGEID_SIZE);

    return dms_reform_req_group(MSG_REQ_REPAIR_NEW, dst, thread_index, (void *)&item, sizeof(repair_item_t));
}

static int dms_reform_repair_new_item_list(uint8 thread_index, bilist_t *list, page_action_t action)
{
    bilist_node_t *node = cm_bilist_head(list);
    drc_buf_res_t *buf_res = NULL;
    int ret = DMS_SUCCESS;

    while (node != NULL) {
        buf_res = DRC_RES_NODE_OF(drc_buf_res_t, node, rebuild_node);
        DRC_DISPLAY(buf_res, "repair_new");
        ret = dms_reform_repair_new_item(thread_index, buf_res, action);
        DMS_RETURN_IF_ERROR(ret);
        node = BINODE_NEXT(node);
    }

    return DMS_SUCCESS;
}

int dms_reform_repair_by_partid(uint8 thread_index, uint16 part_id)
{
    reform_info_t *reform_info = DMS_REFORM_INFO;
    drc_part_list_t *list_flush_copy = &reform_info->normal_copy_lists[part_id];
    return dms_reform_repair_new_item_list(thread_index, &list_flush_copy->list, DMS_REQ_FLUSH_COPY);
}

static int dms_reform_repair_inner(void)
{
    drc_part_mngr_t *part_mngr = DRC_PART_MNGR;
    drc_inst_part_t *inst_part = &part_mngr->inst_part_tbl[g_dms.inst_id];
    uint16 part_id = inst_part->first;
    int ret = DMS_SUCCESS;

    dms_reform_req_group_init(CM_INVALID_ID8);
    for (uint8 i = 0; i < inst_part->count; i++) {
        ret = dms_reform_repair_by_partid(CM_INVALID_ID8, part_id);
        DMS_RETURN_IF_ERROR(ret);
        part_id = part_mngr->part_map[part_id].next;
    }
    if (ret == DMS_SUCCESS) {
        ret = dms_reform_req_group_send_rest(CM_INVALID_ID8);
    }
    dms_reform_req_group_free(CM_INVALID_ID8);
    return ret;
}

int dms_reform_repair(void)
{
    int ret = DMS_SUCCESS;

    LOG_RUN_FUNC_ENTER;
    ret = dms_reform_repair_inner();
    if (ret != DMS_SUCCESS) {
        LOG_RUN_FUNC_FAIL;
        return ret;
    }
    dms_reform_next_step();
    LOG_RUN_FUNC_SUCCESS;
    return DMS_SUCCESS;
}