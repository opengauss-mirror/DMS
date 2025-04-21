/*
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
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
 * dms_param.c
 *
 * IDENTIFICATION
 *    src/param/dms_param.c
 * -------------------------------------------------------------------------
 */

#include "dms_param.h"


dms_param_func g_dms_param_func[DMS_PARAM_SS_COUNT] = {
    [DMS_PARAM_SS_INTERCONNECT_URL] = dms_update_connect_url,
    [DMS_PARAM_SS_ELAPSED_SWITCH] = dms_update_elapsed_switch,
    [DMS_PARAM_SS_DRC_MEM_MAX_SIZE] = dms_update_drc_mem_max_size,
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
    [DMS_PARAM_SS_FI_PACKET_LOSS_ENTRIES] = dms_update_fi_entries_pl,
    [DMS_PARAM_SS_FI_NET_LATENCY_ENTRIES] = dms_update_fi_entries_nl,
    [DMS_PARAM_SS_FI_CPU_LATENCY_ENTRIES] = dms_update_fi_entries_cl,
    [DMS_PARAM_SS_FI_PROCESS_FAULT_ENTRIES] = dms_update_fi_entries_pf,
    [DMS_PARAM_SS_FI_CUSTOM_FAULT_ENTRIES] = dms_update_fi_entries_cf,
    [DMS_PARAM_SS_FI_PACKET_LOSS_PROB] = dms_update_fi_entry_value_pl,
    [DMS_PARAM_SS_FI_NET_LATENCY_MS] = dms_update_fi_entry_value_nl,
    [DMS_PARAM_SS_FI_CPU_LATENCY_MS] = dms_update_fi_entry_value_cl,
    [DMS_PARAM_SS_FI_PROCESS_FAULT_PROB] = dms_update_fi_entry_value_pf,
    [DMS_PARAM_SS_FI_CUSTOM_FAULT_PARAM] = dms_update_fi_entry_value_cf,
#endif
};

#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t dms_parse_ss_fi_entry_list(char *value, uint32 *entry_list, uint32 *count)
{
    text_t text, entry;

    int32 id = 0;
    *count = 0;

    cm_str2text(value, &text);
    if (cm_text_str_equal_ins(&text, "NULL")) {
        return DMS_SUCCESS;
    }

    while (cm_fetch_text(&text, ',', '\0', &entry)) {
        if (entry.len == 0) {
            continue;
        }

        cm_trim_text(&entry);
        if (entry.len >= CM_MAX_CONFIG_LINE_SIZE) {
            CM_THROW_ERROR(ERR_LINE_TOO_LONG, *count);
            return CM_ERROR;
        }

        if (entry.len == 0) {
            continue;
        }

        CM_RETURN_IFERR(cm_text2int(&entry, &id));

        if (id >= DDES_FI_ENTRY_END || id < 0) {
            CM_THROW_ERROR(ERR_INVALID_PARAMETER_ENUM, "SS_FI_ENTRIES", entry.str);
            return CM_ERROR;
        }

        if (*count >= DDES_FI_ENTRY_COUNT_PER_TYPE) {
            CM_THROW_ERROR(ERR_PARAM_COUNT_OVERFLOW, *count, DDES_FI_ENTRY_COUNT_PER_TYPE);
            return CM_ERROR;
        }
        entry_list[*count] = (uint32)id;
        *count = *count + 1;
    }

    return DMS_SUCCESS;
}

status_t dms_update_fi_entries_pl(char *value)
{
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    CM_RETURN_IFERR(dms_parse_ss_fi_entry_list(value, entries, &count));
    CM_RETURN_IFERR(ddes_fi_set_entries(DDES_FI_TYPE_PACKET_LOSS, entries, count));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entries_nl(char *value)
{
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    CM_RETURN_IFERR(dms_parse_ss_fi_entry_list(value, entries, &count));
    CM_RETURN_IFERR(ddes_fi_set_entries(DDES_FI_TYPE_NET_LATENCY, entries, count));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entries_cl(char *value)
{
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    CM_RETURN_IFERR(dms_parse_ss_fi_entry_list(value, entries, &count));
    CM_RETURN_IFERR(ddes_fi_set_entries(DDES_FI_TYPE_CPU_LATENCY, entries, count));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entries_pf(char *value)
{
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    CM_RETURN_IFERR(dms_parse_ss_fi_entry_list(value, entries, &count));
    CM_RETURN_IFERR(ddes_fi_set_entries(DDES_FI_TYPE_PROCESS_FAULT, entries, count));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entries_cf(char *value)
{
    unsigned int entries[DDES_FI_ENTRY_COUNT_PER_TYPE];
    unsigned int count;
    CM_RETURN_IFERR(dms_parse_ss_fi_entry_list(value, entries, &count));
    CM_RETURN_IFERR(ddes_fi_set_entries(DDES_FI_TYPE_CUSTOM_FAULT, entries, count));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entry_value_pl(char *value)
{
    int32 int_val;
    CM_RETURN_IFERR(cm_str2int(value, &int_val));
    CM_RETURN_IFERR(ddes_fi_set_entry_value(DDES_FI_TYPE_PACKET_LOSS, (unsigned int)int_val));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entry_value_nl(char *value)
{
    int32 int_val;
    CM_RETURN_IFERR(cm_str2int(value, &int_val));
    CM_RETURN_IFERR(ddes_fi_set_entry_value(DDES_FI_TYPE_NET_LATENCY, (unsigned int)int_val));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entry_value_cl(char *value)
{
    int32 int_val;
    CM_RETURN_IFERR(cm_str2int(value, &int_val));
    CM_RETURN_IFERR(ddes_fi_set_entry_value(DDES_FI_TYPE_CPU_LATENCY, (unsigned int)int_val));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entry_value_pf(char *value)
{
    int32 int_val;
    CM_RETURN_IFERR(cm_str2int(value, &int_val));
    CM_RETURN_IFERR(ddes_fi_set_entry_value(DDES_FI_TYPE_PROCESS_FAULT, (unsigned int)int_val));
    return DMS_SUCCESS;
}

status_t dms_update_fi_entry_value_cf(char *value)
{
    int32 int_val;
    CM_RETURN_IFERR(cm_str2int(value, &int_val));
    CM_RETURN_IFERR(ddes_fi_set_entry_value(DDES_FI_TYPE_CUSTOM_FAULT, (unsigned int)int_val));
    return DMS_SUCCESS;
}
#endif

void dms_get_bitmap_inst(uint64 *bitmap, mes_addr_t *inst_net_addr, uint32 node_cnt)
{
    for (uint32 i = 0; i < node_cnt; ++i) {
        bitmap64_set(bitmap, inst_net_addr[i].inst_id);
    }
}

int dms_get_online_inst(uint64 *online_node)
{
    if (dms_reform_in_process()) {
        *online_node = 0;
        return DMS_ERROR;
    }
    *online_node = g_dms.reform_ctx.reform_info.bitmap_in;
    return DMS_SUCCESS;
}

int dms_url_change_check(mes_addr_t *inst_net_addr, uint32 node_cnt)
{
    uint64 bitmap_in = 0;
    if (dms_get_online_inst(&bitmap_in) != DMS_SUCCESS) {
        LOG_RUN_ERR("Cannot alter parameter SS_INTERCONNECT_URL during DMS reform");
        CM_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "alter parameter SS_INTERCONNECT_URL", "DMS reform");
        return DMS_ERROR;
    }
    uint64 bitmap_old = 0;
    uint64 bitmap_new = 0;
    dms_get_bitmap_inst(&bitmap_old, MES_GLOBAL_INST_MSG.profile.inst_net_addr, MES_GLOBAL_INST_MSG.profile.inst_cnt);
    dms_get_bitmap_inst(&bitmap_new, inst_net_addr, node_cnt);
    if (!bitmap64_include(bitmap_new, bitmap_old)) {
        LOG_RUN_ERR("the new inst bitmap must include old inst bitmap. please check");
        CM_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT, "change the node ID or decrease node cnt",
            "the cluster when the URL is changed dynamically");
        return DMS_ERROR;
    }

    int i_old = 0;
    for (int i = 0; i < node_cnt; ++i) {
        if (inst_net_addr[i].inst_id != MES_GLOBAL_INST_MSG.profile.inst_net_addr[i_old].inst_id) {
            continue;
        }
        if (cm_str_equal_ins(inst_net_addr[i].ip, MES_GLOBAL_INST_MSG.profile.inst_net_addr[i_old].ip)
            && inst_net_addr[i].port == MES_GLOBAL_INST_MSG.profile.inst_net_addr[i_old].port) {
            ++i_old;
            continue;
        }
        if (bitmap64_exist(&bitmap_in, (uint8)inst_net_addr[i].inst_id)) {
            LOG_RUN_ERR(
                "The URL of an online node cannot be dynamically modified. You can modify the configuration file "
                "by setting scope=pfile and restart the cluster for the modification to take effect");
            CM_THROW_ERROR(ERR_OPERATIONS_NOT_SUPPORT,
                "dynamic modification of the SS_INTERCONNECT_URL memory ",
                "online node, You can set scope=pfile to modify the configuration file and restart the cluster for "
                "the modification to take effect.");
            return DMS_ERROR;
        }
        ++i_old;
    }
    return DMS_SUCCESS;
}

status_t dms_update_elapsed_switch(char *value)
{
    mfc_set_elapsed_switch((bool32)value[0]);
    return DMS_SUCCESS;
}

status_t dms_update_drc_mem_max_size(char *value)
{
    uint64 val = 0;
    CM_RETURN_IFERR(cm_str2size(value, (int64 *)&val));
    if (g_dms.drc_mem_context == NULL || val == 0) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "SS_DRC_MAX_MEM_SIZE change failed, drc_mem_context is not available");
        return DMS_ERROR;
    }
    g_dms.drc_mem_context->mem_max_size = val;
    return DMS_SUCCESS;
}

status_t dms_update_connect_url(char *value)
{
    errno_t ret;
    uint32 node_cnt = 0;
    char nodes[DMS_MAX_INSTANCES][CM_MAX_IP_LEN];
    uint16 ports[CM_MAX_INSTANCES] = { 0 };
    if (cm_split_mes_urls(nodes, ports, value) != DMS_SUCCESS) {
        DMS_THROW_ERROR(ERRNO_DMS_PARAM_INVALID, "SS_INTERCONNECT_URL change faild");
        return DMS_ERROR;
    }

    mes_addr_t inst_net_addr[DMS_MAX_INSTANCES] = {0};
    for (uint32 i = 0; i < DMS_MAX_INSTANCES; i++) {
        if (ports[i] == 0) {
            continue;
        }
        ret = strncpy_s(inst_net_addr[node_cnt].ip, CM_MAX_IP_LEN, nodes[i], strlen(nodes[i]));
        if (ret != EOK) {
            CM_THROW_ERROR(ERR_SYSTEM_CALL, (ret));
            return DMS_ERROR;
        }
        inst_net_addr[node_cnt].port = ports[i];
        inst_net_addr[node_cnt].inst_id = i;
        inst_net_addr[node_cnt].need_connect = CM_TRUE;
        node_cnt++;
    }

    if (dms_url_change_check(inst_net_addr, node_cnt) != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    if (mes_update_instance(node_cnt, inst_net_addr) != DMS_SUCCESS) {
        LOG_DEBUG_ERR("[DMS] update connect url failed.");
        return DMS_ERROR;
    }
    return DMS_SUCCESS;
}

status_t dms_update_param(uint32 index, char *value)
{
    if (index >= DMS_PARAM_SS_COUNT) {
        return DMS_ERROR;
    }
    return g_dms_param_func[index](value);
}

void dms_update_inst_cnt(unsigned int inst_cnt, unsigned long long int inst_map)
{
    if (inst_cnt != g_dms.inst_cnt || inst_map != g_dms.inst_map) {
        LOG_RUN_INF("[DMS REFORM] change dms inst_cnt from %u to %u, and inst_map from %llu to %llu",
            g_dms.inst_cnt, inst_cnt, g_dms.inst_map, inst_map);
        g_dms.inst_cnt = inst_cnt;
        g_dms.inst_map = inst_map;
    }
}