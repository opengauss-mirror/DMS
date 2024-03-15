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
 * fault_injection.c
 *
 * Fault categories:
 * - Network
 *   - packet loss
 *   - network latency
 * - CPU
 *   - process latency
 *   - process exit
 * - Customized
 *   - inject customized logic at any location, such as conditional triggering
 *
 * -------------------------------------------------------------------------
 */
#include "fault_injection.h"
#include <float.h>
#include <stdarg.h>
#include "cm_defs.h"
#include "cm_encrypt.h"
#include "cm_log.h"
#include "dms_process.h"
#include "cm_error.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined _DEBUG

static thread_local_var int32 packet_loss_triggered = CM_FALSE;
static thread_local_var int32 custom_triggered = CM_FALSE;

static dms_fi_entry g_fi_entry_dms[DMS_FI_ENTRY_END - DMS_FI_ENTRY_BEGIN] = { 0 };
static dms_fi_entry g_fi_entry_db[FI_ENTRY_END - DB_FI_ENTRY_BEGIN] = { 0 };

dms_fi_type_mapping_t g_fi_type_map[FI_TYPE_NUM_MAX] = {
    {DMS_FI_TYPE_PACKET_LOSS, FI_PACKET_LOSS_FLAG, &g_dms.fi_ctx.ss_fi_packet_loss},
    {DMS_FI_TYPE_NET_LATENCY, FI_NET_LATENCY_FLAG, &g_dms.fi_ctx.ss_fi_net_latency},
    {DMS_FI_TYPE_CPU_LATENCY, FI_CPU_LATENCY_FLAG, &g_dms.fi_ctx.ss_fi_cpu_latency},
    {DMS_FI_TYPE_PROCESS_FAULT, FI_PROCESS_FAULT_FLAG, &g_dms.fi_ctx.ss_fi_process_fault},
    {DMS_FI_TYPE_CUSTOM_FAULT, FI_CUSTOM_FAULT_FLAG, &g_dms.fi_ctx.ss_fi_custom_fault},
};

static inline bool32 dms_fi_entry_type_active(const dms_fi_entry *entry, int type)
{
    int flag = g_fi_type_map[type].fi_flag;
    return entry->faultFlags & flag;
}

static int dms_fi_inject_network_latency(const dms_fi_entry *entry, va_list args)
{
    if (dms_fi_entry_type_active(entry, DMS_FI_TYPE_NET_LATENCY)) {
        LOG_DEBUG_INF("[DMS_FI]entry:%d triggers network latency", entry->pointId);
        cm_sleep(g_fi_type_map[DMS_FI_TYPE_NET_LATENCY].config->fault_value);
    }
    return DMS_SUCCESS;
}

static int dms_fi_inject_cpu_latency(const dms_fi_entry *entry, va_list args)
{
    if (dms_fi_entry_type_active(entry, DMS_FI_TYPE_CPU_LATENCY)) {
        LOG_DEBUG_INF("[DMS_FI]entry:%d triggers cpu latency", entry->pointId);
        cm_sleep(g_fi_type_map[DMS_FI_TYPE_CPU_LATENCY].config->fault_value);
    }
    return DMS_SUCCESS;
}

static int dms_fi_inject_process_fault(const dms_fi_entry *entry, va_list args)
{
    if (dms_fi_entry_type_active(entry, DMS_FI_TYPE_PROCESS_FAULT)) {
        uint32 rand = cm_random(DMS_FI_PROB_ALWAYS);
        uint32 prob = g_fi_type_map[DMS_FI_TYPE_PROCESS_FAULT].config->fault_value;
        if (rand < prob) {
            LOG_RUN_INF("[DMS_FI]entry:%d triggers proc fault exit, %d in %d", entry->pointId, rand, prob);
            cm_exit(0);
        }
    }
    return DMS_SUCCESS;
}

static void dms_fi_inject_pack_loss(const dms_fi_entry *entry, va_list args)
{
    if (dms_fi_entry_type_active(entry, DMS_FI_TYPE_PACKET_LOSS)) {
        uint32 rand = cm_random(DMS_FI_PROB_ALWAYS);
        uint32 prob = g_fi_type_map[DMS_FI_TYPE_PACKET_LOSS].config->fault_value;
        if (rand < prob) {
            va_list apcopy;
            va_copy(apcopy, args);
            unsigned int cmd = (unsigned int)va_arg(apcopy, unsigned int);
            LOG_DEBUG_INF("[DMS_FI]triggers packloss cmd:%u, %d in %d", cmd, rand, prob);
            packet_loss_triggered = CM_TRUE;
            va_end(apcopy);
        }
    }
}

static int dms_fi_inject_custom_fault(dms_fi_entry *entry, va_list args)
{
    if (dms_fi_entry_type_active(entry, DMS_FI_TYPE_CUSTOM_FAULT)) {
        LOG_DEBUG_INF("[DMS_FI]entry:%d triggers cust fault", entry->pointId);
        va_list apcopy;
        va_copy(apcopy, args);
        dms_fi_callback_func callback = (dms_fi_callback_func)va_arg(apcopy, dms_fi_callback_func);
        entry->func = callback;
        entry->func(entry, apcopy);
        va_end(apcopy);
    }
    return DMS_SUCCESS;
}

static void dms_fi_common_injection(dms_fi_entry *entry, va_list args)
{
    dms_fi_inject_network_latency(entry, args);
    dms_fi_inject_cpu_latency(entry, args);
    dms_fi_inject_pack_loss(entry, args);
    dms_fi_inject_process_fault(entry, args);
    dms_fi_inject_custom_fault(entry, args);
}

void fault_injection_call(unsigned int point, ...)
{
    dms_fi_entry *entry = dms_fi_get_entry(point);
    if (entry != NULL && entry->faultFlags) {
        entry->calledCount++;
        va_list args;
        va_start(args, point);
        dms_fi_common_injection(entry, args);
        va_end(args);
    }
}

static int is_valid_entry_point(unsigned int point)
{
    return (point < DMS_FI_ENTRY_END || (point >= DB_FI_ENTRY_BEGIN && point < FI_ENTRY_END));
}

dms_fi_entry *dms_fi_get_entry(unsigned int point)
{
    if (!is_valid_entry_point(point)) {
        return NULL;
    }
    if (point >= DB_FI_ENTRY_BEGIN) {
        return (dms_fi_entry *)&g_fi_entry_db[point - DB_FI_ENTRY_BEGIN];
    }
    return (dms_fi_entry *)&g_fi_entry_dms[point];
}

int dms_fi_get_tls_trigger()
{
    return packet_loss_triggered;
}

void dms_fi_set_tls_trigger(int val)
{
    packet_loss_triggered = val;
}

int dms_fi_get_tls_trigger_custom()
{
    return custom_triggered;
}

void dms_fi_set_tls_trigger_custom(int val)
{
    custom_triggered = val;
}

static int dms_fi_set_type_entries(unsigned int type, unsigned int *entries, unsigned int count)
{
    unsigned int *elist = g_fi_type_map[type].config->entries;
    unsigned int *elist_count = &(g_fi_type_map[type].config->count);
    int flag = g_fi_type_map[type].fi_flag;
    for (unsigned int i = 0; i < count; i++) {
        if (!is_valid_entry_point(entries[i])) {
            LOG_DEBUG_ERR("[DMS_FI] entry idx %u invalid:%u", i, entries[i]);
            return DMS_ERROR;
        }
        LOG_DEBUG_INF("[DMS_FI] entry %u activated, flag %d", entries[i], flag);
        FAULT_INJECTION_ACTIVATE(entries[i], flag);
        elist[i] = entries[i];
    }
    *elist_count = count;
    LOG_DEBUG_INF("[DMS_FI] set entries for type:%u", type);
    return DMS_SUCCESS;
}

static void dms_fi_reset_type_entries(unsigned int type)
{
    unsigned int *elist = g_fi_type_map[type].config->entries;
    unsigned int count = g_fi_type_map[type].config->count;
    for (int i = 0; i < count; ++i) {
        FAULT_INJECTION_INACTIVE(elist[i], g_fi_type_map[type].fi_flag);
    }
    errno_t ret = memset_s(elist, sizeof(int) * MAX_FI_ENTRY_COUNT, 0, sizeof(int) * MAX_FI_ENTRY_COUNT);
    DMS_SECUREC_CHECK(ret);
}

int dms_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count)
{
    if (type >= DMS_FI_TYPE_END) {
        LOG_DEBUG_ERR("[DMS_FI] wrong type");
        return DMS_ERROR;
    }
    dms_fi_reset_type_entries(type);
    return dms_fi_set_type_entries(type, entries, count);
}

int dms_fi_set_entry_value(unsigned int type, unsigned int value)
{
    if (type >= DMS_FI_TYPE_END) {
        LOG_DEBUG_ERR("[DMS_FI] wrong type");
        return DMS_ERROR;
    }
    if (type == DMS_FI_TYPE_PACKET_LOSS || type == DMS_FI_TYPE_PROCESS_FAULT) {
        if (value > DMS_FI_PROB_ALWAYS) {
            LOG_DEBUG_ERR("[DMS_FI] wrong prob value");
            return DMS_ERROR;
        }
    }

    unsigned int *var_ptr = &(g_fi_type_map[type].config->fault_value);
    *var_ptr = value;
    LOG_DEBUG_INF("[DMS_FI] set type %u fault value %u", type, value);
    return DMS_SUCCESS;
}

#else
int dms_fi_set_entries(unsigned int type, unsigned int *entries, unsigned int count) {return DMS_ERROR;}
int dms_fi_set_entry_value(unsigned int type, unsigned int value) {return DMS_ERROR;}
void fault_injection_call(unsigned int point, ...) {}
int dms_fi_get_tls_trigger_custom() {return DMS_ERROR;}
void dms_fi_set_tls_trigger_custom(int val) {}

#endif

#ifdef __cplusplus
}
#endif