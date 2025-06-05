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
 * dms_param.h
 *
 * IDENTIFICATION
 *    src/param/dms_param.h
 * -------------------------------------------------------------------------
 */
#ifndef DMS_PARAM_H
#define DMS_PARAM_H

#include "cm_config.h"
#include "dms_api.h"
#include "dms_msg.h"
#include "dms_msg_command.h"
#include "cm_types.h"
#include "dms_error.h"
#include "ddes_fault_injection.h"
#include "mes_interface.h"
#include "dms_mfc.h"
#include "mes_func.h"
#include "dms_process.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef status_t (*dms_param_func)(char *value);

status_t dms_update_param(unsigned int index, char *value);
status_t dms_update_connect_url(char *value);
status_t dms_update_elapsed_switch(char *value);
status_t dms_update_drc_mem_max_size(char *value);
#if defined(_DEBUG) || defined(DEBUG) || defined(DB_DEBUG_VERSION)
status_t dms_update_fi_entries_pl(char *value);
status_t dms_update_fi_entries_nl(char *value);
status_t dms_update_fi_entries_cl(char *value);
status_t dms_update_fi_entries_pf(char *value);
status_t dms_update_fi_entries_cf(char *value);
status_t dms_update_fi_entry_value_pl(char *value);
status_t dms_update_fi_entry_value_nl(char *value);
status_t dms_update_fi_entry_value_cl(char *value);
status_t dms_update_fi_entry_value_pf(char *value);
status_t dms_update_fi_entry_value_cf(char *value);
#endif

#ifdef __cplusplus
}
#endif

#endif