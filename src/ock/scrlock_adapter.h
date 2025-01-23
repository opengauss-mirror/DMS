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
 * scrlock_adapter.h
 *
 *
 * IDENTIFICATION
 *    src/ock/scrlock_adapter.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SCRLOCK_ADAPTER_H__
#define __SCRLOCK_ADAPTER_H__

#include "dms_api.h"
#include "scrlock.h"

/*
 * @brief scrlock init
 * @[in]param profile -  config value
 * @return DMS_SUCCESS - success;otherwise: failed
 */
int dms_scrlock_init(dms_profile_t *dms_profile);

/*
 * @brief scrlock reinit for failure recovery
 * @[in]param profile -  config value
 * @[in]param active_node_num -  alive node num
 * @return DMS_SUCCESS - success;otherwise: failed
 */
unsigned char dms_scrlock_reinit();

/*
 * @brief scrlock stop server thread
 * @return
 */
void dms_scrlock_stop_server();

/*
 * @brief scrlock uninit
 * @return
 */
void dms_scrlock_uninit();

/*
 * @brief distributed scrlock exclusive acquire timeout method.
 * @param dms_ctx - dms_context_t structure.
 * @param dlatch - distributed resource lock identifier.
 * @param wait_ticks - timeout ticks.
 * @param is_force - whether force to shared mode when contention with exclusive mode.
 * @return CM_TRUE acquire success; CM_FALSE acquire failed.
 */
unsigned char dms_scrlock_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks);

/*
 * @brief distributed scrlock shared acquire timeout method.
 * @param dms_ctx - dms_context_t structure.
 * @param dlatch - distributed resource lock identifier.
 * @param wait_ticks - timeout ticks.
 * @param is_force - whether force to shared mode when contention with exclusive mode.
 * @return CM_TRUE acquire success; CM_FALSE acquire failed.
 */
unsigned char dms_scrlock_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks);

/*
 * @brief distributed scrlock release method.
 * @param dms_ctx - dms_context_t structure.
 * @param dlatch - distributed resource lock identifier.
 * @return
 */
void dms_scrlock_unlock(dms_context_t *dms_ctx, dms_drlatch_t *dlatch);

/*
 * @brief distributed scrlock event stat.
 * @param event_type - SCRLockEvent enum.
 * @param event_cnt - get scrlock event count.
 * @param event_time - get scrlock event total time.
 * @return
 */
void dms_scrlock_get_event(SCRLockEvent event_type, unsigned long long *event_cnt, unsigned long long *event_time);

/*
 * @brief distributed scrlock event stat adapt dms event stat.
 * @param event - dms_wait_event_t  dms event stat.
 * @return SCRLockEvent - scrlock event stat.
 */
SCRLockEvent dms_scrlock_events_adapt(dms_wait_event_t event);

#endif