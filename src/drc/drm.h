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
 * drm.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __DRM_H__
#define __DRM_H__

#include "cm_thread_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DRM_BUFFER_SIZE         SIZE_K(30)

typedef enum en_drm_data_type {
    DRM_DATA_MIGRATE = 0,
    DRM_DATA_RELEASE = 1,

    DRM_DATA_TYPE_COUNT
} drm_data_type_t;

typedef struct st_drm_data {
    uint8               inst_id;                // instance id received from or send to
    uint8               res_type;               // drc type
    uint16              res_len;                // drc len
    uint32              data_type;              // for MIGRATE or RELEASE
    uint32              data_len;               // the len of data
    char                data[DRM_BUFFER_SIZE];  // max size 30K
} drm_data_t;

typedef struct st_drm_group {
    spinlock_t          lock;
    bool8               received;               // indicate if there are any unprocessed data
    uint8               wid;                    // buffer index for receive message
    uint8               unused[2];
    drm_data_t          data[2];
} drm_group_t;

typedef struct st_drm_stat {
    uint64              time_total;
    uint64              time_release;
    uint64              time_migrate;
    uint64              time_collect;
    uint32              count_release;
    uint32              count_migrate;
    uint32              count_collect;
    uint32              count_wait;
} drm_stat_t;

typedef struct st_drm {
    thread_t            thread;
    thread_stat_t       status;
    cm_event_t          event;
    drm_group_t         release;                // received from current master
    drm_group_t         migrate;                // received from old master
    drm_data_t          send_data;           // for current master, cache drc which will be sent to old master
    drm_stat_t          stat;
    bool8               trigger;
    bool8               inited;
    uint16              part_id;
} drm_t;

bool8 drc_cmp_part_info(void);
void drm_release_drc(char *data, uint16 len, uint8 type, uint8 options);
void drm_thread_set_pause(void);
void drm_thread_set_running(void);
int drm_thread_init(void);
void drm_thread_deinit(void);
void drm_trigger(void);
bool8 drm_create(char* resid, uint16 len, uint8 res_type);

#ifdef __cplusplus
}
#endif

#endif /* __DRM_H__ */