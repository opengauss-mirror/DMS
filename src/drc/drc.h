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
 * drc.h
 *
 *
 * IDENTIFICATION
 *    src/drc/drc.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __DRC_H__
#define __DRC_H__

#include "cm_bilist.h"
#include "cm_hash.h"
#include "cm_spinlock.h"
#include "dms_cm.h"
#include "dms.h"
#include "mes_type.h"
#include "cm_chan.h"
#include "cm_thread.h"
#include "cm_latch.h"
#include "cm_date.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DMS_DRC_SHORT_SLEEP cm_sleep(10)
#define DRC_RES_CTX (&g_drc_res_ctx)
#define DRC_PART_MNGR (&g_drc_res_ctx.part_mngr)
#define DRC_PART_REMASTER_MNGR (&g_drc_res_ctx.part_mngr.remaster_mngr)
#define DRC_PART_MASTER_ID(part_id) (g_drc_res_ctx.part_mngr.part_map[(part_id)].inst_id)
#define DRC_DEFAULT_LOCK_RES_NUM (SIZE_M(1))
#define DRC_RES_NODE_OF(type, node, field) ((type *)((char *)(node) - OFFSET_OF(type, field)))
#define DRC_RES_EXTEND_MAX_NUM 3
#define DRC_RES_EXTEND_TRY_TIMES 3
#define DRC_SMON_QUEUE_SIZE 10000
#define DRC_BUF_RES_MAP (&g_drc_res_ctx.global_buf_res.res_map)
#define DRC_BUF_RES_POOL (&g_drc_res_ctx.global_buf_res.res_map.res_pool)
#define DRC_LOCK_RES_MAP (&g_drc_res_ctx.global_lock_res.res_map)
#define DRC_LOCK_RES_POOL (&g_drc_res_ctx.global_lock_res.res_map.res_pool)
#define DRC_GLOBAL_RES_MAP(res_type) ((res_type) == (uint8)DRC_RES_PAGE_TYPE ? &g_drc_res_ctx.global_buf_res : \
    &g_drc_res_ctx.global_lock_res)
#define DRC_RECYCLE_THRESHOLD 0.8 /* hardcoded to 80% res pool usage */
#define DRC_RECYCLE_GREEDY_CNT 0 /* recycle as many as possible */
#define DRC_RECYCLE_ONE_CNT 1

typedef enum {
    DMS_RES_TYPE_IS_PAGE = 0,
    DMS_RES_TYPE_IS_LOCK = 1,
    DMS_RES_TYPE_IS_TXN = 2,
    DMS_RES_TYPE_IS_LOCAL_TXN = 3
} dms_res_type_e;

typedef struct st_drc_res_pool {
    spinlock_t  lock;
    bool32      inited;
    bilist_t    free_list;
    uint32      item_num;
    uint32      used_num;
    uint32      item_size;
    uint32      extend_step;
    uint32      extend_num;
    char*       addr[DRC_RES_EXTEND_MAX_NUM];
    bool32      res_depleted;
} drc_res_pool_t;

int32 drc_res_pool_init(drc_res_pool_t *pool, uint32 res_size, uint32 res_num);
void drc_res_pool_destroy(drc_res_pool_t *pool);
char *drc_res_pool_alloc_item(drc_res_pool_t *pool);
void drc_res_pool_free_item(drc_res_pool_t *pool, char *res);
char *drc_res_pool_try_extend_and_alloc(drc_res_pool_t *pool);

typedef bool32 (*res_cmp_callback)(char* res, const char* resid, uint32 len);
typedef uint32 (*res_hash_callback)(int32 res_type, char* resid, uint32 len);

typedef struct st_drc_res_bucket {
    spinlock_t  lock;
    bilist_t    bucket_list;
} drc_res_bucket_t;

typedef struct st_drc_res_map {
    bool32      inited;
    int32       res_type;
    uint32      bucket_num;
    drc_res_pool_t      res_pool;
    drc_res_bucket_t*   buckets;
    res_cmp_callback    res_cmp_func;
    res_hash_callback   res_hash_func;
} drc_res_map_t;

int32 drc_res_map_init(drc_res_map_t* res_map, int32 res_type, uint32 item_num, uint32 item_size,
    res_cmp_callback res_cmp, res_hash_callback res_hash);
void drc_res_map_destroy(drc_res_map_t* res_map);
drc_res_bucket_t* drc_res_map_get_bucket(drc_res_map_t* res_map, char* resid, uint32 len);
void drc_res_map_add_res(drc_res_bucket_t* bucket, char* res);
char* drc_res_map_lookup(const drc_res_map_t* res_map, drc_res_bucket_t* res_bucket, char* resid, uint32 len);
void drc_res_map_del_res(drc_res_map_t* res_map, drc_res_bucket_t* bucket, char* resid, uint32 len);
void drc_destroy(void);
void drc_init_deposit_map(void);

typedef struct st_drc_request_info {
    uint8   inst_id;            /* the instance that the request comes from */
    uint8   curr_mode;          /* current holding lock mode in request instance */
    uint8   req_mode;           /* the expected lock mode that request instance wants */
    uint8   is_try;             /* if is try request */
    dms_session_e sess_type;    /* session type */
    uint64  rsn;                /* request packet serial number */
    uint16  sess_id;            /* the session id that the request comes from */
    date_t  req_time;
} drc_request_info_t;

typedef struct st_drc_lock_item {
    bilist_node_t node;
    drc_request_info_t req_info;
} drc_lock_item_t;

typedef struct st_drc_cvt_item {
    int64 begin_time;
    drc_request_info_t req_info;
} drc_cvt_item_t;

typedef enum en_dms_copy_promote {
    DMS_COPY_PROMOTE_NONE = 0,
    DMS_COPY_PROMOTE_NORMAL = 1,
    DMS_COPY_PROMOTE_RDP = 2,
} dms_copy_promote_t;

/*
 * page buffer resource DRC management structure.
 */
typedef struct st_drc_buf_res {
    bilist_node_t   node;               /* used for link drc_buf_res_t in free list or bucket list, must be first */
    uint64          copy_insts;          /* bitmap for owners, for S mode, more than one owner may exist */
    spinlock_t      lock;
    atomic32_t      count;              /* for lock */
    uint8           claimed_owner;      /* owner */
    uint8           lock_mode;          /* current DRC lock mode */
    uint8           last_edp;           /* the newest edp instance id */
    uint8           type;               /* page or lock */
    bool8           in_recovery;        /* in recovery or not */
    uint8           copy_promote;       /* copy promote to owner, can not release, may need flush */
    uint16          part_id;            /* which partition id that current page belongs to */
    bilist_node_t   part_node;          /* used for link drc_buf_res_t that belongs to the same partition id */
    uint64          edp_map;            /* indicate which instance has current page's EDP(Earlier Dirty Page) */
    uint64          lsn;                /* the newest edp LSN of current page in the cluster */
    uint16          len;                /* the length of data below */
    uint8           recovery_skip;      /* DRC is accessed in recovery and skip because drc has owner */
    bool8           recycling;
    drc_cvt_item_t  converting;         /* the next requester to grant current page to */
    bilist_t        convert_q;          /* current page's requester queue */
    char            data[DMS_RESID_SIZE];            /* user defined resource(page) identifier */
} drc_buf_res_t;

typedef struct st_drc_buf_res_msg {
    uint8 claimed_owner;
    uint8 mode;
    uint8 last_edp;
    uint16 len;
    char resid[DMS_RESID_SIZE];
    uint64 lsn;
    uint64 copy_insts;
    uint64 edp_map;
    drc_request_info_t converting;
} drc_buf_res_msg_t;

typedef struct st_drc_global_res_map {
    latch_t res_latch;
    bool32 drc_access;  // drc access means we can modify drc
    bool32 data_access; // data access means we can modify data control by this drc
    drc_res_map_t res_map;
    bilist_t res_parts[DRC_MAX_PART_NUM];
    spinlock_t res_parts_lock[DRC_MAX_PART_NUM];
} drc_global_res_map_t;

typedef enum en_drc_mgrt_res_type {
    DRC_MGRT_RES_PAGE_TYPE,
    DRC_MGRT_RES_LOCK_TYPE,
    DRC_MGRT_RES_INVALID_TYPE,
} drc_mgrt_res_type_e;

typedef enum st_drc_part_status {
    PART_INIT,
    PART_NORMAL,
    PART_WAIT_MIGRATE,
    PART_MIGRATING,
    PART_WAIT_RECOVERY,
    PART_RECOVERING,
    PART_MIGRATE_COMPLETE,
    PART_MIGRATE_FAIL,
} drc_part_status_e;

typedef struct st_drc_part {
    uint8 inst_id;
    uint8 status;
    uint16 next;
} drc_part_t;

typedef struct st_drc_inst_part {
    uint16 first;
    uint16 last;
    uint16 count;
    uint16 expected_num;
} drc_inst_part_t;

typedef struct st_inst_drm_info {
    uint8 remaster_status;
    uint8 reserve;
    uint16 task_num;
} inst_drm_info_t;

typedef struct st_drc_part_mngr {
    uint32 version;
    bool8  inited;
    uint8  inst_num;
    uint8  remaster_status;
    uint8  remaster_inst;
    uint32 reversed;
    drc_part_t part_map[DRC_MAX_PART_NUM];
    drc_inst_part_t inst_part_tbl[DMS_MAX_INSTANCES];
} drc_part_mngr_t;

typedef struct st_drc_res_ctx {
    spinlock_t              part_lock;
    drc_res_pool_t          lock_item_pool;     /* enqueue item pool */
    drc_global_res_map_t    global_buf_res;     /* page resource map */
    drc_global_res_map_t    global_lock_res;
    drc_res_map_t           local_lock_res;
    drc_part_mngr_t         part_mngr;
    drc_res_map_t           txn_res_map;
    drc_res_map_t           local_txn_map;
    uint8                   deposit_map[DMS_MAX_INSTANCES];
    chan_t*                 chan;
    thread_t                smon_thread;
    uint32                  smon_sid;
    void*                   smon_handle;
} drc_res_ctx_t;

extern drc_res_ctx_t g_drc_res_ctx;

typedef enum en_drc_req_owner_result_type {
    DRC_REQ_OWNER_GRANTED       = 0,
    DRC_REQ_OWNER_ALREADY_OWNER = 1,
    DRC_REQ_OWNER_CONVERTING    = 2,
    DRC_REQ_OWNER_WAITING       = 3,
    DRC_REQ_OWNER_TRANSFERRED   = 4,
    DRC_REQ_EDP_LOCAL           = 5,    // early dirty page local
    DRC_REQ_EDP_REMOTE          = 6,    // early dirty page remote
} drc_req_owner_result_type_t;

typedef struct st_drc_req_owner_result {
    drc_req_owner_result_type_t type;
    uint8 curr_owner_id;
    uint64 invld_insts;  // share copies to be invalidated.
} drc_req_owner_result_t;

typedef struct st_cvt_info {
    uint8   owner_id;
    uint8   req_id;
    bool8   is_try;
    uint8   res_type;
    uint8   unused;
    uint16  len;
    char    resid[DMS_RESID_SIZE];
    uint64  req_rsn;
    uint32  req_sid;
    dms_lock_mode_t req_mode;
    dms_lock_mode_t curr_mode;
    uint64  invld_insts;
    drc_req_owner_result_type_t type;
} cvt_info_t;

typedef struct st_claim_info {
    uint8   new_id;
    uint8   old_id;
    bool8   has_edp;
    uint8   res_type;
    uint32  len;
    uint64  lsn;
    uint32  sess_id;
    dms_lock_mode_t req_mode;
    char    resid[DMS_RESID_SIZE];
    dms_session_e sess_type;
    uint64  rsn;
} claim_info_t;

typedef struct st_edp_info {
    uint64  edp_map;        /* to indicate which instance holds EDP */
    uint64  lsn;            /* current LSN of page */
    uint8   latest_edp;     /* instance id which holds the max LSN's EDP */
} edp_info_t;

typedef struct st_res_id {
    char    data[DMS_RESID_SIZE];
    uint16  len;
    uint8   type;
    uint8   unused;
} res_id_t;

static inline bool32 dms_same_page(char *res, const char *resid, uint32 len)
{
    drc_buf_res_t *buf_res = (drc_buf_res_t *)res;
    if (buf_res == NULL || resid == NULL || len == 0) {
        cm_panic(0);
    }
    return memcmp(buf_res->data, resid, len) == 0 ? CM_TRUE : CM_FALSE;
}

static inline uint32 dms_res_hash(int32 res_type, char *resid, uint32 len)
{
    return cm_hash_bytes((uint8 *)resid, len, INFINITE_HASH_RANGE);
}

static inline void init_drc_cvt_item(drc_cvt_item_t* converting)
{
    converting->begin_time = 0;
    converting->req_info.inst_id = CM_INVALID_ID8;
    converting->req_info.sess_id = CM_INVALID_ID16;
    converting->req_info.rsn = CM_INVALID_ID64;
    converting->req_info.curr_mode = DMS_LOCK_NULL;
    converting->req_info.req_mode = DMS_LOCK_NULL;
    converting->req_info.is_try = 0;
}

/* page resource related API */
uint8 drc_get_deposit_id(uint8 instance_id);
uint8 drc_lookup_owner_id(uint64 *owner_map);
void drc_get_convert_info(drc_buf_res_t *buf_res, cvt_info_t *cvt_info);

// use BKDR hash algorithm, get the hash id
static inline uint32 drc_resource_id_hash(uint8 *id, uint32 len, uint32 range)
{
    uint32 seed = 131; // this is BKDR hash seed: 31 131 1313 13131 131313 etc..
    uint32 hash = 0;
    uint32 i;

    for (i = 0; i < len; i++) {
        hash = hash * seed + (*id++);
    }
    
    return (hash % range);
}

static inline int32 drc_get_lock_master_id(dms_drid_t *lock_id, uint8 *master_id)
{
    uint32 part_id = drc_resource_id_hash((uint8 *)lock_id, sizeof(dms_drid_t), DRC_MAX_PART_NUM);
    *master_id = DRC_PART_MASTER_ID(part_id);
    return CM_SUCCESS;
}

static inline void bitmap64_set(uint64 *bitmap, uint8 num)
{
    uint64 tmp;
    CM_ASSERT(num < DMS_MAX_INSTANCES);
    tmp = (uint64)1 << num;
    *bitmap |= tmp;
}

static inline void bitmap64_clear(uint64 *bitmap, uint8 num)
{
    uint64 tmp;
    CM_ASSERT(num < DMS_MAX_INSTANCES);
    tmp = ~((uint64)1 << num);
    *bitmap &= tmp;
}

static inline bool32 bitmap64_exist(const uint64 *bitmap, uint8 num)
{
    uint64 tmp;
    CM_ASSERT(num < DMS_MAX_INSTANCES);
    tmp = (uint64)1 << num;
    tmp = (*bitmap) & tmp;
    return (tmp == 0) ? CM_FALSE : CM_TRUE;
}

static inline uint64 bitmap64_create(const uint8 *inst_id, uint8 inst_count)
{
    uint64 inst_map = 0;
    for (uint8 i = 0; i < inst_count; i++) {
        inst_map |= ((uint64)1 << inst_id[i]);
    }
    return inst_map;
}

static inline void bitmap64_minus(uint64 *bitmap1, uint64 bitmap2)
{
    uint64 bitmap = (*bitmap1) & (~bitmap2);
    *bitmap1 = bitmap;
}

static inline void bitmap64_union(uint64 *bitmap1, uint64 bitmap2)
{
    uint64 bitmap = (*bitmap1) | bitmap2;
    *bitmap1 = bitmap;
}

// if all bytes in bitmap2 are also in bitmap1, return true
// bitmap1 = 1101, bitmap2 = 1001 return true
// bitmap1 = 1101, bitmap2 = 1011 return false
static inline bool32 bitmap64_include(uint64 bitmap1, uint64 bitmap2)
{
    uint64 bitmap = bitmap2 & (~bitmap1);
    return bitmap == 0;
}

// if there is byte in bitmap2 is also in bitmap1, return true
// bitmap1 = 1101, bitmap2 = 0010 return false
// bitmap1 = 1101, bitmap2 = 0011 return true
static inline bool32 bitmap64_exist_ex(uint64 bitmap1, uint64 bitmap2)
{
    return (bitmap1 & bitmap2) != 0;
}

static inline uint64 bitmap64_intersect(uint64 bitmap1, uint64 bitmap2)
{
    uint64 bitmap = bitmap1 & bitmap2;
    return bitmap;
}

int32 drc_get_master_id(char *resid, uint8 type, uint8 *master_id);

// [file-page][owner-lock-copy-ver][converting][last_edp-lsn-edp_map][in_recovery-copy_promote-recovery_skip]
#define DRC_DISPLAY(drc, desc)    LOG_DEBUG_INF("[DRC %s][%s]%d-%d-%llu, CVT:%d-%d-%d-%d-%d-%llu-%d, "        \
    "EDP:%d-%llu-%llu, FLAG:%d-%d-%d", desc, cm_display_resid((drc)->data, (drc)->type),                            \
    (drc)->claimed_owner, (drc)->lock_mode, (drc)->copy_insts,                                                      \
    (drc)->converting.req_info.inst_id, (drc)->converting.req_info.curr_mode, (drc)->converting.req_info.req_mode,  \
    (drc)->converting.req_info.is_try, (drc)->converting.req_info.sess_type, (drc)->converting.req_info.rsn,        \
    (drc)->converting.req_info.sess_id, (drc)->last_edp, (drc)->lsn, (drc)->edp_map,                                \
    (drc)->in_recovery, (drc)->copy_promote, (drc)->recovery_skip)

#ifdef __cplusplus
}
#endif
#endif // __DRC_H__
