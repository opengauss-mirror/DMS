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
 * scrlock_adapter.c
 *
 *
 * IDENTIFICATION
 *    src/ock/scrlock_adapter.c
 *
 * -------------------------------------------------------------------------
 */

#include "scrlock_adapter.h"
#include "cm_defs.h"
#include "cm_spinlock.h"
#include "dms_reform.h"
#include "dms_process.h"
#include "mes_rdma_rpc.h"
#include "mes_func.h"

#define OCK_SCRLOCK_ENV_PATH "OCK_SCRLOCK_LIB_PATH"
#define OCK_SCRLOCK_SO_NAME "libscrlock.so"
#define MAX_PATH_LEN SCRLOCK_MAX_PATH_LEN

typedef struct {
    void* g_scrlock_handle;
    SCRLockInit init;
    SCRLockStopServer stop_server;
    SCRLockReinit reinit;
    SCRLockUninit uninit;
    SCRTrylock trylock;
    SCRUnlock unlock;    
} dms_scrlock_func_t;

dms_scrlock_func_t g_scrlock_func;

#define SCRLOCK_LOAD_SYMBOLS(ACTION)        \
    ACTION(init, SCRLockInit)               \
    ACTION(stop_server, SCRLockStopServer)  \
    ACTION(reinit, SCRLockReinit)           \
    ACTION(uninit, SCRLockUninit)           \
    ACTION(trylock, SCRTrylock)             \
    ACTION(unlock, SCRUnlock)

#define SCRLOCK_HANDLE_GET_SYM(op, name)                                                                \
    do {                                                                                                \
        int ret = cm_load_symbol(g_scrlock_func.g_scrlock_handle, #name, (void **)&g_scrlock_func.op);  \
        if (ret != DMS_SUCCESS) {                                                                       \
            LOG_RUN_ERR("dlsym #name failed, err %d", cm_get_os_error());                               \
            return DMS_ERROR;                                                                           \
        }                                                                                               \
    } while (0);

static int scrlock_resolve_path(char* absolute_path, const char* raw_path, const char* filename)
{
    char path[MAX_PATH_LEN] = { 0 };

    if (realpath_file(raw_path, path, MAX_PATH_LEN) != DMS_SUCCESS) {
        LOG_RUN_ERR("realpath path:%s failed", raw_path);
        return DMS_ERROR;
    }

    int ret = snprintf_s(absolute_path, MAX_PATH_LEN, MAX_PATH_LEN - 1, "%s/%s", path, filename);
    if (ret < 0) {
        LOG_RUN_ERR("construct file %s path failed, ret %d.", filename, ret);
        return DMS_ERROR;
    }

    return DMS_SUCCESS;
}

static int scrlock_load_symbols(char* lib_dl_path)
{
    if (cm_open_dl(&g_scrlock_func.g_scrlock_handle, lib_dl_path) != DMS_SUCCESS) {
        LOG_RUN_ERR("dlopen %s failed, err %d", lib_dl_path, cm_get_os_error());
        return DMS_ERROR;
    }

    SCRLOCK_LOAD_SYMBOLS(SCRLOCK_HANDLE_GET_SYM);

    return DMS_SUCCESS;
}

static int scrlock_init_symbols()
{
    char lib_dl_path[MAX_PATH_LEN] = { 0 };

    char* tmp = getenv(OCK_SCRLOCK_ENV_PATH);
    if (tmp == NULL) {
        LOG_RUN_ERR("dms getenv %s failed.", OCK_SCRLOCK_ENV_PATH);
        return DMS_ERROR;
    }

    int ret = scrlock_resolve_path(lib_dl_path, tmp, OCK_SCRLOCK_SO_NAME);
    if (ret != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    ret = scrlock_load_symbols(lib_dl_path);
    if (ret != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    return DMS_SUCCESS;
}

static int scrlock_get_ssl_param(SCRLockOptions* options)
{
    if (!options->sslCfg.enable) {
        LOG_RUN_WAR("The SSL connection in SCRLock module will be disabled during build, which brings security risks.");
        return DMS_SUCCESS;
    }

    int ret = dms_get_ssl_param("SSL_CA", options->sslCfg.ssl.caFile, MAX_PATH_LEN);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("dms scrlock get SSL_CA path failed.");
        return DMS_ERROR;
    }

    ret = dms_get_ssl_param("SSL_CRL", options->sslCfg.ssl.crlFile, MAX_PATH_LEN);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("dms scrlock get SSL_CRL path failed.");
        return DMS_ERROR;
    }

    ret = dms_get_ssl_param("SSL_CERT", options->sslCfg.ssl.certFile, MAX_PATH_LEN);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("dms scrlock get SSL_CERT path failed.");
        return DMS_ERROR;
    }

    ret = dms_get_ssl_param("SSL_KEY", options->sslCfg.ssl.keyFile, MAX_PATH_LEN);
    if (ret != DMS_SUCCESS) {
        LOG_RUN_ERR("dms scrlock get SSL_KEY path failed.");
        return DMS_ERROR;
    }

    options->sslCfg.ssl.certVerifyFunc = mes_ockrpc_tls_cert_verify;
    options->sslCfg.ssl.getKeyFunc = mes_ockrpc_tls_get_private_key;

    return DMS_SUCCESS;
}

static int scrlock_init(dms_profile_t *dms_profile)
{
    int ret;
    SCRLockOptions options;
    SCRLockClientOptions client_options;
    SCRLockServerOptions server_options;

    // common configs
    while (dms_profile->enable_reform && g_dms.reform_ctx.reform_info.reformer_id == CM_INVALID_ID8) {
        cm_sleep(1);
    }
    uint32 primary_inst_id = dms_profile->enable_reform ? g_dms.reform_ctx.reform_info.reformer_id : dms_profile->primary_inst_id;
    options.logLevel = dms_profile->scrlock_log_level;
    ret = memcpy_s(options.serverAddr.ip, SCRLOCK_MAX_IP_LEN, dms_profile->inst_net_addr[primary_inst_id].ip, DMS_MAX_IP_LEN);
    DMS_SECUREC_CHECK(ret);
    options.serverAddr.port = dms_profile->scrlock_server_port;
    ret = memcpy_s(options.clientAddr.ip, SCRLOCK_MAX_IP_LEN, dms_profile->inst_net_addr[dms_profile->inst_id].ip, DMS_MAX_IP_LEN);
    DMS_SECUREC_CHECK(ret);
    options.sslCfg.enable = dms_profile->enable_ssl;
    ret = scrlock_get_ssl_param(&options);
    if (ret != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    // client configs
    client_options.workerBindCore = dms_profile->enable_scrlock_worker_bind_core;
    client_options.workerNum = dms_profile->scrlock_worker_cnt;
    client_options.workerBindCoreStart = dms_profile->scrlock_worker_bind_core_start;
    client_options.workerBindCoreEnd = dms_profile->scrlock_worker_bind_core_end;
    if (realpath_file(dms_profile->ock_log_path, client_options.logPath, SCRLOCK_MAX_PATH_LEN) != DMS_SUCCESS) {
        LOG_RUN_ERR("realpath path:%s failed", dms_profile->ock_log_path);
        return DMS_ERROR;
    }

    options.client = &client_options;

    if (primary_inst_id == dms_profile->inst_id) {
        // server configs
        server_options.sleepMode = dms_profile->enable_scrlock_server_sleep_mode;
        server_options.bindCoreStart = dms_profile->scrlock_server_bind_core_start;
        server_options.bindCoreEnd = dms_profile->scrlock_server_bind_core_end;
        options.server = &server_options;
    } else {
        options.server = NULL;
    }

    ret = g_scrlock_func.init(&options);
    if (ret != SCRL_SUCCESS) {
        LOG_RUN_ERR("dms scrlock init failed, ret %d.", ret);
        return DMS_ERROR;
    }

    return DMS_SUCCESS;
}

unsigned char dms_scrlock_init(dms_profile_t *dms_profile)
{
    if (!g_dms.scrlock_ctx.enable) {
        return DMS_SUCCESS;
    }

    int ret = scrlock_init_symbols();
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    ret = scrlock_init(dms_profile);
    if (ret != DMS_SUCCESS) {
        return ret;
    }

    return DMS_SUCCESS;
}

unsigned char dms_scrlock_reinit()
{
    int ret;
    reform_scrlock_context_t *scrlock_ctx = &g_dms.reform_ctx.scrlock_reinit_ctx;
    
    SCRLockOptions scrlock_options;
    SCRLockClientOptions client_options;
    SCRLockServerOptions server_options;

    scrlock_options.logLevel = scrlock_ctx->log_level;
    scrlock_options.serverAddr.port = scrlock_ctx->scrlock_server_port;
    ret = memcpy_s(scrlock_options.serverAddr.ip, SCRLOCK_MAX_IP_LEN, MES_GLOBAL_INST_MSG.profile.inst_net_addr[scrlock_ctx->scrlock_server_id].ip, MES_MAX_IP_LEN);
    DMS_SECUREC_CHECK(ret);
    scrlock_options.sslCfg.enable = scrlock_ctx->enable_ssl;
    ret = scrlock_get_ssl_param(&scrlock_options);
    if (ret != DMS_SUCCESS) {
        return DMS_ERROR;
    }

    ret = memcpy_s(client_options.logPath, DMS_OCK_LOG_PATH_LEN, scrlock_ctx->log_path, DMS_OCK_LOG_PATH_LEN);
    DMS_SECUREC_CHECK(ret);
    ret = memcpy_s(scrlock_options.clientAddr.ip, SCRLOCK_MAX_IP_LEN, MES_GLOBAL_INST_MSG.profile.inst_net_addr[g_dms.inst_id].ip, MES_MAX_IP_LEN);
    DMS_SECUREC_CHECK(ret);
    client_options.workerNum = scrlock_ctx->worker_num;
    client_options.workerBindCore = scrlock_ctx->worker_bind_core;
    client_options.workerBindCoreStart = scrlock_ctx->worker_bind_core_start;
    client_options.workerBindCoreEnd = scrlock_ctx->worker_bind_core_end;
    scrlock_options.client = &client_options;

    if (scrlock_ctx->scrlock_server_id == g_dms.inst_id) {
        server_options.sleepMode = scrlock_ctx->sleep_mode;
        server_options.bindCoreStart = scrlock_ctx->server_bind_core_start;
        server_options.bindCoreEnd = scrlock_ctx->server_bind_core_end;
        server_options.recoveryNodeNum = scrlock_ctx->recovery_node_num;
        scrlock_options.server = &server_options;
    } else {
        scrlock_options.server = NULL;
    }

    ret = g_scrlock_func.reinit(&scrlock_options);
    return ret == SCRL_SUCCESS ? CM_TRUE : CM_FALSE;
}

void dms_scrlock_stop_server()
{
    if (!g_dms.scrlock_ctx.enable) {
        return;
    }

    g_scrlock_func.stop_server();
}

void dms_scrlock_uninit()
{
    if (!g_dms.scrlock_ctx.enable) {
        return;
    }

    g_scrlock_func.uninit();
}

unsigned char dms_scrlock_timed_x(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks)
{
    uint32 ticks = 0;
    uint32 count = 0;
    bool ret = SCRL_FAIL;
    SCRLockId lock_id = {.pDesc = (const char *)(&dlatch->drid), .len = sizeof(dlatch->drid)};

    do {
        ret = g_scrlock_func.trylock(&lock_id, FAIR_RW, LOCK_EXCLUSIVE);
        if (ret != SCRL_SUCCESS)
        {
            count++;
            if (count >= GS_SPIN_COUNT) {
                cm_spin_sleep();
                count = 0;
                ticks++;
            }   
        }  
    } while (ticks < wait_ticks && ret != SCRL_SUCCESS);

    return ret == SCRL_SUCCESS ? CM_TRUE : CM_FALSE;
}

unsigned char dms_scrlock_timed_s(dms_context_t *dms_ctx, dms_drlatch_t *dlatch, unsigned int wait_ticks)
{
    uint32 ticks = 0;
    uint32 count = 0;
    bool ret = SCRL_FAIL;
    SCRLockId lock_id = {.pDesc = (const char *)(&dlatch->drid), .len = sizeof(dlatch->drid)};

    do {
        ret = g_scrlock_func.trylock(&lock_id, FAIR_RW, LOCK_SHARED);
        if (ret != SCRL_SUCCESS)
        {
            count++;
            if (count >= GS_SPIN_COUNT) {
                cm_spin_sleep();
                count = 0;
                ticks++;
            }   
        }   
    } while (ticks < wait_ticks && ret != SCRL_SUCCESS);

    return ret == SCRL_SUCCESS ? CM_TRUE : CM_FALSE;
}

void dms_scrlock_unlock(dms_context_t *dms_ctx, dms_drlatch_t *dlatch)
{
    SCRLockId lock_id = {.pDesc = (const char *)(&dlatch->drid), .len = sizeof(dlatch->drid)};
    g_scrlock_func.unlock(&lock_id, FAIR_RW);
    return;
}