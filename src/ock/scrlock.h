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
 * scrlock.h
 *
 *
 * IDENTIFICATION
 *    src/ock/scrlock.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __SCRLOCK_H__
#define __SCRLOCK_H__

#include <stdbool.h>

#define SCRLOCK_MAX_PATH_LEN 4096
#define SCRLOCK_MAX_IP_LEN 64

typedef int (*SCRLockVerifyCert)(void *ctx, const char *crlPath);

typedef void (*SCRLockErase)(char *keyPlainText);

typedef void (*SCRLockGetPrivateKey)(const char **keyPath, char **keyPlainText, SCRLockErase *erase);

typedef struct {
    const char *pDesc;
    unsigned int len;
} SCRLockId;

typedef struct {
    char ip[SCRLOCK_MAX_IP_LEN];
    unsigned int port;
} SCRLockNetAddr;

typedef struct {
    char caFile[SCRLOCK_MAX_PATH_LEN];
    char crlFile[SCRLOCK_MAX_PATH_LEN];
    char certFile[SCRLOCK_MAX_PATH_LEN];
    char keyFile[SCRLOCK_MAX_PATH_LEN];
    char cipher[SCRLOCK_MAX_PATH_LEN];
    SCRLockVerifyCert certVerifyFunc;
    SCRLockGetPrivateKey getKeyFunc;
} SSLRelated;

typedef struct {
    bool enable;
    SSLRelated ssl;
} SSLParam;

typedef struct {
    char logPath[SCRLOCK_MAX_PATH_LEN];
    unsigned int workerNum;
    bool workerBindCore;
    unsigned int workerBindCoreStart;
    unsigned int workerBindCoreEnd;
} SCRLockClientOptions;

typedef struct {
    bool sleepMode;
    unsigned int bindCoreStart;
    unsigned int bindCoreEnd;
    unsigned int recoveryNodeNum;  // for recovery
} SCRLockServerOptions;

typedef struct {
    unsigned int logLevel;
    SCRLockNetAddr serverAddr;
    SSLParam sslCfg;
    SCRLockClientOptions *client;
    SCRLockServerOptions *server;  // server == nullptr means this node does not contain server
} SCRLockOptions;

enum SCRLockType { ATOMIC = 0, FAIR_RW = 1, ATOMIC_REENTRANT = 2, LOCK_TYPE_BUTT };

enum SCRLockMode { LOCK_SHARED = 0, LOCK_EXCLUSIVE = 1, LOCK_OPS_BUTT };

enum SCRLockRetCode { SCRL_FAIL = 0, SCRL_SUCCESS = 1, SCRL_RET_BUTT };

typedef bool (*SCRLockInit)(SCRLockOptions *options);

typedef void (*SCRLockStopServer)();

typedef bool (*SCRLockReinit)(SCRLockOptions *options);

typedef void (*SCRLockUninit)();

typedef bool (*SCRTrylock)(SCRLockId *lockId, unsigned int lockType, unsigned int lockOp);

typedef void (*SCRUnlock)(SCRLockId *lockId, unsigned int lockType);

#endif