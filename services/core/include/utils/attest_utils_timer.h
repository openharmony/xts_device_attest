/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __ATTEST_UTILS_TIMER_H__
#define __ATTEST_UTILS_TIMER_H__

#include <time.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef void *ATTEST_TIMER_ID;
typedef void (*TimerCallbackFunc)(void*);
#define LOSCFG_BASE_CORE_MS_PER_SECOND 1000
#define OS_SYS_NS_PER_SECOND 1000000000
#define EXPIRED_INTERVAL 86400000

typedef enum {
    ATTEST_TIMER_STATUS_STOP = 0,
    ATTEST_TIMER_STATUS_RUNNING,
} AttestTimerStatus;

typedef enum {
    ATTEST_TIMER_TYPE_ONCE = 0,
    ATTEST_TIMER_TYPE_PERIOD,
} AttestTimerType;

typedef struct {
    timer_t timerId;
    AttestTimerType type;
    uint32_t milliseconds;
    TimerCallbackFunc func;
    void *arg;
    AttestTimerStatus status;
} AttestTimerInfo;

int32_t AttestStartTimerTask(AttestTimerType isOnce, uint32_t milliseconds,
    void *func, void *arg, ATTEST_TIMER_ID *timerHandle);

int32_t AttestStopTimerTask(const ATTEST_TIMER_ID attestTimerId);

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif
