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

#include <stdio.h>
#include <stdlib.h>
#include <securec.h>
#include <signal.h>
#include <pthread.h>
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_utils_timer.h"

#define ATTEST_TIMER_TASK_ID "attest_timer"

static void AttestTimerCallback(union sigval attestTimer)
{
    (void)pthread_setname_np(pthread_self(), ATTEST_TIMER_TASK_ID); // set pthread name, at most 15 bytes.
    AttestTimerInfo *tmpTimerInfo = (AttestTimerInfo *)attestTimer.sival_ptr;
    if (tmpTimerInfo->type == ATTEST_TIMER_TYPE_ONCE) {
        tmpTimerInfo->status = ATTEST_TIMER_STATUS_STOP;
    }
    tmpTimerInfo->func(tmpTimerInfo->arg);
}

static void AttestMs2TimeSpec(struct timespec *tp, uint32_t ms)
{
    if (tp == NULL) {
        ATTEST_LOG_ERROR("[AttestMs2TimeSpec] tp is null");
        return;
    }
    tp->tv_sec = (time_t)(ms / LOSCFG_BASE_CORE_MS_PER_SECOND);
    ms -= (uint32_t)(tp->tv_sec * LOSCFG_BASE_CORE_MS_PER_SECOND);
    tp->tv_nsec = (long)(((unsigned long long)ms * OS_SYS_NS_PER_SECOND) / LOSCFG_BASE_CORE_MS_PER_SECOND);
}

static ATTEST_TIMER_ID AttestTimerCreate(TimerCallbackFunc func, AttestTimerType type,
    void *arg, uint32_t milliseconds)
{
    if ((func == NULL) || (type != ATTEST_TIMER_TYPE_ONCE && type != ATTEST_TIMER_TYPE_PERIOD)) {
        ATTEST_LOG_ERROR("[AttestTimerCreate] something is wrong");
        return NULL;
    }
    AttestTimerInfo *timerInfo = (AttestTimerInfo *)ATTEST_MEM_MALLOC(sizeof(AttestTimerInfo));
    if (timerInfo == NULL) {
        ATTEST_LOG_ERROR("[AttestTimerCreate] TimerInfo malloc fail");
        return NULL;
    }

    timerInfo->type = type;
    timerInfo->milliseconds = milliseconds;
    timerInfo->func = func;
    timerInfo->arg = arg;
    timerInfo->status = ATTEST_TIMER_STATUS_STOP;

    timer_t timerId;
    struct sigevent sigEvp = { 0 };
    sigEvp.sigev_notify = SIGEV_THREAD;
    sigEvp.sigev_notify_function = AttestTimerCallback;
    sigEvp.sigev_value.sival_ptr = timerInfo;
    int32_t ret = timer_create(CLOCK_REALTIME, &sigEvp, &timerId);
    if (ret != 0) {
        ATTEST_MEM_FREE(timerInfo);
        ATTEST_LOG_ERROR("[AttestTimerCreate] TimerCreate fail");
        return NULL;
    }
    timerInfo->timerId = timerId;
    return (ATTEST_TIMER_ID)timerInfo;
}

static int32_t AttestTimerStart(ATTEST_TIMER_ID attestTimerId)
{
    if (attestTimerId == NULL) {
        ATTEST_LOG_ERROR("[AttestTimerStart] attestTimerId is null");
        return ATTEST_ERR;
    }
    struct itimerspec timerSpec = { 0 };
    AttestTimerInfo *tmpTimerInfo = (AttestTimerInfo *)attestTimerId;

    AttestMs2TimeSpec(&timerSpec.it_value, tmpTimerInfo->milliseconds);
    if (tmpTimerInfo->type == ATTEST_TIMER_TYPE_PERIOD) {
        AttestMs2TimeSpec(&timerSpec.it_interval, tmpTimerInfo->milliseconds);
    }
    int32_t ret = timer_settime(tmpTimerInfo->timerId, 0, &timerSpec, NULL);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[AttestTimerStart] failed to settime");
        return ATTEST_ERR;
    }
    if (tmpTimerInfo->milliseconds != 0) {
        tmpTimerInfo->status = ATTEST_TIMER_STATUS_RUNNING;
    }
    return ATTEST_OK;
}

int32_t AttestStopTimerTask(const ATTEST_TIMER_ID attestTimerId)
{
    if (attestTimerId == NULL) {
        return ATTEST_ERR;
    }
    AttestTimerInfo *tmpTimerInfo = (AttestTimerInfo *)attestTimerId;
    int32_t ret = timer_delete(tmpTimerInfo->timerId);
    ATTEST_MEM_FREE(tmpTimerInfo);
    return (ret != 0) ? ATTEST_ERR : ATTEST_OK;
}

int32_t AttestStartTimerTask(AttestTimerType isOnce, uint32_t milliseconds,
    void *func, void *arg, ATTEST_TIMER_ID *timerHandle)
{
    if (func == NULL || timerHandle == NULL) {
        ATTEST_LOG_ERROR("[AttestStartTimerTask] callBackFunc or timerHandle is null");
        return ATTEST_ERR;
    }
    if (*timerHandle != NULL) {
        AttestTimerInfo *tmpTimerInfo = (AttestTimerInfo *)timerHandle;
        if (tmpTimerInfo->timerId != 0) {
            ATTEST_LOG_ERROR("[AttestStartTimerTask] timerId already exists");
            return ATTEST_ERR;
        }
    }

    AttestTimerType type = (isOnce == ATTEST_TIMER_TYPE_ONCE) ? ATTEST_TIMER_TYPE_ONCE : ATTEST_TIMER_TYPE_PERIOD;
    ATTEST_TIMER_ID attestTimerId = AttestTimerCreate((TimerCallbackFunc)func, type, arg, milliseconds);
    if (attestTimerId == NULL) {
        ATTEST_LOG_ERROR("[AttestStartTimerTask] failed to create timerHandle");
        return ATTEST_ERR;
    }

    if (AttestTimerStart(attestTimerId) != ATTEST_OK) {
        if (AttestStopTimerTask(attestTimerId) == ATTEST_OK) {
            attestTimerId = NULL;
        }
        ATTEST_LOG_ERROR("[AttestStartTimerTask] failed to start timerHandle");
        return ATTEST_ERR;
    }
    *timerHandle = attestTimerId;
    return ATTEST_OK;
}