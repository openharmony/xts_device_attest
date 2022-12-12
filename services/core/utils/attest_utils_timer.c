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
#include <stdint.h>
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_utils_timer.h"

static timer_t g_timerId = 0;

static void TimerFunction(union sigval sigv)
{
    TimerInfo *timerInfo = (TimerInfo *)(sigv.sival_ptr);
    timerInfo->func();
}

static void Ms2TimeSpec(struct timespec *tp, uint32_t ms)
{
    tp->tv_sec = ms / LOSCFG_BASE_CORE_MS_PRE_SECOND;
    ms -= tp->tv_sec * LOSCFG_BASE_CORE_MS_PRE_SECOND;
    tp->tv_nsec = (long)(((unsigned long long)ms * OS_SYS_NS_PER_SECOND) / LOSCFG_BASE_CORE_MS_PRE_SECOND);
}

static int32_t TimerCreate(TimerCallbackFunc userCallBack, TimerInfo* timerInfo)
{
    struct sigevent evp = {0};
    timer_t timerId;
    timerInfo->func = userCallBack;
    evp.sigev_value.sival_ptr = timerInfo;
    evp.sigev_notify = SIGEV_THREAD;
    evp.sigev_notify_function = TimerFunction;
    int32_t ret = timer_create(CLOCK_REALTIME, &evp, &timerId);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[TimerCreate] TimerCreate failed");
        return ATTEST_ERR;
    }
    timerInfo->timerId = timerId;
    return ret;
}

static int32_t TimerStart(TimerInfo* timerInfo, AttestTimerType type, uint32_t milliseconds)
{
    struct itimerspec ts;
    (void)memset_s(&ts, sizeof(ts), 0, sizeof(ts));
    Ms2TimeSpec(&ts.it_value, milliseconds);
    if (type == ATTEST_TIMER_TYPE_PERIOD) {
        Ms2TimeSpec(&ts.it_interval, milliseconds);
    }
    return timer_settime(timerInfo->timerId, 0, &ts, NULL);
}

int32_t CreateTimerTask(uint32_t milliseconds, void* userCallBack, AttestTimerType type)
{
    if (g_timerId != 0) {
        ATTEST_LOG_ERROR("[CreateTimerTask] TimerTask exists");
        return ATTEST_ERR;
    }
    TimerInfo* timerInfo = (TimerInfo *)ATTEST_MEM_MALLOC(sizeof(TimerInfo));
    if (timerInfo == NULL) {
        return ATTEST_ERR;
    }
    int32_t ret = TimerCreate((TimerCallbackFunc)userCallBack, timerInfo);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CreateTimerTask] TimerCreate failed");
        ATTEST_MEM_FREE(timerInfo);
        return ATTEST_ERR;
    }

    ret = TimerStart(timerInfo, type, milliseconds);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CreateTimerTask] TimerStart failed");
        timer_delete(timerInfo->timerId);
        ATTEST_MEM_FREE(timerInfo);
        return ATTEST_ERR;
    } else {
        g_timerId = timerInfo->timerId;
        ATTEST_LOG_INFO("[CreateTimerTask] TimerStart success");
    }
    return ATTEST_OK;
}