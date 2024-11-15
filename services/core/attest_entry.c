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

#include "attest_type.h"
#include "attest_utils_log.h"
#include "attest_utils_timer.h"
#include "attest_service.h"
#include "attest_entry.h"

static ATTEST_TIMER_ID g_ProcAttestTimerId = NULL;

int32_t AttestTask(void)
{
    ATTEST_LOG_INFO("[AttestTask] Begin.");
    // 执行主流程代码
    int32_t ret = ProcAttest();
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestTask] Proc failed ret = %d.", ret);
    }
    ATTEST_LOG_INFO("[AttestTask] End.");
    return ret;
}

int32_t QueryAttest(int32_t** resultArray, int32_t arraySize, char** ticket, int32_t* ticketLength)
{
    return QueryAttestStatus(resultArray, arraySize, ticket, ticketLength);
}

int32_t AttestWaitTaskOver(void)
{
    return AttestWaitTaskOverImpl();
}

int32_t AttestCreateTimerTask(void)
{
    return 0;
}

int32_t AttestDestroyTimerTask(void)
{
    return AttestStopTimerTask(g_ProcAttestTimerId);
}
