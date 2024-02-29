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
#include <stdarg.h>
#include <inttypes.h>
#include <securec.h>
#include "attest_utils.h"
#include "attest_utils_log.h"

static void AttestLogPrint(AttestLogLevel logLevel, const char *logBuf)
{
    switch (logLevel) {
        case ATTEST_LOG_LEVEL_DEBUG:
            ATTEST_LOG_DEBUG("%{public}s", logBuf);
            break;
        case ATTEST_LOG_LEVEL_INFO:
            ATTEST_LOG_INFO("%{public}s", logBuf);
            break;
        case ATTEST_LOG_LEVEL_WARN:
            ATTEST_LOG_WARN("%{public}s", logBuf);
            break;
        case ATTEST_LOG_LEVEL_ERROR:
            ATTEST_LOG_ERROR("%{public}s", logBuf);
            break;
        case ATTEST_LOG_LEVEL_FATAL:
            ATTEST_LOG_FATAL("%{public}s", logBuf);
            break;
        default:
            break;
    }
    return;
}

void AttestLogAnonyStr(AttestLogLevel logLevel, const char* fmt, const char* str)
{
    if (fmt == NULL || str == NULL || logLevel < ATTEST_HILOG_LEVEL) {
        return;
    }
    char *strDup = AttestStrdup(str);
    if (strDup == NULL) {
        return;
    }
    int32_t ret = AnonymiseStr(strDup);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[AttestLogAnonyStr] AnonymiseStr failed, ret = %d;", ret);
        ATTEST_MEM_FREE(strDup);
        return;
    }
    char outStr[ATTEST_LOG_STR_LEM] = {0};
    ret = sprintf_s(outStr, sizeof(outStr), fmt, strDup);
    ATTEST_MEM_FREE(strDup);
    if (ret < 0) {
        AttestLogPrint(logLevel, "[AttestLogAnonyStr] Attest anony str length error.");
        return;
    }
    AttestLogPrint(logLevel, outStr);
}
