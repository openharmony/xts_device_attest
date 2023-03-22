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
#include "securec.h"
#include "attest_utils.h"
#include "attest_utils_log.h"

static void AttestLogPrint(AttestLogLevel logLevel, const char *logBuf)
{
    LogLevel hiLogLevel = LOG_INFO;
    switch (logLevel) {
        case ATTEST_LOG_LEVEL_DEBUG:
            hiLogLevel = LOG_DEBUG;
            break;
        case ATTEST_LOG_LEVEL_INFO:
            hiLogLevel = LOG_INFO;
            break;
        case ATTEST_LOG_LEVEL_WARN:
            hiLogLevel = LOG_WARN;
            break;
        case ATTEST_LOG_LEVEL_ERROR:
            hiLogLevel = LOG_ERROR;
            break;
        case ATTEST_LOG_LEVEL_FATAL:
            hiLogLevel = LOG_FATAL;
            break;
        default:
            break;
    }
    (void)HiLogPrint(LOG_CORE, hiLogLevel, 0xD001800, ATTESTLOG_LABEL, "%{public}s", logBuf);
}

void AttestLog(AttestLogLevel logLevel, const char* fmt, ...)
{
    if (logLevel < ATTEST_HILOG_LEVEL) {
        return;
    }
    char outStr[ATTEST_LOG_STR_LEM] = {0};
    va_list arg;
    va_start(arg, fmt);
    int32_t ret = vsprintf_s(outStr, sizeof(outStr), fmt, arg);
    va_end(arg);
    if (ret < 0) {
        AttestLogPrint(logLevel, "log length error.");
        return;
    }
    AttestLogPrint(logLevel, outStr);
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
