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

#ifndef __ATTEST_UTILS_LOG_H__
#define __ATTEST_UTILS_LOG_H__

#include "hilog/log.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

typedef enum {
    ATTEST_LOG_LEVEL_DEBUG = 0,
    ATTEST_LOG_LEVEL_INFO,
    ATTEST_LOG_LEVEL_WARN,
    ATTEST_LOG_LEVEL_ERROR,
    ATTEST_LOG_LEVEL_FATAL,
} AttestLogLevel;

#define ATTEST_LOG_STR_LEM 1024

#define ATTESTLOG_LABEL "DEVATTEST"

void AttestLog(AttestLogLevel logLevel, const char* fmt, ...);

#define ATTEST_LOG_DEBUG(d_fmt, d_args...) AttestLog(ATTEST_LOG_LEVEL_DEBUG, d_fmt, ##d_args)
#define ATTEST_LOG_INFO(d_fmt, d_args...) AttestLog(ATTEST_LOG_LEVEL_INFO, d_fmt, ##d_args)
#define ATTEST_LOG_WARN(d_fmt, d_args...) AttestLog(ATTEST_LOG_LEVEL_WARN, d_fmt, ##d_args)
#define ATTEST_LOG_ERROR(d_fmt, d_args...) AttestLog(ATTEST_LOG_LEVEL_ERROR, d_fmt, ##d_args)
#define ATTEST_LOG_FATAL(d_fmt, d_args...) AttestLog(ATTEST_LOG_LEVEL_FATAL, d_fmt, ##d_args)

void AttestLogAnonyStr(AttestLogLevel logLevel, const char* fmt, const char* str);

#define ATTEST_LOG_DEBUG_ANONY(d_fmt, d_str) AttestLogAnonyStr(ATTEST_LOG_LEVEL_DEBUG, d_fmt, d_str)
#define ATTEST_LOG_INFO_ANONY(d_fmt, d_str) AttestLogAnonyStr(ATTEST_LOG_LEVEL_INFO, d_fmt, d_str)
#define ATTEST_LOG_WARN_ANONY(d_fmt, d_str) AttestLogAnonyStr(ATTEST_LOG_LEVEL_WARN, d_fmt, d_str)
#define ATTEST_LOG_ERROR_ANONY(d_fmt, d_str) AttestLogAnonyStr(ATTEST_LOG_LEVEL_ERROR, d_fmt, d_str)
#define ATTEST_LOG_FATAL_ANONY(d_fmt, d_str) AttestLogAnonyStr(ATTEST_LOG_LEVEL_FATAL, d_fmt, d_str)

#define ATTEST_LOG_NSPRINT(d_curBuffer, d_curLen, d_maxLen, d_format, d_args...) do { \
    if ((d_curLen) < ((d_maxLen)-1)) { \
        (d_curLen) += snprintf_s((d_curBuffer + d_curLen), (uint32_t)((d_maxLen) - (d_curLen)), \
                                ((uint32_t)((d_maxLen) - (d_curLen)) - 1), (d_format), ##d_args); \
    } \
} while (0)

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif