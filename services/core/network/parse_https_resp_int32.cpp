/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "parse_https_resp_int32.h"

#include <charconv>
#include <cstring>
#include <system_error>

extern "C" bool ParseHttpsRespInt32(const char *text, int32_t *out)
{
    if (text == nullptr || out == nullptr || *text == '\0') {
        return false;
    }
    if (*text < '0' || *text > '9') {
        return false;
    }
    const char *first = text;
    const char *last = text + std::strlen(text);
    int32_t value = 0;
    auto result = std::from_chars(first, last, value, 10);
    if (result.ec != std::errc() || result.ptr == first) {
        return false;
    }
    char leftover = *result.ptr;
    if (leftover != '\0' && leftover != ' ' && leftover != '\t' && leftover != '\r' && leftover != '\n') {
        return false;
    }
    *out = value;
    return true;
}
